import ipaddress
import json
import logging
import os
import re
import hmac
import hashlib
import subprocess
import smtplib
import threading
import io
import contextlib
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import unicodedata
import base64
import ssl
import socket
import time
import uuid
from email.message import EmailMessage
from datetime import datetime, timezone
from difflib import SequenceMatcher
from urllib.parse import urlparse, urljoin, unquote, parse_qsl, urlencode, urlunparse
from functools import lru_cache

import requests
import urllib3
import tldextract
import whois
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("linkcheck")

app = Flask(__name__)
# Limit JSON body size (mitigate DoS / oversized payloads). Override via MAX_CONTENT_LENGTH (bytes).
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH", str(512 * 1024)))

_cors_origins = (os.getenv("CORS_ORIGINS") or "*").strip()
if _cors_origins == "*":
    CORS(app)
else:
    _origins = [o.strip() for o in _cors_origins.split(",") if o.strip()]
    CORS(app, resources={r"/*": {"origins": _origins or ["http://localhost:5173"]}})

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[],
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
)

LIVE_JOB_TIMEOUT_SEC = int(os.getenv("LIVE_JOB_TIMEOUT_SEC", "20"))
LIVE_CACHE_TTL_SEC = int(os.getenv("LIVE_CACHE_TTL_SEC", "180"))
EXTERNAL_INTEL_TIMEOUT_SEC = int(os.getenv("EXTERNAL_INTEL_TIMEOUT_SEC", "4"))
ANALYSIS_FETCH_TIMEOUT_SEC = int(os.getenv("ANALYSIS_FETCH_TIMEOUT_SEC", "4"))
WHOIS_TIMEOUT_SEC = float(os.getenv("WHOIS_TIMEOUT_SEC", "2.5"))
LIVE_LOW_STABILIZE_RETRIES = max(0, int(os.getenv("LIVE_LOW_STABILIZE_RETRIES", "2")))
LIVE_LOW_STABILIZE_DELAY_SEC = max(0.0, float(os.getenv("LIVE_LOW_STABILIZE_DELAY_SEC", "2.0")))
GSB_CACHE_TTL_SEC = int(os.getenv("GSB_CACHE_TTL_SEC", "1800"))
GSB_COOLDOWN_SEC = int(os.getenv("GSB_COOLDOWN_SEC", "180"))
LIVE_ANALYSIS_JOBS: dict[str, dict] = {}
LIVE_ANALYSIS_CACHE: dict[str, dict] = {}
GSB_RESULT_CACHE: dict[str, dict] = {}
GSB_DISABLED_UNTIL_TS = 0.0
# Bump when live-result semantics change to invalidate stale in-memory cache entries.
LIVE_CACHE_SCHEMA_VERSION = os.getenv("LIVE_CACHE_SCHEMA_VERSION", "3")
LIVE_LOCK = threading.Lock()
WHOIS_EXECUTOR = ThreadPoolExecutor(max_workers=4)
WEBHOOK_DEPLOY_LOCK = threading.Lock()
WEBHOOK_DEPLOY_PROCESS: subprocess.Popen | None = None


def _production_mode() -> bool:
    return os.getenv("FLASK_ENV", "").lower() == "production" or os.getenv("APP_ENV", "").lower() == "production"


@app.after_request
def _security_headers(response):
    """OWASP-aligned headers for every API response (see security policy / threat model)."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # JSON API: deny default loads; no frames.
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    if request.is_secure or os.getenv("FORCE_HSTS", "").lower() in {"1", "true", "yes", "on"}:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(413)
def _payload_too_large(_e):
    return jsonify({"ok": False, "error": "payload_too_large"}), 413


@app.errorhandler(429)
def _rate_limited(_e):
    return jsonify({"ok": False, "error": "rate_limited"}), 429


@app.errorhandler(500)
def _internal_error(_e):
    if _production_mode():
        logger.exception("Internal server error")
    return jsonify({"ok": False, "error": "internal_error"}), 500


@app.get("/.well-known/security.txt")
def security_txt():
    """RFC 9116 security disclosure contact (threat modeling / disclosure policy)."""
    contact = (os.getenv("SECURITY_CONTACT_EMAIL") or "erlix.co@gmail.com").strip()
    body = (
        f"Contact: mailto:{contact}\n"
        "Preferred-Languages: en, he\n"
        "Policy: LinkCheck follows coordinated disclosure; include repro steps if possible.\n"
    )
    return app.response_class(body, mimetype="text/plain; charset=utf-8")
gemini_api_key = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL_CANDIDATES = [
    m.strip()
    for m in (
        os.getenv("GEMINI_MODEL_CANDIDATES")
        or "gemini-2.5-flash,gemini-flash-latest,gemini-2.5-flash-lite"
    ).split(",")
    if m.strip()
]
GEMINI_RETRY_ATTEMPTS = max(1, int(os.getenv("GEMINI_RETRY_ATTEMPTS", "2")))
GEMINI_RETRY_DELAY_SEC = max(0.0, float(os.getenv("GEMINI_RETRY_DELAY_SEC", "0.35")))


def _extract_gemini_text(body: dict, default: str = "") -> str:
    return (
        body.get("candidates", [{}])[0]
        .get("content", {})
        .get("parts", [{}])[0]
        .get("text", default)
    )


def _gemini_generate_text(
    *,
    prompt: str,
    response_mime_type: str | None = None,
    temperature: float = 0.0,
    timeout_sec: int = 10,
) -> str:
    """Call Gemini with model fallback and short retry on transient errors."""
    if not gemini_api_key:
        return ""

    payload: dict = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": temperature},
    }
    if response_mime_type:
        payload["generationConfig"]["responseMimeType"] = response_mime_type

    retryable_codes = {429, 500, 502, 503, 504}
    for model_name in GEMINI_MODEL_CANDIDATES:
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
        for attempt in range(GEMINI_RETRY_ATTEMPTS):
            try:
                resp = requests.post(
                    f"{endpoint}?key={gemini_api_key}",
                    json=payload,
                    timeout=timeout_sec,
                )
                if resp.ok:
                    return _extract_gemini_text(resp.json(), default="")
                if resp.status_code in retryable_codes and attempt < GEMINI_RETRY_ATTEMPTS - 1:
                    time.sleep(GEMINI_RETRY_DELAY_SEC * (attempt + 1))
                    continue
                # Non-retryable (or retries exhausted): move to next fallback model.
                break
            except requests.RequestException:
                if attempt < GEMINI_RETRY_ATTEMPTS - 1:
                    time.sleep(GEMINI_RETRY_DELAY_SEC * (attempt + 1))
                    continue
                break
    return ""

# Input size caps for /analyze (DoS / abuse mitigation).
MAX_ANALYZE_URL_LEN = int(os.getenv("MAX_ANALYZE_URL_LEN", "4096"))
MAX_ANALYZE_MESSAGE_LEN = int(os.getenv("MAX_ANALYZE_MESSAGE_LEN", "100000"))
MAX_MESSAGE_URLS_TO_ANALYZE = max(1, int(os.getenv("MAX_MESSAGE_URLS_TO_ANALYZE", "5")))

# Use bundled PSL snapshot for stable, offline-safe registrable extraction.
psl_extract = tldextract.TLDExtract(suffix_list_urls=None)

BRAND_PATTERNS = ("nike", "paypal", "benetton", "amazon")
PROTECTED_BRANDS = ("bankisrael", "paypal", "amazon", "nike", "benetton")
BRAND_CANONICAL_DOMAINS = {
    "paypal": {"paypal.com"},
    # Include known Amazon-owned service/static roots to reduce false positives on legitimate assets.
    "amazon": {"amazon.com", "amazonaws.com", "ssl-images-amazon.com", "media-amazon.com"},
    "nike": {"nike.com"},
    "benetton": {"benetton.com"},
    "apple": {"apple.com"},
    "google": {"google.com", "google.co.il"},
    "microsoft": {
        "microsoft.com",
        "microsoftonline.com",
        "live.com",
        "outlook.com",
        "office.com",
        "office365.com",
        "azure.com",
        "skype.com",
        "bing.com",
        "msn.com",
    },
    "facebook": {"facebook.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "visa": {"visa.com"},
    "mastercard": {"mastercard.com"},
    "bankhapoalim": {"bankhapoalim.co.il"},
    "leumi": {"leumi.co.il"},
    "discount": {"discountbank.co.il"},
    "mizrahi": {"mizrahi-tefahot.co.il"},
    "mercantile": {"mercantile.co.il"},
    "bankisrael": {"bankisrael.co.il"},
}
# Full hostname labels where a brand name appears as substring but the label is legitimate
# (substring matching must not treat these as brand tokens — e.g. microsoft ≠ microsoftonline).
LEGITIMATE_BRAND_COMPOUND_LABELS = frozenset({
    "microsoftonline",
    "googleusercontent",
    "googleapis",
    "gstatic",
    "amazonaws",
    "cloudfront",
})
TRUSTED_TARGET_LABELS = (
    "bankisrael",
    "bankhapoalim",
    "leumi",
    "discount",
    "mizrahi",
    "mercantile",
    "paypal",
    "amazon",
    "apple",
    "google",
    "microsoft",
    "facebook",
    "instagram",
    "whatsapp",
    "bit",
    "visa",
    "mastercard",
)
TRUSTED_ROOT_DOMAINS = {
    "paypal.com",
    "amazon.com",
    "ssl-images-amazon.com",
    "media-amazon.com",
    "amazonaws.com",
    "apple.com",
    "google.com",
    "google.co.il",
    "microsoft.com",
    "microsoftonline.com",
    "live.com",
    "outlook.com",
    "office.com",
    "office365.com",
    "azure.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "visa.com",
    "mastercard.com",
    "bankhapoalim.co.il",
    "leumi.co.il",
    "discountbank.co.il",
    "mizrahi-tefahot.co.il",
}
SHORTENER_DOMAINS = (
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "rb.gy",
    "ow.ly",
    "cutt.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "shorturl.at",
    "shorten.as",
    "did.li",
)
NON_WARNING_LOCAL_KEYS = {"short_link_expanded", "short_link_destination_blocked", "tld_country_notice"}
WEAK_LOCAL_WARNING_KEYS = {"brand", "suspicious_words", "long_url", "many_hyphens"}
STRONG_LOCAL_WARNING_KEYS = {
    "brand_mismatch",
    "lookalike_brand",
    "at_sign_userinfo",
    "case_confusable",
    "mixed_scripts",
    "unicode_lookalike",
    "punycode",
    "suspicious_tld",
    "no_https",
    "single_page_site",
}
MESSAGE_WARNING_KEYS = {
    "message_pressure",
    "message_aggressive",
    "ai_social_engineering",
    "ai_authority_impersonation",
    "ai_sensitive_request",
    "ai_threat_or_reward",
    "ai_model_social_engineering",
    "ai_model_impersonation",
    "ai_model_sensitive_action",
}
SUSPICIOUS_WORDS = ("login", "verify", "secure", "account", "update")
COMPOUND_IMPERSONATION_SUFFIXES = {
    "security",
    "secure",
    "login",
    "verify",
    "account",
    "update",
    "auth",
    "signin",
    "payment",
    "pay",
    "wallet",
    "banking",
}
ENTITY_LIKE_TOKENS = {
    "bank",
    "pay",
    "payment",
    "account",
    "card",
    "wallet",
    "billing",
    "invoice",
    "auth",
    "id",
}
ACTION_SECURITY_TOKENS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "update",
    "confirm",
    "reset",
    "access",
}
GENERIC_SAFE_SUBDOMAIN_LABELS = {
    "www", "m", "mail", "api", "cdn", "static", "img", "images", "assets", "docs", "help", "status",
}
GENERIC_NON_IDENTITY_TOKENS = {
    "login",
    "signin",
    "verify",
    "secure",
    "security",
    "update",
    "account",
    "auth",
    "service",
    "portal",
    "online",
    "web",
}
SUSPICIOUS_TLDS = (".xyz", ".top", ".click", ".site", ".store")
SUSPICIOUS_MESSAGE_TERMS = (
    "urgent",
    "immediately",
    "verify now",
    "account suspended",
    "click now",
    "דחוף",
    "לחץ כאן",
    "אימות",
    "החשבון הושעה"
)
BENIGN_INFO_ALLOWLIST = (
    "לתשומת לבך",
    "למידע נוסף",
    "הודעה ללקוחות",
    "עדכון שירות",
    "שעות פעילות",
    "השירות זמין",
    "מבצע",
    "הטבה",
    "פתיחת חשבון",
    "חשבון סטודנט",
    "for your information",
    "service update",
    "working hours",
    "promotion",
    "new feature",
)
URL_REGEX = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)
# Domain-like token without scheme (e.g. evil-bank.online/path#frag) — must stay in sync with extraction logic.
BARE_URL_IN_TEXT = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:/[^\s]*)?",
    re.IGNORECASE,
)
# If there is no "/" path, reject host.lastlabel when lastlabel looks like a file extension, not a TLD.
FAKE_FILE_TLDS = frozenset({
    "txt", "pdf", "png", "jpg", "jpeg", "gif", "webp", "svg", "ico",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "rar", "7z",
    "exe", "msi", "dll", "bat", "csv", "xml", "json", "md", "log", "map",
})
CYRILLIC_OR_GREEK_CHARS = re.compile(r"[\u0370-\u03ff\u0400-\u04ff]")
HEBREW_CHAR_RE = re.compile(r"[\u0590-\u05FF]")
HTML_TAG_RE = re.compile(r"<[^>]+>")
HREF_RE = re.compile(r"""href\s*=\s*["']([^"'#][^"']*)["']""", re.IGNORECASE)
HEBREW_PHISHING_PAGE_TERMS = (
    "החשבון שלך",
    "אימות זהות",
    "אימות חשבון",
    "זוהתה פעילות חריגה",
    "החשבון הושעה",
    "לחץ כאן",
    "התחבר",
    "הזן קוד",
    "קוד אימות",
    "כרטיס אשראי",
    "עדכן פרטים",
)
FOREIGN_TLDS_FOR_HEBREW_RISK = {
    "cn", "ru", "top", "xyz", "click", "shop", "online", "site", "icu", "monster"
}
I18N = {
    "en": {
        "invalid_url": "The link format looks invalid.",
        "brand": "Looks like a known brand imitation.",
        "brand_mismatch": "Brand name appears in the link, but the real domain ownership does not match that brand.",
        "suspicious_words": "Contains words commonly used in phishing.",
        "lookalike_brand": "Domain name is almost identical to a known brand/domain (one-character trick).",
        "at_sign_userinfo": "URL uses '@' to hide the real destination domain.",
        "case_confusable": "Suspicious mixed letter casing in the hostname.",
        "mixed_scripts": "Hostname mixes alphabets; a non-Latin lookalike character was flagged.",
        "unicode_lookalike": "Hostname uses a Unicode letter that resembles Latin (homoglyph).",
        "punycode": "Link uses encoded international domain format (IDN).",
        "suspicious_tld": "Uses a risky domain ending.",
        "long_url": "The link is unusually long.",
        "many_hyphens": "Too many '-' signs in the link.",
        "no_https": "The link is not secure (no HTTPS).",
        "message_pressure": "The message uses pressure or urgency language.",
        "message_short_link": "Short message with a link can be suspicious.",
        "message_aggressive": "Aggressive punctuation detected.",
        "multiple_links_detected": "The message contains multiple links; the highest-risk link was analyzed in detail.",
        "ai_social_engineering": "Message intent looks like social engineering (pressure + action request).",
        "ai_authority_impersonation": "Message appears to impersonate an official organization/brand.",
        "ai_sensitive_request": "Message asks for sensitive action (login/payment/verification).",
        "ai_threat_or_reward": "Message uses threat or reward language to force quick action.",
        "ai_model_social_engineering": "AI detected social-engineering intent in the message.",
        "ai_model_impersonation": "AI detected likely impersonation of a trusted organization.",
        "ai_model_sensitive_action": "AI detected request for sensitive user action.",
        "ai_subdomain_impersonation_combo": "AI detected social-engineering text together with a potentially misleading subdomain.",
        "domain_reputation_warning": "Main domain reputation adds risk to this link.",
        "ai_model_unavailable": "AI semantic analysis is currently unavailable.",
        "intel_configured": "Advanced safety checks are connected: {sources}.",
        "intel_missing": "Some advanced safety checks are not connected yet.",
        "vt_malicious": "Global virus and threat databases marked this link as malicious.",
        "vt_single_vendor_flag": "A single global threat engine flagged this link. Treat as weak signal and verify context.",
        "vt_suspicious": "Global virus and threat databases found suspicious signs for this link.",
        "vt_clean": "Global virus and threat databases did not report this link as malicious.",
        "vt_pending": "A check in global threat databases has started and is still updating.",
        "vt_unavailable": "Global threat database check is unavailable right now.",
        "urlscan_malicious": "A global website scanning service marked this link as malicious.",
        "urlscan_suspicious": "A global website scanning service found suspicious signs.",
        "urlscan_clean": "A global website scanning service did not find malicious signs.",
        "urlscan_pending": "A global website scanning service is still checking this link.",
        "urlscan_unavailable": "Website scanning service is unavailable right now.",
        "gsb_malicious": "Google Safe Browsing flagged this link as unsafe.",
        "gsb_suspicious": "Google Safe Browsing found suspicious threat indicators for this link.",
        "gsb_clean": "Google Safe Browsing did not report this link as unsafe.",
        "gsb_unavailable": "Google Safe Browsing check is unavailable right now.",
        "short_link_expanded": "HTTP redirects were followed to the final URL.",
        "short_link_unresolved": "Could not follow the full redirect chain (error, loop, or blocked hop).",
        "short_link_destination_blocked": "Redirects ended on a provider block/interstitial page; analysis uses the submitted link.",
        "short_http_to_https_caution": "The short link itself is not encrypted, but it redirects to a known secure destination. Prefer opening the full secure link directly.",
        "short_https_to_http_downgrade": "The short link started as secure HTTPS, but the final destination is not secure. Do not enter personal details on the final page.",
        "shortlink_use_original_recommended": "The final destination appears safe, but the short link itself adds uncertainty. Prefer using the original full link directly.",
        "hebrew_phishing_page_signals": "The page content in Hebrew includes phishing-style pressure/action terms.",
        "hebrew_content_foreign_infra_mismatch": "The page is mainly Hebrew, but the domain infrastructure is atypical for Hebrew-targeted services.",
        "tld_country_notice": "Domain suffix points to a specific country.",
        "single_page_site": "Website appears to have only a single active page (very limited internal structure).",
        "need_input": "Please enter a URL or full message text.",
        "no_major_signals": "No strong phishing signs were found.",
        "safe_now": "No warning signs were found in this check.",
        "insufficient_trust_signals": "Not enough trust signals for a green/safe result.",
        "live_no_url": "No URL provided.",
        "live_progress": "Results are updated in real time as more data is analyzed",
        "live_high_risk_early": "High-risk signal detected. Analysis completed early.",
        "live_waiting_external": "Waiting for external analysis...",
        "live_final_verification": "Final verification pass {current}/{total}...",
        "live_completed": "Analysis completed.",
        "live_cache_loaded": "Loaded from recent cache.",
        "live_still_collecting": "Still collecting external checks. Please wait a few more seconds.",
        "explain_lookalike": "Main warning: the domain looks like an imitation of a trusted name (for example, a one-letter change)."
        ,"explain_lookalike_target": "Main warning: the domain '{seen}' is very similar to trusted name '{target}' (possible impersonation)."
        ,"explain_not_high": "There are warning signs, but not enough for high risk. Treat this link carefully."
        ,"explain_medium": "Several warning signs were found. Avoid clicking unless verified from an official source."
        ,"explain_high": "Strong phishing indicators were found. Do not open this link."
    },
    "he": {
        "invalid_url": "פורמט הקישור נראה לא תקין.",
        "brand": "נראה כמו התחזות למותג מוכר.",
        "brand_mismatch": "שם מותג מופיע בקישור, אבל הדומיין האמיתי לא שייך למותג הזה.",
        "suspicious_words": "יש מילים אופייניות לניסיונות פישינג.",
        "lookalike_brand": "שם הדומיין כמעט זהה למותג/דומיין מוכר (טריק של שינוי תו אחד).",
        "at_sign_userinfo": "הקישור משתמש ב-'@' כדי להסתיר את הדומיין האמיתי.",
        "case_confusable": "בשם המארח זוהתה בעיית ערבוב אותיות חשודה.",
        "mixed_scripts": "בשם המארח מעורבים אלפביתים שונים; סומן תו שאינו אנגלית פשוטה.",
        "unicode_lookalike": "בשם המארח יש אות יוניקוד שנראית כמו אנגלית (הומוגליף).",
        "punycode": "הקישור משתמש בפורמט דומיין מקודד (IDN).",
        "suspicious_tld": "סיומת הדומיין נחשבת חשודה.",
        "long_url": "הקישור ארוך בצורה חריגה.",
        "many_hyphens": "יש יותר מדי סימני '-' בקישור.",
        "no_https": "הקישור לא מאובטח (ללא HTTPS).",
        "message_pressure": "יש בהודעה ניסוח מלחיץ או דחוף.",
        "message_short_link": "הודעה קצרה עם קישור יכולה להיות חשודה.",
        "message_aggressive": "נמצאו סימני פיסוק אגרסיביים.",
        "multiple_links_detected": "בהודעה נמצאו כמה קישורים; הקישור בעל הסיכון הגבוה ביותר נבדק בפירוט.",
        "ai_social_engineering": "נראית כוונת הנדסה חברתית בהודעה (לחץ + בקשה לפעולה).",
        "ai_authority_impersonation": "נראה שההודעה מתחזה לגורם רשמי/מותג מוכר.",
        "ai_sensitive_request": "ההודעה מבקשת פעולה רגישה (כניסה/תשלום/אימות).",
        "ai_threat_or_reward": "ההודעה משתמשת באיום או פיתוי כדי לדחוף לפעולה מהירה.",
        "ai_model_social_engineering": "מנוע ה-AI זיהה כוונת הנדסה חברתית בהודעה.",
        "ai_model_impersonation": "מנוע ה-AI זיהה חשד להתחזות לגורם אמין.",
        "ai_model_sensitive_action": "מנוע ה-AI זיהה בקשה לפעולה רגישה מצד המשתמש.",
        "ai_subdomain_impersonation_combo": "מנוע ה-AI זיהה הנדסה חברתית יחד עם תת-דומיין שעשוי להטעות.",
        "domain_reputation_warning": "מוניטין הדומיין הראשי מוסיף סיכון לקישור זה.",
        "ai_model_unavailable": "ניתוח סמנטי מבוסס AI אינו זמין כרגע.",
        "intel_configured": "בדיקות בטיחות מתקדמות מחוברות: {sources}.",
        "intel_missing": "חלק מבדיקות הבטיחות המתקדמות עדיין לא מחוברות.",
        "vt_malicious": "בדיקה במאגרי וירוסים ואיומים עולמיים סימנה את הקישור כזדוני.",
        "vt_single_vendor_flag": "רק מנוע אחד סימן את הקישור כמסוכן.",
        "vt_suspicious": "בדיקה במאגרי וירוסים ואיומים עולמיים מצאה סימנים חשודים בקישור.",
        "vt_clean": "בדיקה במאגרי וירוסים ואיומים עולמיים לא מצאה שהקישור זדוני.",
        "vt_pending": "בדיקה במאגרי וירוסים ואיומים עולמיים התחילה ועדיין מתעדכנת.",
        "vt_unavailable": "בדיקה במאגרי האיומים העולמיים אינה זמינה כרגע.",
        "urlscan_malicious": "שירות עולמי לסריקת אתרים סימן את הקישור כזדוני.",
        "urlscan_suspicious": "שירות עולמי לסריקת אתרים מצא סימנים חשודים בקישור.",
        "urlscan_clean": "שירות עולמי לסריקת אתרים לא מצא סימנים זדוניים.",
        "urlscan_pending": "שירות עולמי לסריקת אתרים עדיין בודק את הקישור.",
        "urlscan_unavailable": "שירות סריקת האתרים אינו זמין כרגע.",
        "gsb_malicious": "Google Safe Browsing סימן את הקישור כלא בטוח.",
        "gsb_suspicious": "Google Safe Browsing מצא אינדיקציות חשודות לקישור.",
        "gsb_clean": "Google Safe Browsing לא סימן את הקישור כלא בטוח.",
        "gsb_unavailable": "בדיקת Google Safe Browsing אינה זמינה כרגע.",
        "short_link_expanded": "בוצע מעקב אחרי הפניות עד לכתובת היעד הסופית.",
        "short_link_unresolved": "לא ניתן היה למלא את שרשרת ההפניות (שגיאה, לולאה, או צעד חסום).",
        "short_link_destination_blocked": "ההפניות הסתיימו בדף חסימה/ביניים של ספק; הניתוח מבוסס על הקישור שנשלח.",
        "short_http_to_https_caution": "הקישור המקוצר עצמו אינו מוצפן, אך הוא מפנה ליעד מאובטח ומוכר. מומלץ לפתוח ישירות את הקישור המלא והמאובטח.",
        "short_https_to_http_downgrade": "הקישור המקוצר התחיל כמאובטח, אך יעד הסיום אינו מאובטח. מומלץ לא להזין פרטים אישיים בדף היעד.",
        "shortlink_use_original_recommended": "היעד הסופי נראה בטוח, אך קישור מקוצר מוסיף אי-ודאות. מומלץ להשתמש ישירות בקישור המלא המקורי.",
        "hebrew_phishing_page_signals": "בתוכן הדף בעברית נמצאו מונחי לחץ/פעולה שמאפיינים פישינג.",
        "hebrew_content_foreign_infra_mismatch": "התוכן בדף בעברית, אבל תשתית הדומיין אינה תואמת בדרך כלל לשירות שפונה לקהל עברי.",
        "tld_country_notice": "סיומת הדומיין מצביעה על מדינה מסוימת.",
        "single_page_site": "נראה שלאתר יש דף פעיל יחיד בלבד (מבנה פנימי דל מאוד).",
        "need_input": "יש להזין קישור או טקסט הודעה מלא.",
        "no_major_signals": "לא נמצאו סימני פישינג חזקים.",
        "safe_now": "בבדיקה הזו לא נמצאו סימני אזהרה.",
        "insufficient_trust_signals": "אין מספיק אותות אמון כדי לתת מצב ירוק/בטוח.",
        "live_no_url": "לא סופק קישור לבדיקה.",
        "live_progress": "התוצאות מתעדכנות בזמן אמת ככל שנאסף מידע נוסף",
        "live_high_risk_early": "זוהה סימן בסיכון גבוה. הבדיקה הושלמה מוקדם.",
        "live_waiting_external": "ממתינים לניתוח חיצוני...",
        "live_final_verification": "בדיקת אימות סופית {current}/{total}...",
        "live_completed": "הבדיקה הושלמה.",
        "live_cache_loaded": "התוצאה נטענה ממטמון עדכני.",
        "live_still_collecting": "עדיין נאסף מידע חיצוני. נא להמתין עוד מספר שניות.",
        "explain_lookalike": "האזהרה המרכזית: הדומיין נראה כהתחזות לשם אמין (למשל שינוי של אות אחת)."
        ,"explain_lookalike_target": "האזהרה המרכזית: הדומיין '{seen}' דומה מאוד לשם האמין '{target}' (חשד להתחזות)."
        ,"explain_not_high": "זוהו סימני אזהרה, אבל לא ברמה גבוהה. מומלץ להתייחס לקישור בזהירות."
        ,"explain_medium": "זוהו כמה סימני אזהרה משמעותיים. לא ללחוץ לפני אימות מול מקור רשמי."
        ,"explain_high": "זוהו סימנים חזקים לפישינג. לא לפתוח את הקישור."
    }
}


def t(language: str, key: str, **kwargs) -> str:
    lang = "he" if language == "he" else "en"
    template = I18N[lang][key]
    return template.format(**kwargs) if kwargs else template


# Copy onto live snapshots / partial results so UI can name the exact spoof character.
_SNAPSHOT_URL_CONTEXT_KEYS = (
    "case_confusable_char",
    "case_confusable_lower_host",
    "mixed_scripts_char",
    "unicode_lookalike_char",
    "domain_tld",
    "tld_country_code",
    "lookalike_target",
    "lookalike_seen",
    "brand_target",
    "brand_seen_domain",
)


def _localized_reason_line(language: str, key: str, ctx: dict) -> str:
    """Build one human line for API `reasons` when extra hostname context exists."""
    he = language == "he"
    if key == "case_confusable":
        ch = (ctx.get("case_confusable_char") or "").strip()
        low = (ctx.get("case_confusable_lower_host") or "").strip()
        if ch:
            tail = f" צורה מנורמלת להשוואה: {low}" if (he and low) else (f" Normalized for comparison: {low}" if low else "")
            if he:
                return f"בשם המארח מופיע התו «{ch}» — אות גדולה באמצע שנועדה להיראות כמו אות קטנה.{tail}"
            return f'Misleading hostname character «{ch}» (mixed capitals).{tail}'
    if key == "mixed_scripts":
        c = (ctx.get("mixed_scripts_char") or "").strip()
        if c:
            if he:
                return f"בשם המארח מופיע התו «{c}» — אות שאינה אנגלית ASCII פשוטה (`a-z`), והערבוב עם לטינית מעלה חשד להטעיה."
            return f'Hostname mixes scripts; flagged character «{c}» (not plain Latin).'
    if key == "unicode_lookalike":
        c = (ctx.get("unicode_lookalike_char") or "").strip()
        if c:
            if he:
                return f"בשם המארח מופיע התו «{c}» — נראה כמו אות לטינית רגילה אך שייך לאלפבית אחר (הומוגליף)."
            return f'Lookalike Unicode letter «{c}» in hostname (homoglyph).'
    return t(language, key)


def count_term_hits(text: str, terms: tuple[str, ...] | list[str]) -> int:
    return sum(1 for term in terms if term in text)


def detect_brand_token_in_hostname(hostname: str) -> str:
    """
    Find brand keys in hostname labels using token/segment boundaries.
    Avoids false positives where a brand name is a substring of a real label
    (e.g. 'microsoft' inside 'microsoftonline' on login.microsoftonline.com).
    """
    registrable = get_registrable_domain(hostname)
    registrable_label = get_primary_label(hostname)
    if not registrable or not registrable_label:
        return ""

    labels = [registrable_label]
    brand_keys = sorted(BRAND_CANONICAL_DOMAINS.keys(), key=len, reverse=True)
    for label in labels:
        if label in LEGITIMATE_BRAND_COMPOUND_LABELS:
            continue
        segments = [s for s in re.split(r"[-_]+", label) if s]
        for segment in segments:
            if segment in LEGITIMATE_BRAND_COMPOUND_LABELS:
                continue
            if segment in BRAND_CANONICAL_DOMAINS:
                return segment
        if label in BRAND_CANONICAL_DOMAINS:
            return label
        for segment in segments:
            if segment in LEGITIMATE_BRAND_COMPOUND_LABELS:
                continue
            for token in brand_keys:
                if len(segment) <= len(token):
                    continue
                if segment.startswith(token) or segment.endswith(token):
                    return token
    return ""


def detect_brand_token_in_path(path: str) -> str:
    path_value = (path or "").lower()
    tokens = [token for token in re.split(r"[/\-_.]+", path_value) if token]
    for token in tokens:
        if token in BRAND_CANONICAL_DOMAINS:
            return token
    return ""


def has_action_security_token_in_path(path: str) -> bool:
    path_value = (path or "").lower()
    tokens = [token for token in re.split(r"[/\-_.]+", path_value) if token]
    return any(
        token in ACTION_SECURITY_TOKENS or token in COMPOUND_IMPERSONATION_SUFFIXES
        for token in tokens
    )


def detect_structural_identity_impersonation(hostname: str) -> str:
    """
    Generic structural detection (not example-specific):
    identity-like token + security/action token inside registrable label.
    Examples: bankaustria-security.com, paypal-login.net
    """
    host = (hostname or "").lower()
    registrable_domain = get_registrable_domain(host)
    if not registrable_domain or registrable_domain in TRUSTED_ROOT_DOMAINS:
        return ""

    primary_label = get_primary_label(host)
    if "-" not in primary_label:
        return ""

    parts = [p for p in re.split(r"[-_.]+", primary_label) if p]
    meaningful_parts = [p for p in parts if len(p) >= 2]
    if len(meaningful_parts) < 2:
        return ""

    has_action_token = any(
        part in ACTION_SECURITY_TOKENS or part in COMPOUND_IMPERSONATION_SUFFIXES
        for part in meaningful_parts
    )
    has_entity_token = any(
        part in ENTITY_LIKE_TOKENS
        or part.startswith("bank")
        or part.startswith("pay")
        or part.startswith("auth")
        for part in meaningful_parts
    )

    identity_candidate = meaningful_parts[0]
    looks_like_identity = (
        identity_candidate.isalnum()
        and len(identity_candidate) >= 5
        and identity_candidate not in GENERIC_NON_IDENTITY_TOKENS
    )

    if has_action_token and (has_entity_token or looks_like_identity):
        return identity_candidate
    return ""


def normalize_lookalike_text(value: str) -> str:
    """Normalize common digit-substitution tricks used in phishing domains."""
    char_map = str.maketrans({
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t"
    })
    return value.translate(char_map)


def detect_script(ch: str) -> str:
    if "a" <= ch <= "z":
        return "latin"
    # Hebrew
    if "\u0590" <= ch <= "\u05ff":
        return "hebrew"
    # Cyrillic
    if "\u0400" <= ch <= "\u04ff":
        return "cyrillic"
    # Greek
    if "\u0370" <= ch <= "\u03ff":
        return "greek"
    return "other"


def has_mixed_scripts(text: str) -> bool:
    scripts = set()
    for ch in text.lower():
        if not ch.isalpha():
            continue
        script = detect_script(ch)
        if script != "other":
            scripts.add(script)
    return len(scripts) > 1


def _first_non_ascii_latin_letter(hostname: str) -> str:
    """First hostname letter that is not plain ASCII a–z (any case), for UI callouts."""
    for ch in hostname:
        if not ch.isalpha():
            continue
        o = ord(ch)
        if ord("A") <= o <= ord("Z") or ord("a") <= o <= ord("z"):
            continue
        return ch
    return ""


def ascii_skeleton(text: str) -> str:
    """
    Convert common homoglyphs to a latin-like skeleton.
    This is not perfect, but catches many phishing obfuscation patterns.
    """
    # NFKD helps normalize some compatibility characters first.
    normalized = unicodedata.normalize("NFKD", text.lower())
    map_chars = {
        # Cyrillic lookalikes
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "к": "k", "м": "m", "в": "b", "н": "h", "т": "t",
        # Greek lookalikes
        "α": "a", "β": "b", "γ": "y", "δ": "d", "ε": "e", "ι": "i", "κ": "k", "ο": "o", "ρ": "p", "τ": "t", "υ": "y", "χ": "x",
    }
    converted = "".join(map_chars.get(ch, ch) for ch in normalized)
    return normalize_lookalike_text(converted)


def is_one_edit_away(a: str, b: str) -> bool:
    """Return True when strings are one edit away (insert/delete/replace)."""
    if a == b:
        return False
    if abs(len(a) - len(b)) > 1:
        return False

    # Two-pointer one-edit check (fast and enough for our domain labels).
    i = 0
    j = 0
    edits = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        edits += 1
        if edits > 1:
            return False
        if len(a) > len(b):
            i += 1
        elif len(b) > len(a):
            j += 1
        else:
            i += 1
            j += 1

    # Remaining trailing char counts as one edit.
    if i < len(a) or j < len(b):
        edits += 1

    return edits == 1


def similarity_ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def find_lookalike_target(label_normalized: str) -> str:
    """
    Identify suspiciously similar trusted labels.
    This is principle-based fuzzy matching, not exact example matching.
    """
    best_target = ""
    best_ratio = 0.0
    for trusted in TRUSTED_TARGET_LABELS:
        if label_normalized == trusted:
            continue
        if abs(len(label_normalized) - len(trusted)) > 2:
            continue
        ratio = similarity_ratio(label_normalized, trusted)
        if ratio > best_ratio:
            best_ratio = ratio
            best_target = trusted

    # Strong fuzzy similarity threshold for lookalike domains.
    if best_target and best_ratio >= 0.84:
        return best_target
    return ""


def get_primary_label(hostname: str) -> str:
    """Get registrable primary label using PSL extraction."""
    host = (hostname or "").lower().strip(".")
    if not host:
        return ""
    ext = psl_extract(host)
    if ext.domain:
        return ext.domain.lower()
    parts = [p for p in host.split(".") if p]
    return parts[-1] if parts else ""


def get_registrable_domain(hostname: str) -> str:
    """Return registrable domain (eTLD+1) using PSL-aware extraction."""
    host = (hostname or "").lower().strip(".")
    if not host:
        return ""
    ext = psl_extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain.lower()}.{ext.suffix.lower()}"
    return host


def _strip_leading_www(hostname: str) -> str:
    """Normalize host comparisons by ignoring a leading www label."""
    host = (hostname or "").lower().strip(".")
    if host.startswith("www."):
        return host[4:]
    return host


def brand_key_for_canonical_domain(domain: str) -> str:
    value = (domain or "").lower().strip(".")
    if not value:
        return ""
    for brand_key, domains in BRAND_CANONICAL_DOMAINS.items():
        if value in domains:
            return brand_key
    return ""


def detect_embedded_trusted_root_in_subdomain(hostname: str, registrable_domain: str) -> str:
    """
    Detect impersonation via embedded trusted root domain inside the subdomain part.
    Example: apple.com.verify-user.net (registrable: verify-user.net) embeds apple.com.

    Returns the embedded trusted root domain when found, else empty string.
    """
    host = (hostname or "").lower().strip(".")
    reg = (registrable_domain or "").lower().strip(".")
    if not host or not reg:
        return ""
    if host == reg or not host.endswith(f".{reg}"):
        return ""
    subdomain_part = host[: -(len(reg) + 1)]  # remove ".<registrable>"
    if not subdomain_part:
        return ""
    labels = [p for p in subdomain_part.split(".") if p]
    if len(labels) < 2:
        return ""
    # Scan for any trusted root domain embedded as consecutive labels.
    # Prefer longer matches first.
    trusted = sorted(TRUSTED_ROOT_DOMAINS, key=len, reverse=True)
    for candidate in trusted:
        if subdomain_part == candidate or subdomain_part.endswith(f".{candidate}"):
            return candidate
    return ""


def extract_host_preserve_case(parsed_url) -> str:
    """
    Extract hostname while preserving original casing from netloc.
    urlparse().hostname lowercases the value, so we derive from netloc for case checks.
    """
    netloc = parsed_url.netloc or ""
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]
    if ":" in netloc:
        netloc = netloc.split(":", 1)[0]
    return netloc.strip("[]")


def _bare_url_candidate_ok(raw: str) -> bool:
    """Filter false positives (e.g. report.pdf) for bare domain matches."""
    s = raw.strip(".,);]").strip()
    if not s:
        return False
    hostport = s.split("/", 1)[0]
    host = hostport.split(":", 1)[0]
    # Skip IPv4-looking hosts (avoid matching 1.2.3.4 as a domain)
    parts = host.split(".")
    if len(parts) >= 2 and all(p.isdigit() for p in parts):
        return False
    if "/" not in s:
        labels = host.rsplit(".", 1)
        if len(labels) == 2 and labels[-1].lower() in FAKE_FILE_TLDS:
            return False
    return True


def _extract_bare_domain_url(text: str) -> str:
    """First domain[/path] without scheme (e.g. finanz.example.online/path#x)."""
    for m in BARE_URL_IN_TEXT.finditer(text):
        cand = m.group(0)
        if _bare_url_candidate_ok(cand):
            return cand.strip(".,);]")
    return ""


def extract_urls(text: str) -> list[str]:
    """Extract unique URLs from message text, preserving first-seen order."""
    if not text:
        return []
    candidates: list[tuple[int, str]] = []
    urls: list[str] = []
    seen: set[str] = set()

    def collect(start: int, candidate: str) -> None:
        candidates.append((start, candidate))

    def add(candidate: str) -> None:
        value = (candidate or "").strip(".,);]")
        if not value:
            return
        if value.startswith("www."):
            value = f"https://{value}"
        normalized = normalize_url_for_checks(value)
        if not normalized:
            return
        key = normalized.lower()
        if key in seen:
            return
        seen.add(key)
        urls.append(normalized)

    for match in URL_REGEX.finditer(text):
        collect(match.start(), match.group(0))

    for domain in SHORTENER_DOMAINS:
        pattern = re.compile(rf"\b{re.escape(domain)}/\S+", re.IGNORECASE)
        for match in pattern.finditer(text):
            collect(match.start(), match.group(0))

    for match in BARE_URL_IN_TEXT.finditer(text):
        cand = match.group(0)
        if _bare_url_candidate_ok(cand):
            collect(match.start(), cand)

    for _, candidate in sorted(candidates, key=lambda item: item[0]):
        add(candidate)

    return urls


def extract_first_url(text: str) -> str:
    """Extract first URL from text if present."""
    urls = extract_urls(text)
    return urls[0] if urls else ""


def normalize_url_for_checks(url: str) -> str:
    if not url:
        return ""
    value = url.strip()
    if "://" not in value:
        value = f"https://{value}"
    return value


def decode_url_for_analysis(url: str) -> str:
    """
    Decode percent-encoded URL parts in a controlled manner before analysis.
    We decode at most twice to handle nested encodings without going unbounded.
    """
    normalized = normalize_url_for_checks(url)
    if not normalized:
        return normalized
    decoded = normalized
    for _ in range(2):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def canonicalize_url_for_external_intel(url: str) -> str:
    """
    Build stable URL form for external reputation APIs.
    Keeps same resource but normalizes query ordering and strips fragment.
    """
    normalized = normalize_url_for_checks(url)
    if not normalized:
        return ""
    try:
        p = urlparse(normalized)
        query_pairs = parse_qsl(p.query, keep_blank_values=True)
        query_pairs.sort(key=lambda kv: (kv[0], kv[1]))
        stable_query = urlencode(query_pairs, doseq=True)
        stable = p._replace(query=stable_query, fragment="")
        return urlunparse(stable)
    except Exception:
        return normalized


def _drop_url_fragment(url: str) -> str:
    """Return URL without client-side fragment (#...), preserving everything else."""
    normalized = normalize_url_for_checks(url)
    if not normalized:
        return ""
    p = urlparse(normalized)
    if not p.fragment:
        return normalized
    return p._replace(fragment="").geturl()


def _safe_url_for_server_redirect(url: str) -> bool:
    """
    Reject URLs that must not be fetched server-side (SSRF / internal network).
    Only http/https allowed; block localhost, private IPs, link-local, metadata.
    """
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    host = (p.hostname or "").strip().lower()
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "metadata", "metadata.google.internal"):
        return False
    if host == "169.254.169.254":
        return False
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return False
    except ValueError:
        pass
    return True


def _tls_verify_bundle() -> bool | str:
    """Prefer Mozilla CA bundle via certifi (fixes many Windows/Python SSL issues)."""
    try:
        import certifi

        return certifi.where()
    except Exception:
        return True


def _redirect_session_get(session: requests.Session, url: str, *, headers: dict, timeout: int) -> requests.Response:
    """
    GET for redirect following. Retry without TLS verify if the server's chain fails
    locally (common with some CDNs/shorteners). Set REDIRECT_FETCH_STRICT_SSL=1 to disable retry.
    """
    verify = _tls_verify_bundle()
    try:
        return session.get(url, allow_redirects=False, headers=headers, timeout=timeout, verify=verify)
    except requests.exceptions.SSLError:
        if os.getenv("REDIRECT_FETCH_STRICT_SSL", "").lower() in {"1", "true", "yes", "on"}:
            raise
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return session.get(url, allow_redirects=False, headers=headers, timeout=timeout, verify=False)


def _html_interstitial_or_block_page(r: requests.Response) -> bool:
    """Detect ISP / DNS sinkhole / blocking HTML that is not a real final destination."""
    if r.status_code != 200:
        return False
    ct = (r.headers.get("Content-Type") or "").lower()
    if "text/html" not in ct:
        return False
    head = (r.text or "")[:20000].lower()
    # Keep markers specific: the substring "interstitial" appears in normal SPA
    # bundles (e.g. WhatsApp web) and must not classify real destinations as blocks.
    markers = (
        "dns blocking",
        "sinkhole",
        "blocked page",
        "a1 | dns blocking",
        "connection blocked",
        "zugriff verweigert",
    )
    return any(m in head for m in markers)


def expand_short_url(url: str) -> tuple[str, list[str], list[str]]:
    """
    Follow HTTP redirect hops (any shortener or generic site) to the final URL, then analyze that.
    Uses hop-by-hop GET with allow_redirects=False so each Location can be validated (SSRF-safe).
    Returns (final_url, reason_keys, redirect_chain).
    """
    reason_keys: list[str] = []
    redirect_chain: list[str] = []
    normalized = normalize_url_for_checks(url)
    if not normalized:
        return normalized, reason_keys, redirect_chain

    # Client-side fragment is not sent to servers; treat fragment-free URL as canonical step.
    canonical_start = _drop_url_fragment(normalized)
    if canonical_start != normalized:
        redirect_chain = [normalized, canonical_start]
    else:
        redirect_chain = [normalized]

    if not _safe_url_for_server_redirect(canonical_start):
        reason_keys.append("short_link_unresolved")
        return normalized, reason_keys, redirect_chain

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }
    session = requests.Session()
    current = canonical_start
    max_hops = 12
    last_resp: requests.Response | None = None
    saw_http_redirect = False

    for _ in range(max_hops):
        try:
            r = _redirect_session_get(session, current, headers=headers, timeout=12)
        except Exception:
            # Network unresolved applies when HTTP redirect chain started and then failed.
            if saw_http_redirect:
                reason_keys.append("short_link_unresolved")
            return current, reason_keys, redirect_chain

        last_resp = r

        if r.status_code in (301, 302, 303, 307, 308):
            saw_http_redirect = True
            loc = r.headers.get("Location")
            if not loc:
                reason_keys.append("short_link_unresolved")
                return current, reason_keys, redirect_chain
            next_u = urljoin(current, loc.strip())
            if not _safe_url_for_server_redirect(next_u):
                reason_keys.append("short_link_unresolved")
                return current, reason_keys, redirect_chain
            if next_u in redirect_chain:
                reason_keys.append("short_link_unresolved")
                return current, reason_keys, redirect_chain
            redirect_chain.append(next_u)
            current = next_u
            continue

        break

    final = current
    # Passthrough hop returned HTML block page (e.g. ISP sinkhole) — not a real destination,
    # but HTTP redirect following did complete; analysis falls back to the submitted URL.
    if last_resp is not None and _html_interstitial_or_block_page(last_resp):
        reason_keys.append("short_link_expanded")
        reason_keys.append("short_link_destination_blocked")
        # If the last hop landed on a known-trusted host (e.g. api.whatsapp.com), keep it for
        # analysis even when HTML heuristics misfire on legitimate SPA content.
        cand_host = (urlparse(current).hostname or "").lower()
        cand_reg = get_registrable_domain(cand_host) if cand_host else ""
        if cand_reg in TRUSTED_ROOT_DOMAINS:
            final = current
        else:
            final = canonical_start
        return final, reason_keys, redirect_chain

    if len(redirect_chain) > 1:
        reason_keys.append("short_link_expanded")
    return final, reason_keys, redirect_chain


def analyze_url(url: str) -> tuple[int, list[str], dict]:
    """Analyze URL heuristics and return partial score + reasons."""
    score = 0
    reasons = []
    normalized_url = (url or "").strip()

    context = {}
    if not normalized_url:
        return 0, reasons, context

    # Parse URL parts; add temporary https scheme if missing for robust parsing.
    parsed = urlparse(normalized_url if "://" in normalized_url else f"https://{normalized_url}")
    lower_url = normalized_url.lower()
    hostname = (parsed.hostname or "").lower()
    path_value = parsed.path or ""
    searchable_path = " ".join(
        part for part in [parsed.path, parsed.params, parsed.query, parsed.fragment] if part
    ).lower()
    host_case_raw = extract_host_preserve_case(parsed)
    netloc_raw = parsed.netloc or ""

    # Basic format validation: require a hostname like example.com.
    if not hostname or "." not in hostname:
        reasons.append("invalid_url")
        return score, reasons, context

    registrable_domain = get_registrable_domain(hostname)
    registrable_label = get_primary_label(hostname)
    is_brand_canonical_domain = any(
        registrable_domain in domains for domains in BRAND_CANONICAL_DOMAINS.values()
    )

    # Strong phishing: embedded trusted root domain inside subdomain but registrable owner differs.
    # Example: apple.com.verify-user.net embeds "apple.com" while registrable is verify-user.net.
    embedded_trusted = detect_embedded_trusted_root_in_subdomain(hostname, registrable_domain)
    if embedded_trusted:
        score += 120
        reasons.append("brand_mismatch")
        brand_key = brand_key_for_canonical_domain(embedded_trusted) or get_primary_label(embedded_trusted)
        if brand_key:
            context["brand_target"] = brand_key
        context["brand_seen_domain"] = registrable_domain

    # Rule: suspicious account/action words are common in phishing URLs.
    # Evaluate on URL path/query/fragment only, not subdomains.
    if any(word in searchable_path for word in SUSPICIOUS_WORDS):
        score += 15
        reasons.append("suspicious_words")

    brand_token = detect_brand_token_in_hostname(hostname)
    if brand_token:
        canonical_domains = BRAND_CANONICAL_DOMAINS.get(brand_token, set())
        exact_brand_label = registrable_label == brand_token
        if canonical_domains and registrable_domain not in canonical_domains and not exact_brand_label:
            # Structural identity mismatch: brand-like host but wrong registrable owner domain.
            score += 120
            reasons.append("brand_mismatch")
            context["brand_target"] = brand_token
            context["brand_seen_domain"] = registrable_domain

    # Brand token in path + action/security token on a different registrable domain
    # is a strong impersonation indicator (e.g. google.com/paypal/login).
    if "brand_mismatch" not in reasons:
        path_brand_token = detect_brand_token_in_path(path_value)
        if path_brand_token and has_action_security_token_in_path(path_value):
            canonical_domains = BRAND_CANONICAL_DOMAINS.get(path_brand_token, set())
            if canonical_domains and registrable_domain not in canonical_domains:
                score += 110
                reasons.append("brand_mismatch")
                context["brand_target"] = path_brand_token
                context["brand_seen_domain"] = registrable_domain

    # Generic identity mismatch without brand whitelist:
    # detects brand-like compound registrable labels such as <identity>-security.*
    if "brand_mismatch" not in reasons:
        structural_identity = detect_structural_identity_impersonation(hostname)
        if structural_identity:
            score += 110
            reasons.append("brand_mismatch")
            context["brand_target"] = structural_identity
            context["brand_seen_domain"] = registrable_domain

    # Weak brand hint is allowed only when registrable owner label is different.
    # This avoids false positives on legitimate country domains like amazon.de.
    brand_hit = next((pattern for pattern in BRAND_PATTERNS if pattern in hostname), "")
    if brand_hit and "brand_mismatch" not in reasons:
        canonical_domains = BRAND_CANONICAL_DOMAINS.get(brand_hit, set())
        if registrable_domain in canonical_domains:
            brand_hit = ""
        if brand_hit and registrable_label and registrable_label != brand_hit:
            score += 20
            reasons.append("brand")
            context["brand_target"] = brand_hit

    # Rule: some top-level domains are frequently abused.
    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 20
        reasons.append("suspicious_tld")

    # Rule: punycode is often used to hide IDN lookalikes.
    if "xn--" in hostname:
        score += 25
        reasons.append("punycode")

    # Rule: mixing scripts (latin + cyrillic/greek/hebrew) is suspicious.
    if has_mixed_scripts(hostname):
        score += 30
        reasons.append("mixed_scripts")
        c_mix = _first_non_ascii_latin_letter(hostname)
        if c_mix:
            context["mixed_scripts_char"] = c_mix

    # Rule: unicode lookalikes that change when mapped to ASCII skeleton.
    if CYRILLIC_OR_GREEK_CHARS.search(hostname):
        skeleton = ascii_skeleton(hostname)
        ascii_only = re.sub(r"[^a-z0-9.-]", "", skeleton)
        if ascii_only and ascii_only != hostname:
            score += 30
            reasons.append("unicode_lookalike")
            m_hom = CYRILLIC_OR_GREEK_CHARS.search(hostname)
            if m_hom:
                context["unicode_lookalike_char"] = m_hom.group(0)

    # Rule: detect lookalike domains (e.g. bank1srael / banklsrael vs bankisrael).
    label = get_primary_label(hostname).replace("-", "")
    label_normalized = normalize_lookalike_text(label)
    is_lookalike = False
    lookalike_target = ""
    for brand in PROTECTED_BRANDS:
        if label == brand:
            continue
        if label_normalized == brand or is_one_edit_away(label_normalized, brand):
            is_lookalike = True
            lookalike_target = brand
            break

    if not is_lookalike:
        fuzzy_target = find_lookalike_target(label_normalized)
        if fuzzy_target:
            is_lookalike = True
            lookalike_target = fuzzy_target

    if is_lookalike:
        score += 70
        reasons.append("lookalike_brand")
        context["lookalike_seen"] = label
        context["lookalike_target"] = lookalike_target

    # Rule: suspicious case-mixing (e.g. iI) is a strong phishing indicator.
    # Ignore an uppercase first character only (common auto-capitalization),
    # and trigger only when uppercase appears later in the hostname.
    upper_positions = [
        (idx, ch)
        for idx, ch in enumerate(host_case_raw)
        if ch.isalpha() and ch.isupper()
    ]
    has_lower = any(ch.isalpha() and ch.islower() for ch in host_case_raw)
    suspicious_upper = next((ch for idx, ch in upper_positions if idx > 0), "")
    if has_lower and suspicious_upper:
        score += 70
        reasons.append("case_confusable")
        context["case_confusable_char"] = suspicious_upper
        context["case_confusable_lower_host"] = host_case_raw.lower()

    # Rule: URLs with userinfo (@) are a classic phishing obfuscation trick.
    if "@" in netloc_raw:
        score += 100
        reasons.append("at_sign_userinfo")

    # Rule: unusually long host/domain labels can be suspicious.
    # Do not score long query/path strings by themselves.
    if len(hostname) > 45:
        score += 10
        reasons.append("long_url")

    # Rule: many hyphens in the host/domain (not query params) can indicate deception.
    if hostname.count("-") >= 3 and not is_brand_canonical_domain:
        score += 10
        reasons.append("many_hyphens")

    # Rule: non-HTTPS URLs are less trustworthy.
    has_https = lower_url.startswith("https://")
    if not has_https:
        score += 25
        reasons.append("no_https")

    return score, reasons, context


def analyze_message_text(message: str) -> tuple[int, list[str]]:
    """Analyze phishing language patterns in full SMS/email text."""
    score = 0
    reasons = []
    text = (message or "").strip().lower()
    if not text:
        return score, reasons

    # Urgency and pressure wording is common in social engineering.
    hit_count = count_term_hits(text, SUSPICIOUS_MESSAGE_TERMS)
    benign_hits = count_term_hits(text, BENIGN_INFO_ALLOWLIST)
    has_hard_pressure = any(term in text for term in ("urgent", "immediately", "דחוף", "מייד", "מיידית"))
    if hit_count and not (benign_hits > 0 and not has_hard_pressure):
        score += min(20, hit_count * 8)
        reasons.append("message_pressure")

    # Very short message with link-only pattern is suspicious.
    has_link = (
        bool(URL_REGEX.search(text))
        or bool(_extract_bare_domain_url(text))
        or any(
            re.search(rf"\b{re.escape(d)}/\S+", text, re.IGNORECASE) for d in SHORTENER_DOMAINS
        )
    )
    if len(text) < 35 and has_link:
        score += 10
        reasons.append("message_short_link")

    # Excessive punctuation is often used for pressure.
    if "!!!" in text:
        score += 5
        reasons.append("message_aggressive")

    return score, reasons


def analyze_message_intent(message: str) -> tuple[int, list[str]]:
    """
    AI-like intent layer (without hardcoding one exact phrase):
    scores social-engineering patterns by combining multiple semantic signals.
    """
    text = (message or "").strip().lower()
    if not text:
        return 0, []

    urgency_terms = [
        "urgent", "immediately", "now", "today", "asap",
        "דחוף", "מייד", "מיידית", "עכשיו", "בהקדם", "לאלתר", "מיידי"
    ]
    authority_terms = [
        "bank", "paypal", "amazon", "company", "security team", "support",
        "בנק", "חברת", "חברה", "מחלקת אבטחה", "צוות אבטחה", "תמיכה", "שירות לקוחות"
    ]
    sensitive_action_terms = [
        "login", "log in", "verify", "verification", "confirm", "password",
        "payment", "pay now", "card details", "credit card", "otp", "one-time code",
        "secure your account", "update your details", "reset password",
        "התחבר", "התחברות", "אימות", "אשר", "סיסמה", "תשלום", "שלם",
        "פרטי כרטיס", "כרטיס אשראי", "קוד חד פעמי", "קוד אימות",
        "עדכן פרטים", "אשר את חשבונך", "אבטח את חשבונך", "שחזור סיסמה"
    ]
    action_verbs = [
        "click", "enter", "login", "log in", "verify", "confirm", "update", "pay", "submit",
        "לחץ", "הזן", "הכנס", "התחבר", "אמת", "אשר", "עדכן", "שלם", "שלחו"
    ]
    threat_or_reward_terms = [
        "suspended", "blocked", "penalty", "fine", "won", "gift", "will be blocked", "account locked",
        "נחסם", "ייחסם", "יחסם", "יושעה", "הושעה", "קנס", "תזכה", "זכית", "מתנה"
    ]

    has_urgency = any(term in text for term in urgency_terms)
    has_authority = any(term in text for term in authority_terms)
    has_sensitive_keyword = any(term in text for term in sensitive_action_terms)
    has_action_verb = any(term in text for term in action_verbs)
    has_sensitive_request = has_sensitive_keyword and has_action_verb
    has_threat_or_reward = any(term in text for term in threat_or_reward_terms)
    has_imperative_pattern = bool(
        re.search(r"(הכנס|לחץ|אשר|עדכן|התחבר).*(מייד|עכשיו|לאלתר|בהקדם)", text)
    )
    benign_hits = count_term_hits(text, BENIGN_INFO_ALLOWLIST)
    has_benign_info_context = benign_hits > 0

    # Reduce false positives for official informational/marketing messages.
    if has_benign_info_context and not (has_urgency or has_threat_or_reward or has_imperative_pattern):
        return 0, []

    score = 0
    reasons: list[str] = []

    # Composite signals - the core of social engineering.
    if has_urgency and (has_sensitive_request or has_imperative_pattern):
        score += 20
        reasons.append("ai_social_engineering")
    if has_authority and has_sensitive_request and (has_urgency or has_threat_or_reward or has_imperative_pattern):
        score += 20
        reasons.append("ai_authority_impersonation")
    if has_sensitive_request and (has_urgency or has_threat_or_reward or has_imperative_pattern):
        score += 10
        reasons.append("ai_sensitive_request")
    if has_threat_or_reward and (has_sensitive_request or has_urgency):
        score += 15
        reasons.append("ai_threat_or_reward")
    if has_imperative_pattern and has_sensitive_request:
        score += 15
        if "ai_social_engineering" not in reasons:
            reasons.append("ai_social_engineering")

    # Allowlist is only a soft balancer: it can reduce weak signals, never override strong ones.
    has_strong_attack_signal = has_threat_or_reward or has_imperative_pattern or (has_urgency and has_sensitive_request)
    if benign_hits > 0 and not has_strong_attack_signal and score > 0:
        score = max(0, score - min(15, benign_hits * 6))
        if score == 0:
            reasons = []

    return min(45, score), reasons


def analyze_message_intent_with_model(message: str, url: str) -> tuple[int, list[str]]:
    """
    Optional real AI layer.
    Returns additional score + reason keys.
    Falls back safely when model is unavailable.
    """
    if not message or not gemini_api_key:
        return 0, []

    schema_prompt = """
You are a phishing detection assistant.
Analyze the message and URL semantically.
Important:
- The message can be in any language. Detect intent regardless of language.
- Official informational/marketing messages are NOT phishing by default.
- Mark sensitive_action=true only when there is an explicit request to login, pay, verify, share credentials, or perform account-security action.
- Mark impersonation=true only when there are clear signs the sender pretends to be another trusted entity.
- If the message is informational and has no pressure/threat/urgent demand, keep all flags false.
Return STRICT JSON only with these boolean keys:
- social_engineering
- impersonation
- sensitive_action
"""

    prompt = (
        f"{schema_prompt}\n\n"
        f"message: {message}\n"
        f"url: {url}\n"
    )
    text = _gemini_generate_text(
        prompt=prompt,
        response_mime_type="application/json",
        temperature=0.0,
        timeout_sec=10,
    )
    if not text:
        return 0, ["ai_model_unavailable"]
    try:
        parsed = json.loads(text)
    except Exception:
        return 0, ["ai_model_unavailable"]

    score = 0
    reasons: list[str] = []
    if bool(parsed.get("social_engineering")):
        score += 20
        reasons.append("ai_model_social_engineering")
    if bool(parsed.get("impersonation")):
        score += 20
        reasons.append("ai_model_impersonation")
    if bool(parsed.get("sensitive_action")):
        score += 15
        reasons.append("ai_model_sensitive_action")

    return min(45, score), reasons


def build_ai_model_summary(
    *,
    message: str,
    submitted_url: str,
    analyzed_url: str,
    language: str,
    risk_level: str,
    reason_keys: list[str],
    domain_verdict: dict,
    tld_country_code: str,
) -> str:
    """Dynamic user-facing AI summary synced with final findings."""
    has_short_http_context = "short_http_to_https_caution" in (reason_keys or [])
    has_short_https_downgrade = "short_https_to_http_downgrade" in (reason_keys or [])
    if not gemini_api_key or (not message and not (has_short_http_context or has_short_https_downgrade)):
        return ""
    response_language = "Hebrew" if language == "he" else "English"
    context_blob = {
        "submitted_url": submitted_url,
        "analyzed_url": analyzed_url,
        "risk_level": risk_level,
        "reason_keys": reason_keys,
        "domain_verdict": domain_verdict,
        "tld_country_code": tld_country_code,
    }
    prompt = (
        "You are a phishing-risk explainer.\n"
        f"Respond strictly in {response_language}.\n"
        "Write 2-4 short sentences, plain language for non-technical users.\n"
        "Must explain risk by combining message text and technical findings.\n"
        "State only findings explicitly present in reason_keys/domain_verdict.\n"
        "Do not claim a URL is blocked, malicious, or confirmed dangerous unless one of these appears: "
        "vt_malicious, urlscan_malicious, gsb_malicious, brand_mismatch.\n"
        "If a short URL redirects to a trusted final domain and no malicious key exists, phrase it as cautionary but low risk.\n"
        "If there is country mismatch or suspicious short/final URL behavior, mention it clearly.\n"
        "Do not output JSON.\n\n"
        f"message: {message or '[No message provided]'}\n"
        f"findings: {json.dumps(context_blob, ensure_ascii=False)}\n"
    )
    text = _gemini_generate_text(
        prompt=prompt,
        temperature=0.1,
        timeout_sec=10,
    )
    return str(text or "").strip()


def external_intel_status(url: str) -> tuple[str, list[str]]:
    if not url:
        return "", []

    enabled_sources = []
    if os.getenv("VIRUSTOTAL_API_KEY"):
        enabled_sources.append("VirusTotal")
    if os.getenv("URLSCAN_API_KEY"):
        enabled_sources.append("URLScan")
    if os.getenv("GOOGLE_SAFE_BROWSING_API_KEY"):
        enabled_sources.append("Google Safe Browsing")

    if enabled_sources:
        return "intel_configured", enabled_sources
    return "intel_missing", []


def _should_query_google_safe_browsing(
    *,
    url_score: int,
    url_reason_keys: list[str],
    was_short_link: bool,
    has_message: bool,
) -> bool:
    strong_keys = {"brand_mismatch", "lookalike_brand", "at_sign_userinfo", "suspicious_tld", "punycode", "mixed_scripts"}
    if was_short_link:
        return True
    if has_message:
        return True
    if url_score >= 20:
        return True
    return any(k in strong_keys for k in url_reason_keys)


def _vt_url_id(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8")
    return encoded.strip("=")


def query_virustotal(url: str, api_key: str) -> tuple[int, list[str], str]:
    """
    Returns: (score_delta, reason_keys, intel_note_key)
    """
    headers = {"x-apikey": api_key}
    reason_keys: list[str] = []
    intel_note_key = "intel_configured"

    try:
        url_id = _vt_url_id(url)
        report_resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=EXTERNAL_INTEL_TIMEOUT_SEC
        )

        if report_resp.status_code == 404:
            submit_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=EXTERNAL_INTEL_TIMEOUT_SEC
            )
            if submit_resp.ok:
                # Retry once quickly to reduce "pending" mismatch for short-link vs final-link checks.
                try:
                    time.sleep(0.35)
                    report_resp = requests.get(
                        f"https://www.virustotal.com/api/v3/urls/{url_id}",
                        headers=headers,
                        timeout=EXTERNAL_INTEL_TIMEOUT_SEC
                    )
                except Exception:
                    return 0, ["vt_pending"], intel_note_key
                if not report_resp.ok:
                    return 0, ["vt_pending"], intel_note_key
            else:
                return 0, [], "vt_unavailable"

        if not report_resp.ok:
            return 0, [], "vt_unavailable"

        stats = (
            report_resp.json()
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))

        if malicious >= 2:
            return min(60, 35 + malicious), ["vt_malicious"], intel_note_key
        if malicious == 1:
            return 12, ["vt_single_vendor_flag"], intel_note_key
        if suspicious > 0:
            return min(40, 20 + suspicious * 2), ["vt_suspicious"], intel_note_key
        return 0, ["vt_clean"], intel_note_key
    except Exception:
        return 0, [], "vt_unavailable"


def query_urlscan(url: str, api_key: str) -> tuple[int, list[str], str]:
    """
    Returns: (score_delta, reason_keys, intel_note_key)
    """
    headers = {"API-Key": api_key, "Content-Type": "application/json"}

    try:
        search_resp = requests.get(
            "https://urlscan.io/api/v1/search/",
            headers=headers,
            params={"q": f'page.url:"{url}"', "size": 1},
            timeout=EXTERNAL_INTEL_TIMEOUT_SEC
        )
        if search_resp.ok:
            results = search_resp.json().get("results", [])
            if results:
                overall = results[0].get("verdicts", {}).get("overall", {})
                malicious = bool(overall.get("malicious"))
                score = int(overall.get("score", 0) or 0)
                categories = overall.get("categories", []) or []
                if malicious:
                    return min(60, 35 + max(0, score)), ["urlscan_malicious"], "intel_configured"
                if score > 0 or len(categories) > 0:
                    return min(40, 15 + max(0, score)), ["urlscan_suspicious"], "intel_configured"
                return 0, ["urlscan_clean"], "intel_configured"

        submit_resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={"url": url, "visibility": "public"},
            timeout=EXTERNAL_INTEL_TIMEOUT_SEC
        )
        if submit_resp.ok:
            return 0, ["urlscan_pending"], "intel_configured"
        return 0, [], "urlscan_unavailable"
    except Exception:
        return 0, [], "urlscan_unavailable"


def query_google_safe_browsing(url: str, api_key: str) -> tuple[int, list[str], str]:
    """
    Returns: (score_delta, reason_keys, intel_note_key)
    """
    global GSB_DISABLED_UNTIL_TS
    now = time.time()
    if now < GSB_DISABLED_UNTIL_TS:
        return 0, ["gsb_unavailable"], "gsb_unavailable"

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={api_key}"
    )
    cache_key = canonicalize_url_for_external_intel(url)
    with LIVE_LOCK:
        cached = GSB_RESULT_CACHE.get(cache_key)
        if cached and (now - float(cached.get("ts", 0)) <= GSB_CACHE_TTL_SEC):
            return int(cached.get("score", 0)), list(cached.get("reason_keys", [])), str(cached.get("note", "intel_configured"))
    payload = {
        "client": {"clientId": "linkcheck", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=EXTERNAL_INTEL_TIMEOUT_SEC)
        if not resp.ok:
            GSB_DISABLED_UNTIL_TS = time.time() + GSB_COOLDOWN_SEC
            return 0, ["gsb_unavailable"], "gsb_unavailable"
        body = resp.json() if resp.text else {}
        matches = body.get("matches", []) or []
        if not matches:
            result = (0, ["gsb_clean"], "intel_configured")
            with LIVE_LOCK:
                GSB_RESULT_CACHE[cache_key] = {"ts": time.time(), "score": result[0], "reason_keys": result[1], "note": result[2]}
            return result
        threat_types = {str(m.get("threatType", "")).upper() for m in matches}
        if "MALWARE" in threat_types or "SOCIAL_ENGINEERING" in threat_types:
            result = (50, ["gsb_malicious"], "intel_configured")
            with LIVE_LOCK:
                GSB_RESULT_CACHE[cache_key] = {"ts": time.time(), "score": result[0], "reason_keys": result[1], "note": result[2]}
            return result
        result = (20, ["gsb_suspicious"], "intel_configured")
        with LIVE_LOCK:
            GSB_RESULT_CACHE[cache_key] = {"ts": time.time(), "score": result[0], "reason_keys": result[1], "note": result[2]}
        return result
    except Exception:
        GSB_DISABLED_UNTIL_TS = time.time() + GSB_COOLDOWN_SEC
        return 0, ["gsb_unavailable"], "gsb_unavailable"


def dns_resolves(hostname: str) -> bool:
    try:
        socket.getaddrinfo(hostname, None)
        return True
    except Exception:
        return False


def tls_certificate_valid(hostname: str) -> bool:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True
    except Exception:
        return False


def page_http_status(url: str) -> int | None:
    """
    Check whether the specific page URL responds.
    Returns HTTP status code when available, otherwise None.
    """
    if not url:
        return None
    normalized = normalize_url_for_checks(url)
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }
    deadline = time.monotonic() + 4.5

    try:
        remaining = max(0.8, deadline - time.monotonic())
        head_resp = requests.head(
            normalized,
            allow_redirects=True,
            headers=headers,
            timeout=min(2.5, remaining)
        )
        if head_resp.status_code and head_resp.status_code != 405:
            return int(head_resp.status_code)
    except Exception:
        pass

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None

    try:
        get_resp = requests.get(
            normalized,
            allow_redirects=True,
            headers=headers,
            timeout=max(1.0, min(3.0, remaining)),
            stream=True
        )
        return int(get_resp.status_code)
    except Exception:
        return None


def _strip_html_to_text(html: str) -> str:
    if not html:
        return ""
    without_scripts = re.sub(r"(?is)<(script|style|noscript).*?>.*?</\1>", " ", html)
    no_tags = HTML_TAG_RE.sub(" ", without_scripts)
    text = re.sub(r"\s+", " ", no_tags).strip()
    return unquote(text)


def _fetch_page_text_for_analysis(url: str) -> str:
    """Fetch a small HTML snapshot for language/intent heuristics."""
    normalized = normalize_url_for_checks(url)
    if not normalized or not _safe_url_for_server_redirect(normalized):
        return ""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }
    try:
        with requests.Session() as session:
            current = normalized
            resp = None
            for _ in range(4):
                resp = _redirect_session_get(session, current, headers=headers, timeout=ANALYSIS_FETCH_TIMEOUT_SEC)
                if resp.status_code not in (301, 302, 303, 307, 308):
                    break
                loc = resp.headers.get("Location")
                if not loc:
                    break
                next_url = urljoin(current, loc.strip())
                if not _safe_url_for_server_redirect(next_url):
                    return ""
                current = next_url
            if resp is None:
                return ""
            ct = (resp.headers.get("Content-Type") or "").lower()
            if "text/html" not in ct:
                return ""
            return _strip_html_to_text((resp.text or "")[:120000])
    except Exception:
        return ""


def _fetch_html_for_analysis(url: str) -> tuple[str, str, int | None]:
    """Return (html, final_url, status_code) after a few safe redirects."""
    normalized = normalize_url_for_checks(url)
    if not normalized or not _safe_url_for_server_redirect(normalized):
        return "", normalized, None
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }
    try:
        with requests.Session() as session:
            current = normalized
            resp = None
            for _ in range(5):
                resp = _redirect_session_get(session, current, headers=headers, timeout=ANALYSIS_FETCH_TIMEOUT_SEC)
                if resp.status_code not in (301, 302, 303, 307, 308):
                    break
                loc = resp.headers.get("Location")
                if not loc:
                    break
                next_url = urljoin(current, loc.strip())
                if not _safe_url_for_server_redirect(next_url):
                    return "", current, None
                current = next_url
            if resp is None:
                return "", current, None
            status_code = int(resp.status_code)
            # Do not infer "single-page" from forbidden/challenge/error pages.
            if status_code >= 400:
                return "", current, status_code
            ct = (resp.headers.get("Content-Type") or "").lower()
            if "text/html" not in ct:
                return "", current, status_code
            return (resp.text or "")[:200000], current, status_code
    except Exception:
        return "", normalized, None


def analyze_site_structure_signal(url: str) -> tuple[int, list[str], dict]:
    """
    Structural signal: very few internal pages can indicate throwaway phishing sites.
    Not a proof by itself, but a strong supporting signal.
    """
    html, final_url, status_code = _fetch_html_for_analysis(url)
    if not html:
        return 0, [], {"structure_fetch_status": status_code}

    p = urlparse(final_url)
    host = (p.hostname or "").lower()
    if not host:
        return 0, [], {}

    internal_paths: set[str] = set()
    for href in HREF_RE.findall(html):
        candidate = urljoin(final_url, href.strip())
        cp = urlparse(candidate)
        if cp.scheme not in ("http", "https"):
            continue
        if (cp.hostname or "").lower() != host:
            continue
        path = (cp.path or "").strip()
        if not path or path == "/":
            continue
        internal_paths.add(path.rstrip("/"))
        if len(internal_paths) >= 3:
            break

    lowered = html.lower()
    nav_terms = (
        "about", "contact", "privacy", "terms", "support", "faq",
        "אודות", "צור קשר", "מדיניות פרטיות", "תנאי שימוש", "שירות לקוחות",
    )
    nav_hits = count_term_hits(lowered, nav_terms)

    internal_count = len(internal_paths)
    context = {"internal_pages_found": internal_count, "structure_fetch_status": status_code}
    if internal_count <= 1 and nav_hits == 0:
        return 30, ["single_page_site"], context
    return 0, [], context


def _fetch_page_text_with_playwright(url: str) -> str:
    """
    Render JS-heavy pages in a headless browser and extract visible text.
    Requires `playwright` package and installed Chromium runtime.
    """
    enabled = os.getenv("ENABLE_PLAYWRIGHT_RENDER", "1").lower() not in {"0", "false", "no", "off"}
    if not enabled:
        return ""
    normalized = normalize_url_for_checks(url)
    if not normalized or not _safe_url_for_server_redirect(normalized):
        return ""
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return ""

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_default_navigation_timeout(8000)
            page.set_default_timeout(6000)
            page.goto(normalized, wait_until="domcontentloaded")
            try:
                page.wait_for_load_state("networkidle", timeout=2500)
            except Exception:
                pass
            html = page.content() or ""
            text = page.locator("body").inner_text(timeout=1500) or ""
            browser.close()
            combined = f"{text}\n{_strip_html_to_text(html)}".strip()
            return combined[:120000]
    except Exception:
        return ""


def _detect_page_audience(text: str) -> str:
    lower = (text or "").lower()
    heb_count = len(HEBREW_CHAR_RE.findall(lower))
    arabic_count = len(re.findall(r"[\u0600-\u06FF]", lower))
    cyrillic_count = len(re.findall(r"[\u0400-\u04FF]", lower))
    latin_count = len(re.findall(r"[a-z]", lower))
    max_count = max(heb_count, arabic_count, cyrillic_count, latin_count)
    if max_count < 20:
        return ""
    if max_count == heb_count:
        return "he"
    if max_count == arabic_count:
        return "ar"
    if max_count == cyrillic_count:
        return "ru"
    if max_count == latin_count:
        return "en"
    return ""


def _country_from_tld(hostname: str) -> tuple[str, str]:
    """
    Return (tld, country_code) based on domain suffix.
    For country-code TLDs we use ISO-like 2-letter code (uk -> GB).
    """
    host = (hostname or "").strip().lower()
    if not host:
        return "", ""
    ext = tldextract.extract(host)
    suffix = (ext.suffix or "").lower()
    if not suffix:
        return "", ""
    tld = suffix.split(".")[-1]
    if not tld:
        return "", ""
    if tld == "uk":
        return tld, "GB"
    if len(tld) == 2 and tld.isalpha():
        return tld, tld.upper()
    return tld, ""


def _has_potentially_misleading_subdomain(hostname: str, registrable_domain: str) -> bool:
    """
    Heuristic for deceptive presentation:
    subdomain exists and first visible label looks like a branded/service identity
    (not generic infra labels such as www/cdn/api).
    """
    host = (hostname or "").lower().strip(".")
    reg = (registrable_domain or "").lower().strip(".")
    if not host or not reg or host == reg:
        return False
    if not host.endswith(f".{reg}"):
        return False
    sub = host[: -(len(reg) + 1)]
    if not sub:
        return False
    first = sub.split(".", 1)[0]
    if not first or first in GENERIC_SAFE_SUBDOMAIN_LABELS:
        return False
    letters_only = re.sub(r"[^a-z0-9]", "", first)
    if len(letters_only) < 6:
        return False
    return True


def analyze_page_language_signals(url: str) -> tuple[int, list[str], dict]:
    """
    Heuristic page-content analysis:
    - Hebrew phishing-style wording
    - Hebrew-content vs foreign-infrastructure mismatch
    """
    text = _fetch_page_text_for_analysis(url)
    # Fallback for JS-rendered pages where plain HTTP fetch returns little/no useful text.
    if len(text) < 80:
        rendered_text = _fetch_page_text_with_playwright(url)
        if len(rendered_text) > len(text):
            text = rendered_text
    if not text:
        return 0, [], {}

    parsed = urlparse(url if "://" in url else f"https://{url}")
    hostname = (parsed.hostname or "").lower()
    tld, tld_country_code = _country_from_tld(hostname)

    heb_chars = len(HEBREW_CHAR_RE.findall(text))
    ascii_letters = len(re.findall(r"[a-zA-Z]", text))
    dominant_hebrew = heb_chars >= 25 and heb_chars >= (ascii_letters * 1.3)
    lower_text = text.lower()

    score = 0
    reasons: list[str] = []
    context: dict = {}
    audience = _detect_page_audience(text)
    context["page_audience"] = audience
    if tld:
        context["domain_tld"] = tld
    if tld_country_code:
        context["tld_country_code"] = tld_country_code

    if dominant_hebrew:
        page_phishing_hits = count_term_hits(lower_text, HEBREW_PHISHING_PAGE_TERMS)
        if page_phishing_hits >= 2:
            score += min(26, 14 + page_phishing_hits * 4)
            reasons.append("hebrew_phishing_page_signals")

        if tld in FOREIGN_TLDS_FOR_HEBREW_RISK:
            score += 25
            reasons.append("hebrew_content_foreign_infra_mismatch")

    return min(45, score), reasons, context


@lru_cache(maxsize=2048)
def domain_age_days(hostname: str) -> int | None:
    try:
        def _lookup() -> object:
            # python-whois can print low-level socket timeout messages to stdout/stderr.
            # Capture those writes so server logs stay clean.
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return whois.whois(hostname)

        fut = WHOIS_EXECUTOR.submit(_lookup)
        data = fut.result(timeout=WHOIS_TIMEOUT_SEC)
        created = data.creation_date
        if isinstance(created, list):
            created = created[0] if created else None
        if not created:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return max(0, (now - created).days)
    except FuturesTimeoutError:
        return None
    except Exception:
        return None


def classify_risk(score: int) -> str:
    if score <= 20:
        return "Low"
    if score <= 60:
        return "Medium"
    return "High"


def build_explanation(language: str, risk_level: str, reason_keys: list[str], context: dict) -> str:
    if not reason_keys:
        return t(language, "safe_now")
    if "lookalike_brand" in reason_keys:
        target = context.get("lookalike_target", "")
        seen = context.get("lookalike_seen", "")
        if target and seen:
            return t(language, "explain_lookalike_target", target=target, seen=seen)
        return t(language, "explain_lookalike")
    if risk_level == "High":
        return t(language, "explain_high")
    if risk_level == "Medium":
        return t(language, "explain_medium")
    return t(language, "explain_not_high")


def _summarize_url_risk(url: str) -> tuple[int, str, list[str]]:
    """
    Lightweight risk summary for a standalone URL.
    Used for side-by-side domain-vs-link visibility in UI.
    """
    if not url:
        return 0, "Low", []
    local_score, local_keys, _ = analyze_url(url)
    total_score = local_score
    reason_keys = list(local_keys)
    intel_url = canonicalize_url_for_external_intel(url)

    if os.getenv("VIRUSTOTAL_API_KEY"):
        s, k, _ = query_virustotal(intel_url or url, os.getenv("VIRUSTOTAL_API_KEY", ""))
        total_score += s
        reason_keys.extend(k)
    if os.getenv("URLSCAN_API_KEY"):
        s, k, _ = query_urlscan(intel_url or url, os.getenv("URLSCAN_API_KEY", ""))
        total_score += s
        reason_keys.extend(k)
    if os.getenv("GOOGLE_SAFE_BROWSING_API_KEY"):
        s, k, _ = query_google_safe_browsing(intel_url or url, os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", ""))
        total_score += s
        reason_keys.extend(k)

    total_score = min(100, total_score)
    reason_keys = list(dict.fromkeys(reason_keys))
    risk = classify_risk(total_score)
    if any(k in reason_keys for k in {"vt_malicious", "gsb_malicious", "urlscan_malicious", "brand_mismatch"}):
        risk = "High"
        total_score = max(total_score, 85)
    return total_score, risk, reason_keys


def _severity_rank(level: str) -> int:
    return {"Low": 0, "Medium": 1, "High": 2}.get(level, 0)


def _risk_to_rank(level: str) -> int:
    return _severity_rank(level)


def _escalate_level(current: str, candidate: str) -> str:
    return current if _severity_rank(current) >= _severity_rank(candidate) else candidate


def _risk_from_score(score: int) -> str:
    if score <= 20:
        return "Low"
    if score <= 60:
        return "Medium"
    return "High"


def _steps_payload(stage: int, final: bool) -> list[dict]:
    return [
        {"key": "stage_1", "label": "URL analysis", "status": "done" if stage >= 1 else "pending"},
        {"key": "stage_2", "label": "Redirect check", "status": "done" if stage >= 2 else "pending"},
        {
            "key": "stage_3",
            "label": "External checks",
            "status": "done" if final or stage >= 3 else ("in_progress" if stage == 2 else "pending"),
        },
    ]


def _stage_progress(stage: int, final: bool) -> int:
    if final:
        return 100
    return {1: 33, 2: 66, 3: 100}.get(stage, 0)


def _normalize_live_result_consistency(result: dict | None) -> dict | None:
    """
    Guard against stale cached payloads where top risk_level no longer matches
    finalized link/domain verdict objects after logic updates.
    """
    if not isinstance(result, dict):
        return result
    normalized = dict(result)
    top_level = str(normalized.get("risk_level", "Low") or "Low")
    link_verdict = normalized.get("link_verdict") or {}
    link_level = str(link_verdict.get("risk_level", "") or "")
    allowed = {"Low", "Medium", "High"}
    if top_level in allowed and link_level in allowed and top_level != link_level:
        normalized["risk_level"] = link_level
        link_score = link_verdict.get("score")
        if isinstance(link_score, (int, float)):
            normalized["score"] = int(link_score)
        normalized["is_green_safe"] = link_level == "Low"
    return normalized


def _is_complete_live_result(result: dict | None) -> bool:
    """Only cache authoritative full-analysis payloads, not stage snapshots."""
    if not isinstance(result, dict):
        return False
    green_checks = result.get("green_checks")
    return (
        isinstance(green_checks, list)
        and len(green_checks) > 0
        and isinstance(result.get("link_verdict"), dict)
    )


def _cache_get(url_key: str) -> dict | None:
    now = time.time()
    with LIVE_LOCK:
        payload = LIVE_ANALYSIS_CACHE.get(url_key)
        if not payload:
            return None
        if now - float(payload.get("ts", 0)) > LIVE_CACHE_TTL_SEC:
            LIVE_ANALYSIS_CACHE.pop(url_key, None)
            return None
        result = _normalize_live_result_consistency(payload.get("result"))
        if not _is_complete_live_result(result):
            LIVE_ANALYSIS_CACHE.pop(url_key, None)
            return None
        return result


def _cache_set(url_key: str, result: dict) -> None:
    normalized = _normalize_live_result_consistency(result) or result
    if not _is_complete_live_result(normalized):
        return
    with LIVE_LOCK:
        LIVE_ANALYSIS_CACHE[url_key] = {
            "ts": time.time(),
            "result": normalized,
        }


def _live_cache_key(submitted_url: str, message: str, language: str) -> str:
    """
    Cache key for live analysis.
    Includes URL + normalized message + language to avoid returning stale text/context
    from a previous scan of the same URL.
    """
    normalized_url = normalize_url_for_checks(submitted_url) or ""
    normalized_message = " ".join((message or "").split())
    blob = f"{LIVE_CACHE_SCHEMA_VERSION}\n{language}\n{normalized_url}\n{normalized_message}"
    digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    return f"v{LIVE_CACHE_SCHEMA_VERSION}:{normalized_url}::{digest[:20]}"


def _run_full_analysis_internal(payload: dict) -> dict:
    """Reuse existing /analyze logic as final-stage engine without changing current behavior."""
    try:
        with app.test_client() as client:
            resp = client.post("/analyze", json=payload)
            if resp.is_json:
                body = resp.get_json(silent=True) or {}
                if isinstance(body, dict):
                    return body
    except Exception:
        pass
    return {"score": 0, "risk_level": "Low", "is_green_safe": False, "reasons": [], "reason_keys": []}


def _build_stage1_snapshot(submitted_url: str, language: str) -> tuple[str, list[str], dict]:
    url_score, url_reasons, ctx = analyze_url(submitted_url)
    parsed = urlparse(submitted_url if "://" in submitted_url else f"https://{submitted_url}")
    hostname = (parsed.hostname or "").lower()
    tld, tld_country_code = _country_from_tld(hostname)
    if tld and not ctx.get("domain_tld"):
        ctx["domain_tld"] = tld
    if tld_country_code and not ctx.get("tld_country_code"):
        ctx["tld_country_code"] = tld_country_code
    tls_ok = tls_certificate_valid(hostname) if hostname else False
    if hostname and not tls_ok and any(k in url_reasons for k in ("brand_mismatch", "suspicious_tld", "lookalike_brand")):
        url_score = max(url_score, 85)
    risk = _risk_from_score(url_score)
    reasons = (
        [_localized_reason_line(language, key, ctx) for key in url_reasons]
        if url_reasons
        else [t(language, "safe_now")]
    )
    snapshot = {
        "score": url_score,
        "risk_level": risk,
        "is_green_safe": False,
        "submitted_url": submitted_url,
        "analyzed_url": submitted_url,
        "redirect_chain": [submitted_url] if submitted_url else [],
        "reason_keys": url_reasons,
        "reasons": reasons,
    }
    for detail_key in _SNAPSHOT_URL_CONTEXT_KEYS:
        val = ctx.get(detail_key)
        if val:
            snapshot[detail_key] = val
    return risk, url_reasons, snapshot


def _run_live_pipeline(job_id: str, payload: dict) -> None:
    language = "he" if (payload.get("language", "") or "").lower() == "he" else "en"
    raw_url = (payload.get("url", "") or "").strip()
    message = (payload.get("message", "") or "").strip()
    submitted_url = normalize_url_for_checks(raw_url or extract_first_url(message))
    cache_key = _live_cache_key(submitted_url, message, language)

    if not submitted_url:
        with LIVE_LOCK:
            job = LIVE_ANALYSIS_JOBS.get(job_id)
            if not job:
                return
            job["final"] = True
            job["stage"] = 3
            job["progress"] = 100
            job["status_text"] = t(language, "live_no_url")
        return

    current_level, stage1_reasons, stage1_snapshot = _build_stage1_snapshot(submitted_url, language)
    strong_stage1 = {"brand_mismatch", "lookalike_brand", "at_sign_userinfo"}
    early_red = any(k in strong_stage1 for k in stage1_reasons)

    with LIVE_LOCK:
        job = LIVE_ANALYSIS_JOBS.get(job_id)
        if not job:
            return
        job["stage"] = 1
        job["risk_level"] = current_level
        job["progress"] = _stage_progress(1, False)
        job["steps"] = _steps_payload(1, False)
        job["status_text"] = t(language, "live_progress")
        job["result"] = stage1_snapshot

    if early_red:
        with LIVE_LOCK:
            job = LIVE_ANALYSIS_JOBS.get(job_id)
            if not job:
                return
            job["final"] = True
            job["stage"] = 3
            job["progress"] = 100
            job["risk_level"] = "High"
            job["steps"] = _steps_payload(3, True)
            stage1_snapshot["risk_level"] = "High"
            job["result"] = stage1_snapshot
            job["status_text"] = t(language, "live_high_risk_early")
        _cache_set(cache_key, stage1_snapshot)
        return

    # Stage 2: redirect/domain consistency
    expanded_url, short_keys, redirect_chain = expand_short_url(submitted_url)
    stage2_level = current_level
    if "short_link_unresolved" in short_keys:
        stage2_level = _escalate_level(stage2_level, "Medium")
    with LIVE_LOCK:
        job = LIVE_ANALYSIS_JOBS.get(job_id)
        if not job:
            return
        job["stage"] = 2
        job["risk_level"] = stage2_level
        job["progress"] = _stage_progress(2, False)
        job["steps"] = _steps_payload(2, False)
        job["status_text"] = t(language, "live_waiting_external")
        # Keep partial data visible while async intel runs.
        partial = dict(stage1_snapshot)
        partial["risk_level"] = stage2_level
        partial["analyzed_url"] = expanded_url or submitted_url
        partial["redirect_chain"] = redirect_chain or [submitted_url]
        merged_keys = list(dict.fromkeys((partial.get("reason_keys") or []) + short_keys))
        partial["reason_keys"] = merged_keys
        partial["reasons"] = (
            [_localized_reason_line(language, k, partial) for k in merged_keys]
            if merged_keys
            else [t(language, "safe_now")]
        )
        job["result"] = partial

    # Stage 3: full existing analysis with external intel (VT/GSB/URLScan)
    # Keep raw_url here: when the user pasted a message with multiple links, /analyze
    # must see the original empty URL field and choose the highest-risk link.
    full_payload = {"url": raw_url, "message": message, "language": language, "_skip_scan_log": True}
    final_result = _run_full_analysis_internal(full_payload)
    transient_intel_keys = {"vt_pending", "urlscan_pending", "gsb_unavailable"}

    # When low-risk result still relies on pending/unavailable external intel,
    # retry briefly before finalizing to reduce "first scan green, second scan red" behavior.
    for attempt in range(LIVE_LOW_STABILIZE_RETRIES):
        result_level = str(final_result.get("risk_level", "Low"))
        result_keys = set(final_result.get("reason_keys", []) or [])
        if result_level != "Low" or not (result_keys & transient_intel_keys):
            break
        with LIVE_LOCK:
            job = LIVE_ANALYSIS_JOBS.get(job_id)
            if not job:
                return
            job["stage"] = 3
            job["steps"] = _steps_payload(3, False)
            job["status_text"] = t(
                language,
                "live_final_verification",
                current=attempt + 1,
                total=LIVE_LOW_STABILIZE_RETRIES,
            )
        if LIVE_LOW_STABILIZE_DELAY_SEC > 0:
            time.sleep(LIVE_LOW_STABILIZE_DELAY_SEC)
        refreshed = _run_full_analysis_internal(full_payload)
        previous_level = str(final_result.get("risk_level", "Low"))
        refreshed_level = str(refreshed.get("risk_level", "Low"))
        final_result = refreshed
        # Keep monotonic severity during stabilization retries.
        if _risk_to_rank(refreshed_level) < _risk_to_rank(previous_level):
            final_result["risk_level"] = previous_level

    # Full /analyze output is authoritative for cached JSON. Do not merge a higher
    # stage-2 headline risk into risk_level without updating link_verdict/domain_verdict —
    # that produced contradictory UI (e.g. High banner with both split rows green).
    candidate = str(final_result.get("risk_level", "Low"))
    final_level = candidate
    final_result["risk_level"] = final_level
    final_result["live_monotonic"] = True

    with LIVE_LOCK:
        job = LIVE_ANALYSIS_JOBS.get(job_id)
        if not job:
            return
        job["final"] = True
        job["stage"] = 3
        job["risk_level"] = final_level
        job["progress"] = 100
        job["steps"] = _steps_payload(3, True)
        job["status_text"] = t(language, "live_completed")
        job["result"] = final_result

    _cache_set(cache_key, final_result)
    if not payload.get("_skip_scan_log"):
        try:
            append_scan_event_to_file(
                url_field=raw_url,
                message_field=message,
                language=language,
                user_agent=str(payload.get("_scan_user_agent") or "")[:2000],
                client_ip=str(payload.get("_scan_client_ip") or "")[:200],
                result=final_result,
                source="live",
            )
        except Exception:
            pass


@app.post("/analyze")
@limiter.limit("20 per minute")
def analyze():
    payload = request.get_json(silent=True) or {}
    language = "he" if (payload.get("language", "") or "").lower() == "he" else "en"
    raw_url = (payload.get("url", "") or "").strip()
    message = (payload.get("message", "") or "").strip()

    if len(raw_url) > MAX_ANALYZE_URL_LEN or len(message) > MAX_ANALYZE_MESSAGE_LEN:
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "payload_too_large",
                    "score": 0,
                    "risk_level": "Low",
                    "reasons": [],
                }
            ),
            413,
        )

    # If user provided full message, extract URL automatically.
    message_urls = extract_urls(message)
    if not raw_url and len(message_urls) > 1 and not payload.get("_single_url_only"):
        analyzed_links: list[dict] = []
        for idx, link in enumerate(message_urls[:MAX_MESSAGE_URLS_TO_ANALYZE]):
            with app.test_client() as client:
                resp = client.post(
                    "/analyze",
                    json={
                        "url": link,
                        "message": message,
                        "language": language,
                        "_single_url_only": True,
                        "_skip_ai_model_intent": True,
                        "_skip_ai_summary": True,
                    },
                )
            if not resp.is_json:
                continue
            body = resp.get_json(silent=True) or {}
            if not isinstance(body, dict) or resp.status_code >= 400:
                continue
            analyzed_links.append(
                {
                    "index": idx,
                    "submitted_url": link,
                    "analyzed_url": body.get("analyzed_url", link),
                    "risk_level": body.get("risk_level", "Low"),
                    "score": int(body.get("score", 0) or 0),
                    "reason_keys": body.get("reason_keys", []),
                    "result": body,
                }
            )

        if analyzed_links:
            selected = max(
                analyzed_links,
                key=lambda item: (_severity_rank(str(item.get("risk_level", "Low"))), int(item.get("score", 0) or 0)),
            )
            result = dict(selected["result"])
            reason_keys = list(result.get("reason_keys", []) or [])
            if "multiple_links_detected" not in reason_keys:
                reason_keys.insert(0, "multiple_links_detected")
            result["reason_keys"] = reason_keys
            result["reasons"] = [_localized_reason_line(language, key, result) for key in reason_keys]
            result["message_link_count"] = len(message_urls)
            result["message_links_analyzed_count"] = len(analyzed_links)
            result["message_links"] = [
                {k: v for k, v in item.items() if k != "result"}
                for item in analyzed_links
            ]
            result["selected_message_url"] = selected.get("submitted_url", "")
            result["selected_message_url_index"] = selected.get("index", 0)
            result["ai_model_summary"] = build_ai_model_summary(
                message=message,
                submitted_url=result.get("submitted_url", "") or "",
                analyzed_url=result.get("analyzed_url", "") or "",
                language=language,
                risk_level=result.get("risk_level", "Low") or "Low",
                reason_keys=list(dict.fromkeys(reason_keys)),
                domain_verdict=result.get("domain_verdict") or {},
                tld_country_code=result.get("tld_country_code", "") or "",
            )
            if not payload.get("_skip_scan_log"):
                append_scan_event_to_file(
                    url_field=raw_url,
                    message_field=message,
                    language=language,
                    user_agent=(request.headers.get("User-Agent") or "")[:2000],
                    client_ip=(request.headers.get("X-Forwarded-For") or request.remote_addr or "")[:200],
                    result=result,
                    source="analyze",
                )
            return jsonify(result)

    extracted_url = extract_first_url(message)
    submitted_url = raw_url or extracted_url
    normalized_submitted = normalize_url_for_checks(submitted_url)
    submitted_is_http = normalized_submitted.lower().startswith("http://") if normalized_submitted else False
    submitted_is_https = normalized_submitted.lower().startswith("https://") if normalized_submitted else False
    expanded_url, short_link_reason_keys, redirect_chain = expand_short_url(normalized_submitted)
    expanded_or_submitted = expanded_url or normalized_submitted
    decoded_url = decode_url_for_analysis(expanded_or_submitted)
    url_to_check = decoded_url or expanded_or_submitted
    final_is_https = url_to_check.lower().startswith("https://") if url_to_check else False
    final_is_http = url_to_check.lower().startswith("http://") if url_to_check else False
    original_host = (urlparse(normalized_submitted).hostname or "").lower() if normalized_submitted else ""
    # Show redirect / short-link trust row when we followed hops OR domain is a known shortener list.
    was_short_link = bool(normalized_submitted) and (
        len(redirect_chain) > 1
        or (
            original_host
            and any(original_host == d or original_host.endswith(f".{d}") for d in SHORTENER_DOMAINS)
        )
    )
    short_link_resolved = "short_link_expanded" in short_link_reason_keys

    if not url_to_check and not message:
        return jsonify(
            {
                "score": 0,
                "risk_level": "Low",
                "reasons": [t(language, "need_input")]
            }
        ), 400

    url_score, url_reason_keys, url_context = analyze_url(url_to_check)
    url_reason_keys.extend(short_link_reason_keys)
    parsed_for_trust = urlparse(url_to_check if "://" in url_to_check else f"https://{url_to_check}")
    hostname_for_trust = (parsed_for_trust.hostname or "").lower()
    registrable_for_trust = get_registrable_domain(hostname_for_trust) if hostname_for_trust else ""
    is_trusted_root_domain = registrable_for_trust in TRUSTED_ROOT_DOMAINS

    # Trusted root domains reduce risk when only weak, lexical hints were triggered.
    has_strong_local = any(key in STRONG_LOCAL_WARNING_KEYS for key in url_reason_keys)
    if is_trusted_root_domain and not has_strong_local:
        original_len = len(url_reason_keys)
        url_reason_keys = [
            key for key in url_reason_keys
            if key not in WEAK_LOCAL_WARNING_KEYS
        ]
        removed_weak_count = original_len - len(url_reason_keys)
        if removed_weak_count > 0:
            url_score = max(0, url_score - (removed_weak_count * 15))

    text_score, text_reason_keys = analyze_message_text(message)
    intent_score, intent_reason_keys = analyze_message_intent(message)
    if payload.get("_skip_ai_model_intent"):
        model_intent_score, model_intent_reason_keys = 0, []
    else:
        model_intent_score, model_intent_reason_keys = analyze_message_intent_with_model(message, url_to_check)
    page_score, page_reason_keys, page_context = analyze_page_language_signals(url_to_check)
    structure_score, structure_reason_keys, structure_context = analyze_site_structure_signal(url_to_check)
    url_reason_keys.extend(page_reason_keys)
    url_reason_keys.extend(structure_reason_keys)
    if isinstance(page_context, dict):
        url_context.update(page_context)
    if isinstance(structure_context, dict):
        url_context.update(structure_context)
    intel_key, intel_sources = external_intel_status(url_to_check)
    intel_score = 0
    intel_reason_keys: list[str] = []

    def _query_external_intel(target_url: str) -> None:
        nonlocal intel_key, intel_score, intel_reason_keys
        intel_target_url = canonicalize_url_for_external_intel(target_url)
        if not intel_target_url:
            return
        if os.getenv("VIRUSTOTAL_API_KEY"):
            vt_score, vt_reason_keys, vt_note_key = query_virustotal(
                intel_target_url, os.getenv("VIRUSTOTAL_API_KEY", "")
            )
            intel_score += vt_score
            intel_reason_keys.extend(vt_reason_keys)
            intel_key = vt_note_key
        if os.getenv("URLSCAN_API_KEY"):
            us_score, us_reason_keys, us_note_key = query_urlscan(
                intel_target_url, os.getenv("URLSCAN_API_KEY", "")
            )
            intel_score += us_score
            intel_reason_keys.extend(us_reason_keys)
            intel_key = us_note_key
        if os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") and _should_query_google_safe_browsing(
            url_score=url_score,
            url_reason_keys=url_reason_keys,
            was_short_link=was_short_link,
            has_message=bool(message),
        ):
            gsb_score, gsb_reason_keys, gsb_note_key = query_google_safe_browsing(
                intel_target_url, os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
            )
            intel_score += gsb_score
            intel_reason_keys.extend(gsb_reason_keys)
            intel_key = gsb_note_key

    # If a short link resolves to a known trusted destination (e.g. whatsapp.com),
    # evaluate external intel by the final destination to avoid false-red from the
    # shortener reputation itself.
    submitted_intel_url = canonicalize_url_for_external_intel(normalized_submitted)
    final_intel_url = canonicalize_url_for_external_intel(url_to_check)
    submitted_host = _strip_leading_www((urlparse(normalized_submitted).hostname or "")) if normalized_submitted else ""
    final_host = _strip_leading_www((urlparse(url_to_check).hostname or "")) if url_to_check else ""
    final_registrable = get_registrable_domain(final_host) if final_host else ""
    trusted_shortlink_destination = (
        was_short_link
        and short_link_resolved
        and bool(final_intel_url)
        and final_registrable in TRUSTED_ROOT_DOMAINS
        and submitted_intel_url != final_intel_url
        and submitted_host != final_host
    )

    # Double-check short-link source and final destination to keep verdicts aligned.
    checked_targets: list[str] = []
    if trusted_shortlink_destination:
        checked_targets.append(url_to_check)
    else:
        if normalized_submitted:
            checked_targets.append(normalized_submitted)
    if url_to_check and final_intel_url != submitted_intel_url:
        checked_targets.append(url_to_check)

    # Preserve order and avoid duplicate external lookups.
    checked_targets = list(dict.fromkeys(checked_targets))
    for target_url in checked_targets:
        _query_external_intel(target_url)

    # Balance lexical "long URL" signal:
    # if it is the only local warning and external intel is clean/unavailable,
    # do not keep medium-risk just because of length.
    local_warning_keys = [k for k in url_reason_keys if k not in NON_WARNING_LOCAL_KEYS]
    only_long_url_local = local_warning_keys == ["long_url"]
    intel_has_bad_signal = any(
        k in intel_reason_keys
        for k in {"vt_malicious", "vt_suspicious", "urlscan_malicious", "urlscan_suspicious", "gsb_malicious", "gsb_suspicious"}
    )
    if only_long_url_local and not intel_has_bad_signal:
        url_reason_keys = [k for k in url_reason_keys if k != "long_url"]
        url_score = max(0, url_score - 10)

    # Message analysis always contributes at a baseline weight, even when URL heuristics look clean.
    # This keeps social-engineering text signals meaningful without over-amplifying false positives.
    url_has_warnings = len([key for key in url_reason_keys if key not in NON_WARNING_LOCAL_KEYS]) > 0
    if url_has_warnings:
        message_contrib = text_score + intent_score + model_intent_score
    else:
        message_contrib = min(25, int((text_score * 0.5) + (intent_score * 0.5) + (model_intent_score * 0.5)))

    total_score = min(
        100,
        url_score + page_score + structure_score + intel_score + message_contrib,
    )
    vt_malicious_hit = "vt_malicious" in intel_reason_keys
    brand_mismatch_hit = "brand_mismatch" in url_reason_keys
    if vt_malicious_hit:
        # Hard rule: if VirusTotal marks URL as malicious, force high severity.
        total_score = max(total_score, 85)
    if brand_mismatch_hit:
        # Hard rule: structural identity mismatch is a strong phishing indicator.
        total_score = max(total_score, 85)
    reason_keys = (
        url_reason_keys
        + text_reason_keys
        + intent_reason_keys
        + model_intent_reason_keys
        + intel_reason_keys
    )
    if submitted_is_http and final_is_https and short_link_resolved:
        reason_keys.append("short_http_to_https_caution")
    if submitted_is_https and final_is_http and short_link_resolved:
        reason_keys.append("short_https_to_http_downgrade")
        total_score = max(total_score, 45)

    # Favor final trusted destination over shortener reputation alone, while
    # still keeping user guidance about short-link uncertainty.
    shortlink_hard_risk_keys = {
        "brand_mismatch",
        "lookalike_brand",
        "at_sign_userinfo",
        "vt_malicious",
        "gsb_malicious",
        "urlscan_malicious",
        "short_https_to_http_downgrade",
    }
    shortlink_intel_bad = any(
        k in reason_keys for k in {"vt_malicious", "vt_suspicious", "urlscan_malicious", "urlscan_suspicious", "gsb_malicious", "gsb_suspicious"}
    )
    shortlink_message_warning = any(k in MESSAGE_WARNING_KEYS for k in reason_keys)
    if trusted_shortlink_destination and short_link_resolved:
        reason_keys.append("shortlink_use_original_recommended")
        if not any(k in reason_keys for k in shortlink_hard_risk_keys):
            if not shortlink_intel_bad and not shortlink_message_warning:
                total_score = min(total_score, 18)
            else:
                total_score = min(total_score, 35)

    parsed = urlparse(url_to_check if "://" in url_to_check else f"https://{url_to_check}")
    hostname = (parsed.hostname or "").lower()
    tld, tld_country_code = _country_from_tld(hostname)
    if tld and not url_context.get("domain_tld"):
        url_context["domain_tld"] = tld
    if tld_country_code and not url_context.get("tld_country_code"):
        url_context["tld_country_code"] = tld_country_code
    if language == "he" and tld_country_code and tld_country_code != "IL":
        if "tld_country_notice" not in reason_keys:
            reason_keys.append("tld_country_notice")
    registrable_domain = get_registrable_domain(hostname) if hostname else ""
    host_no_www = _strip_leading_www(hostname)
    has_subdomains = bool(host_no_www and registrable_domain and host_no_www != registrable_domain)
    potentially_misleading_subdomain = _has_potentially_misleading_subdomain(hostname, registrable_domain)
    social_engineering_hit = (
        "ai_social_engineering" in reason_keys
        or "ai_model_social_engineering" in reason_keys
    )
    if social_engineering_hit and potentially_misleading_subdomain:
        total_score = max(total_score, 85)
        if "ai_subdomain_impersonation_combo" not in reason_keys:
            reason_keys.append("ai_subdomain_impersonation_combo")
    # Performance guard: once a strong phishing hard-rule already fired, avoid slow
    # network trust checks that cannot change final risk classification.
    skip_expensive_trust_checks = brand_mismatch_hit or vt_malicious_hit

    if skip_expensive_trust_checks:
        dns_ok = False
        tls_ok = False
        page_status_code = None
        page_exists = False
        page_status = "na"
        age_days = None
    else:
        dns_ok = dns_resolves(hostname) if hostname else False
        tls_ok = tls_certificate_valid(hostname) if hostname else False
        page_status_code = page_http_status(url_to_check) if url_to_check else None
        page_exists = False
        page_status = "na"
        if page_status_code is not None:
            # Consider page reachable when it resolves to real content/redirect/auth challenge.
            page_exists = (
                (200 <= page_status_code < 400)
                or page_status_code in {401, 403}
            )
            page_status = "pass" if page_exists else "fail"
        age_days = domain_age_days(hostname) if hostname else None
    vt_configured = bool(os.getenv("VIRUSTOTAL_API_KEY"))
    urlscan_configured = bool(os.getenv("URLSCAN_API_KEY"))
    gsb_configured = bool(os.getenv("GOOGLE_SAFE_BROWSING_API_KEY"))
    vt_pending = "vt_pending" in intel_reason_keys
    urlscan_pending = "urlscan_pending" in intel_reason_keys
    vt_clean = (
        (not vt_configured)
        or ("vt_clean" in intel_reason_keys)
        or ("vt_single_vendor_flag" in intel_reason_keys)
    )
    vt_checked = vt_configured and not vt_pending
    urlscan_clean = not urlscan_configured or "urlscan_clean" in intel_reason_keys
    urlscan_checked = urlscan_configured and not urlscan_pending
    gsb_clean = "gsb_clean" in intel_reason_keys
    gsb_unavailable = "gsb_unavailable" in intel_reason_keys
    gsb_checked = gsb_configured and not gsb_unavailable
    url_only_warning_keys = [key for key in url_reason_keys if key not in NON_WARNING_LOCAL_KEYS]
    no_url_warnings = len(url_only_warning_keys) == 0
    domain_old_enough = age_days is not None and age_days >= 180

    age_status = "na"
    if age_days is not None:
        age_status = "pass" if age_days >= 180 else "fail"

    green_checks = [
        {"key": "no_local_warnings", "status": "pass" if no_url_warnings else "fail"},
        {
            "key": "no_message_warnings",
            "status": "pass" if not any(k in MESSAGE_WARNING_KEYS for k in reason_keys) else "fail",
        },
        {"key": "vt_clean", "status": ("pass" if vt_clean else "fail") if vt_checked else "na"},
        {"key": "urlscan_clean", "status": ("pass" if urlscan_clean else "fail") if urlscan_checked else "na"},
        {"key": "gsb_clean", "status": ("pass" if gsb_clean else "fail") if gsb_checked else "na"},
        {"key": "dns_resolves", "status": "pass" if dns_ok else "fail"},
        {"key": "tls_valid", "status": "pass" if tls_ok else "fail"},
        {"key": "page_available", "status": page_status, "value": page_status_code},
        {"key": "domain_age_180d", "status": age_status, "value": age_days},
    ]
    if was_short_link:
        green_checks.append(
            {"key": "short_link_resolved", "status": "pass" if short_link_resolved else "fail"}
        )

    # Core trust requirements must pass; unconfigured intel sources are skipped (neither pass nor block).
    vt_passes = (not vt_configured) or vt_pending or vt_clean
    urlscan_passes = (not urlscan_configured) or urlscan_pending or urlscan_clean
    gsb_passes = (not gsb_configured) or gsb_unavailable or gsb_clean
    message_passes = not any(k in MESSAGE_WARNING_KEYS for k in reason_keys)
    page_passes = (page_status_code is None) or page_exists
    core_pass = (
        no_url_warnings
        and message_passes
        and vt_passes
        and urlscan_passes
        and gsb_passes
        and dns_ok
        and tls_ok
        and page_passes
    )
    if was_short_link:
        core_pass = core_pass and short_link_resolved
    age_not_risky = age_days is None or age_days >= 30
    is_green_safe = core_pass and age_not_risky

    failed_green_checks = [item for item in green_checks if item["status"] == "fail"]
    if not is_green_safe:
        # Add weighted floor by number of failed trust checks.
        fail_count = len(failed_green_checks)
        if fail_count >= 3:
            total_score = max(total_score, 55)
        elif fail_count == 2:
            total_score = max(total_score, 40)
        elif fail_count == 1:
            total_score = max(total_score, 25)

        if "insufficient_trust_signals" not in reason_keys:
            reason_keys.append("insufficient_trust_signals")

    weak_only_keys = {
        "single_page_site",
        "vt_single_vendor_flag",
        "urlscan_pending",
        "insufficient_trust_signals",
        "short_link_expanded",
        "short_link_destination_blocked",
        "shortlink_use_original_recommended",
        "tld_country_notice",
        "gsb_unavailable",
        "vt_clean",
        "urlscan_clean",
        "gsb_clean",
    }
    hard_risk_keys = {
        "brand_mismatch",
        "lookalike_brand",
        "at_sign_userinfo",
        "vt_malicious",
        "gsb_malicious",
        "urlscan_malicious",
        "ai_subdomain_impersonation_combo",
    }
    force_low_for_weak_only = False
    effective_keys = {k for k in reason_keys if k not in {"insufficient_trust_signals"}}
    if effective_keys and effective_keys.issubset(weak_only_keys) and not any(k in reason_keys for k in hard_risk_keys):
        # Weak/ambiguous signals alone should not force medium-risk banners.
        total_score = min(total_score, 20)
        reason_keys = [k for k in reason_keys if k != "insufficient_trust_signals"]
        failed_green_checks = [item for item in failed_green_checks if item.get("key") != "no_local_warnings"]
        force_low_for_weak_only = True
        is_green_safe = True

    reasons = [_localized_reason_line(language, key, url_context) for key in reason_keys]
    intel_note = ""
    if intel_key == "intel_configured":
        intel_note = t(language, intel_key, sources=", ".join(intel_sources))
    elif intel_key:
        intel_note = t(language, intel_key)

    if not reasons:
        reasons = [t(language, "safe_now")]

    # Green is granted only when all required trust signals pass.
    if force_low_for_weak_only:
        risk_level = "Low"
    elif is_green_safe:
        risk_level = "Low"
    else:
        risk_level = "High" if total_score > 60 else "Medium"
    if vt_malicious_hit:
        risk_level = "High"
    if brand_mismatch_hit:
        risk_level = "High"
    if social_engineering_hit and potentially_misleading_subdomain:
        risk_level = "High"

    domain_verdict = {}
    if registrable_domain:
        domain_url = f"https://{registrable_domain}"
        domain_score, domain_risk_level, domain_reason_keys = _summarize_url_risk(domain_url)
        domain_verdict = {
            "url": domain_url,
            "risk_level": domain_risk_level,
            "score": domain_score,
            "is_safe": domain_risk_level == "Low",
            "reason_keys": domain_reason_keys,
        }
        if domain_risk_level == "High" and risk_level != "High":
            risk_level = "High"
            total_score = max(total_score, 70)
            if "domain_reputation_warning" not in reason_keys:
                reason_keys.append("domain_reputation_warning")
        elif domain_risk_level == "Medium" and risk_level == "Low":
            risk_level = "Medium"
            total_score = max(total_score, 40)
            if "domain_reputation_warning" not in reason_keys:
                reason_keys.append("domain_reputation_warning")
    reason_keys = list(dict.fromkeys(reason_keys))
    reasons = (
        [_localized_reason_line(language, key, url_context) for key in reason_keys]
        if reason_keys
        else [t(language, "safe_now")]
    )
    link_verdict = {
        "url": url_to_check,
        "risk_level": risk_level,
        "score": total_score,
        "is_safe": risk_level == "Low",
        "reason_keys": list(dict.fromkeys(reason_keys)),
    }
    if payload.get("_skip_ai_summary"):
        model_intent_summary = ""
    else:
        model_intent_summary = build_ai_model_summary(
            message=message,
            submitted_url=normalized_submitted or "",
            analyzed_url=url_to_check or "",
            language=language,
            risk_level=risk_level,
            reason_keys=list(dict.fromkeys(reason_keys)),
            domain_verdict=domain_verdict,
            tld_country_code=url_context.get("tld_country_code", ""),
        )

    response_payload = {
            "score": total_score,
            "risk_level": risk_level,
            "is_green_safe": is_green_safe,
            "green_checks": green_checks,
            "submitted_url": normalized_submitted,
            "redirect_chain": redirect_chain,
            "registrable_domain": registrable_domain,
            "has_subdomains": has_subdomains,
            "reason_keys": reason_keys,
            "reasons": reasons,
            "explanation": build_explanation(language, risk_level, reason_keys, url_context),
            "intel_note": intel_note,
            "analyzed_url": url_to_check,
            "decoded_url": decoded_url,
            "lookalike_target": url_context.get("lookalike_target", ""),
            "lookalike_seen": url_context.get("lookalike_seen", ""),
            "brand_target": url_context.get("brand_target", ""),
            "case_confusable_char": url_context.get("case_confusable_char", ""),
            "case_confusable_lower_host": url_context.get("case_confusable_lower_host", ""),
            "mixed_scripts_char": url_context.get("mixed_scripts_char", ""),
            "unicode_lookalike_char": url_context.get("unicode_lookalike_char", ""),
            "domain_tld": url_context.get("domain_tld", ""),
            "tld_country_code": url_context.get("tld_country_code", ""),
            "page_audience": url_context.get("page_audience", ""),
            "domain_verdict": domain_verdict,
            "link_verdict": link_verdict,
            "ai_model_summary": model_intent_summary,
        }
    if not payload.get("_skip_scan_log") and not payload.get("_single_url_only"):
        append_scan_event_to_file(
            url_field=raw_url,
            message_field=message,
            language=language,
            user_agent=(request.headers.get("User-Agent") or "")[:2000],
            client_ip=(request.headers.get("X-Forwarded-For") or request.remote_addr or "")[:200],
            result=response_payload,
            source="analyze",
        )
    return jsonify(response_payload)


@app.post("/analyze/live/start")
@limiter.limit("15 per minute")
def analyze_live_start():
    payload = request.get_json(silent=True) or {}
    language = "he" if (payload.get("language", "") or "").lower() == "he" else "en"
    raw_url = (payload.get("url", "") or "").strip()
    message = (payload.get("message", "") or "").strip()
    scan_user_agent = (request.headers.get("User-Agent") or "")[:2000]
    scan_client_ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "")[:200]
    if len(raw_url) > MAX_ANALYZE_URL_LEN or len(message) > MAX_ANALYZE_MESSAGE_LEN:
        return jsonify({"ok": False, "error": "payload_too_large"}), 413
    submitted_url = normalize_url_for_checks(raw_url or extract_first_url(message))
    if not submitted_url:
        return jsonify({"ok": False, "error": "need_input", "reasons": [t(language, "need_input")]}), 400

    cache_key = _live_cache_key(submitted_url, message, language)
    cached = _cache_get(cache_key)
    if cached:
        try:
            append_scan_event_to_file(
                url_field=raw_url,
                message_field=message,
                language=language,
                user_agent=scan_user_agent,
                client_ip=scan_client_ip,
                result=cached,
                source="live_cache",
            )
        except Exception:
            pass
        return jsonify(
            {
                "ok": True,
                "analysis_id": "",
                "cached": True,
                "final": True,
                "stage": 3,
                "progress": 100,
                "risk_level": cached.get("risk_level", "Low"),
                "steps": _steps_payload(3, True),
                "status_text": t(language, "live_cache_loaded"),
                "result": cached,
            }
        )

    risk_level, reason_keys, snapshot = _build_stage1_snapshot(submitted_url, language)
    job_id = str(uuid.uuid4())
    with LIVE_LOCK:
        LIVE_ANALYSIS_JOBS[job_id] = {
            "id": job_id,
            "created_at": time.time(),
            "final": False,
            "stage": 1,
            "progress": 33,
            "risk_level": risk_level,
            "steps": _steps_payload(1, False),
            "status_text": t(language, "live_progress"),
            "result": snapshot,
            "payload": {"url": raw_url, "message": message, "language": language},
        }

    worker = threading.Thread(
        target=_run_live_pipeline,
        args=(
            job_id,
            {
                "url": raw_url,
                "message": message,
                "language": language,
                "_scan_user_agent": scan_user_agent,
                "_scan_client_ip": scan_client_ip,
            },
        ),
        daemon=True,
    )
    worker.start()

    return jsonify(
        {
            "ok": True,
            "analysis_id": job_id,
            "cached": False,
            "final": False,
            "stage": 1,
            "progress": 33,
            "risk_level": risk_level,
            "steps": _steps_payload(1, False),
            "status_text": t(language, "live_progress"),
            "result": snapshot,
        }
    )


@app.get("/analyze/live/status/<analysis_id>")
@limiter.limit("120 per minute")
def analyze_live_status(analysis_id: str):
    with LIVE_LOCK:
        job = LIVE_ANALYSIS_JOBS.get(analysis_id)
        if not job:
            return jsonify({"ok": False, "error": "analysis_not_found"}), 404
        age = time.time() - float(job.get("created_at", 0))
        if not job.get("final") and age > LIVE_JOB_TIMEOUT_SEC:
            # Do not mark partial data as final; avoid early "safe/green" impressions.
            job["stage"] = max(2, int(job.get("stage", 1)))
            job["progress"] = _stage_progress(job["stage"], False)
            language = "he" if (job.get("payload", {}).get("language", "") or "").lower() == "he" else "en"
            job["status_text"] = t(language, "live_still_collecting")
        response = {
            "ok": True,
            "analysis_id": analysis_id,
            "final": bool(job.get("final")),
            "stage": int(job.get("stage", 1)),
            "progress": int(job.get("progress", 0)),
            "risk_level": job.get("risk_level", "Low"),
            "steps": job.get("steps", _steps_payload(1, False)),
            "status_text": job.get("status_text", ""),
            "result": job.get("result", {}),
        }
    return jsonify(response)


@app.route("/webhook", methods=["POST"])
@limiter.limit("60 per minute")
def github_webhook():
    """Receive GitHub webhook and trigger deploy script asynchronously."""
    raw_body = request.get_data() or b""
    event = (request.headers.get("X-GitHub-Event") or "").strip().lower()
    payload = request.get_json(silent=True) or {}
    signature = (request.headers.get("X-Hub-Signature-256") or "").strip()
    secret = (os.getenv("GITHUB_WEBHOOK_SECRET") or "").strip()

    if not secret:
        return jsonify({"ok": False, "error": "webhook_not_configured"}), 503

    expected_signature = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        return jsonify({"ok": False, "error": "invalid_signature"}), 401

    if event == "ping":
        return jsonify({"ok": True, "message": "pong"})
    if event != "push":
        return jsonify({"ok": True, "ignored": event})

    try:
        payload = json.loads(raw_body.decode("utf-8") or "{}")
    except Exception:
        return jsonify({"ok": False, "error": "invalid_payload"}), 400


    if payload.get("ref") != "refs/heads/main":
        return jsonify({"ok": True, "ignored": "non_main_branch"})

    script_path = (os.getenv("DEPLOY_SCRIPT_PATH") or "/root/erlix/linkcheck/deploy.sh").strip()
    log_path = (os.getenv("DEPLOY_LOG_PATH") or "/root/erlix/linkcheck/deploy-webhook.log").strip()
    if not os.path.exists(script_path):
        return jsonify({"ok": False, "error": "deploy_script_missing"}), 500

    global WEBHOOK_DEPLOY_PROCESS
    with WEBHOOK_DEPLOY_LOCK:
        if WEBHOOK_DEPLOY_PROCESS and WEBHOOK_DEPLOY_PROCESS.poll() is None:
            return jsonify({"ok": True, "status": "deploy_already_running"}), 202

        log_dir = os.path.dirname(log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        with open(log_path, "ab") as log_file:
            WEBHOOK_DEPLOY_PROCESS = subprocess.Popen(
                ["nohup", "/bin/bash", script_path],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                cwd="/root/erlix/linkcheck",
                start_new_session=True,
            )

    return jsonify({"ok": True, "status": "deploy_started"}), 202


def _smtp_configured() -> bool:
    return bool(os.getenv("SMTP_HOST", "").strip() and os.getenv("SMTP_USER", "").strip() and os.getenv("SMTP_PASSWORD", "").strip())


def _report_store_path() -> str | None:
    p = (os.getenv("REPORT_STORE_PATH") or "").strip()
    return p or None


def _scan_events_store_path() -> str | None:
    p = (os.getenv("SCAN_EVENTS_STORE_PATH") or "data/scan_events.jsonl").strip()
    return p or None


def _resolved_report_store_path() -> str | None:
    """Resolve REPORT_STORE_PATH relative to this file's directory (stable regardless of cwd)."""
    raw = _report_store_path()
    if not raw:
        return None
    if os.path.isabs(raw):
        return os.path.normpath(raw)
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(backend_dir, raw))


def _resolved_scan_events_store_path() -> str | None:
    """Resolve scan-event storage relative to this file's directory."""
    raw = _scan_events_store_path()
    if not raw:
        return None
    if os.path.isabs(raw):
        return os.path.normpath(raw)
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(backend_dir, raw))


def _file_store_configured() -> bool:
    return _report_store_path() is not None


def _host_summary(url: str) -> dict:
    normalized = normalize_url_for_checks(url or "")
    parsed = urlparse(normalized if "://" in normalized else f"https://{normalized}") if normalized else None
    host = (parsed.hostname or "").lower() if parsed else ""
    return {
        "host": host or None,
        "registrable_domain": get_registrable_domain(host) if host else None,
    }


def append_scan_event_to_file(
    *,
    url_field: str,
    message_field: str,
    language: str,
    user_agent: str,
    client_ip: str,
    result: dict,
    source: str,
) -> None:
    """Append privacy-conscious usage analytics without storing full message text."""
    abs_path = _resolved_scan_events_store_path()
    if not abs_path:
        return
    parent = os.path.dirname(abs_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    message_urls = extract_urls(message_field or "")
    submitted_url = result.get("submitted_url") or url_field or (message_urls[0] if message_urls else "")
    analyzed_url = result.get("analyzed_url") or ""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "language": language,
        "client_ip": client_ip,
        "user_agent": user_agent,
        "has_url_field": bool((url_field or "").strip()),
        "has_message_field": bool((message_field or "").strip()),
        "message_length": len(message_field or ""),
        "message_url_count": len(message_urls),
        "message_url_hosts": [_host_summary(url) for url in message_urls],
        "submitted_url": _host_summary(submitted_url),
        "analyzed_url": _host_summary(analyzed_url),
        "risk_level": result.get("risk_level"),
        "score": result.get("score"),
        "reason_keys": result.get("reason_keys") or [],
        "message_links_analyzed_count": result.get("message_links_analyzed_count"),
        "selected_message_url": _host_summary(result.get("selected_message_url") or ""),
    }
    with open(abs_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _format_checked_scan_context(url_field: str, message_field: str) -> str:
    """Human-readable block of URL and/or message the user had in the scan form (if any)."""
    u = (url_field or "").strip()
    m = (message_field or "").strip()
    parts: list[str] = []
    if u:
        parts.append(f"[URL checked]\n{u}")
    if m:
        parts.append(f"[Message checked]\n{m}")
    return "\n\n".join(parts)


def _report_site_only_ui() -> bool:
    return os.getenv("REPORT_SITE_ONLY", "").lower() in {"1", "true", "yes", "on"}


def append_issue_report_to_file(
    *,
    description: str,
    url_field: str,
    message_field: str,
    language: str,
    user_agent: str,
    client_ip: str,
) -> None:
    """Append one JSON object per line to REPORT_STORE_PATH (UTF-8)."""
    abs_path = _resolved_report_store_path()
    if not abs_path:
        raise RuntimeError("REPORT_STORE_PATH not set")
    parent = os.path.dirname(abs_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    ctx = _format_checked_scan_context(url_field, message_field)
    u_stripped = (url_field or "").strip()
    m_stripped = (message_field or "").strip()
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "language": language,
        "client_ip": client_ip,
        "user_agent": user_agent,
        "checked_url": u_stripped or None,
        "checked_message": m_stripped or None,
        "checked_context_text": ctx or None,
        "url_field": url_field,
        "message_field": message_field,
        "description": description,
    }
    with open(abs_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _report_delivery_configured() -> bool:
    return _smtp_configured() or _file_store_configured()


def send_issue_report_email(
    *,
    description: str,
    url_field: str,
    message_field: str,
    language: str,
    user_agent: str,
    client_ip: str,
) -> None:
    """Send plain-text report email via SMTP (requires SMTP_* env vars)."""
    host = os.getenv("SMTP_HOST", "").strip()
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "").strip()
    password = os.getenv("SMTP_PASSWORD", "").strip()
    use_tls = os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes"}
    mail_from = os.getenv("REPORT_FROM_EMAIL", user).strip()
    mail_to = os.getenv("REPORT_TO_EMAIL", "erlix.co@gmail.com").strip()

    ctx = _format_checked_scan_context(url_field, message_field)
    ctx_block = (
        f"From scan (auto):\n{ctx}\n\n"
        if ctx
        else f"URL field:\n{url_field or '(empty)'}\n\nMessage field:\n{message_field or '(empty)'}\n\n"
    )
    body = (
        "LinkCheck — issue report\n"
        "────────────────────────\n"
        f"Language: {language}\n"
        f"Client IP: {client_ip}\n"
        f"User-Agent: {user_agent}\n\n"
        f"{ctx_block}"
        f"Description:\n{description}\n"
    )

    msg = EmailMessage()
    msg["Subject"] = "LinkCheck — issue report"
    msg["From"] = mail_from
    msg["To"] = mail_to
    msg.set_content(body, charset="utf-8")

    with smtplib.SMTP(host, port, timeout=15) as smtp:
        if use_tls:
            smtp.starttls(context=ssl.create_default_context())
        smtp.login(user, password)
        smtp.send_message(msg)


@app.get("/report/config")
@limiter.limit("120 per minute")
def report_config():
    """Tell the UI whether site reports work and whether mailto shortcuts should show."""
    smtp = _smtp_configured()
    file_store = _file_store_configured()
    accepts = _report_delivery_configured()
    site_only = _report_site_only_ui()
    # Hide mailto when operator chose site-only, or when file store alone handles delivery (no SMTP).
    show_mailto = not site_only and not (file_store and not smtp)
    return jsonify(
        {
            "accepts_site_reports": accepts,
            "show_mailto": show_mailto,
            "smtp": smtp,
            "file_store": file_store,
        }
    )


@app.post("/report")
@limiter.limit("12 per 5 minutes")
def report_issue():
    """Receive bug/issue reports: SMTP and/or append to REPORT_STORE_PATH (JSON lines)."""
    if not _report_delivery_configured():
        mailto_fb = not _report_site_only_ui()
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "report_delivery_not_configured",
                    "mailto_fallback": mailto_fb,
                }
            ),
            503,
        )

    payload = request.get_json(silent=True) or {}
    description = (payload.get("description") or "").strip()
    if len(description) < 5:
        return jsonify({"ok": False, "error": "description_too_short"}), 400
    if len(description) > 8000:
        return jsonify({"ok": False, "error": "description_too_long"}), 400

    url_field = (payload.get("url_field") or "")[:4000]
    message_field = (payload.get("message_field") or "")[:8000]
    language = (payload.get("language") or "en")[:8]

    user_agent = (request.headers.get("User-Agent") or "")[:2000]
    client_ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "")[:200]

    delivered = []

    if _file_store_configured():
        try:
            append_issue_report_to_file(
                description=description,
                url_field=url_field,
                message_field=message_field,
                language=language,
                user_agent=user_agent,
                client_ip=client_ip,
            )
            delivered.append("file")
        except Exception:
            if not _smtp_configured():
                return jsonify({"ok": False, "error": "store_failed"}), 502

    if _smtp_configured():
        try:
            send_issue_report_email(
                description=description,
                url_field=url_field,
                message_field=message_field,
                language=language,
                user_agent=user_agent,
                client_ip=client_ip,
            )
            delivered.append("smtp")
        except Exception:
            if "file" not in delivered:
                return jsonify({"ok": False, "error": "send_failed"}), 502

    if not delivered:
        return jsonify({"ok": False, "error": "send_failed"}), 502

    return jsonify({"ok": True, "via": delivered})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)


# חיבור דף הבית לשרת אוטומטית

@app.route('/webhook-home', methods=['POST'])
def webhook_home():
    import subprocess, os, hmac, hashlib

    raw_body = request.get_data() or b""
    signature = (request.headers.get("X-Hub-Signature-256") or "").strip()
    secret = (os.getenv("GITHUB_WEBHOOK_SECRET") or "").strip()

    # אימות חתימה
    if not signature or not secret:
        return jsonify({"ok": False, "error": "missing_signature"}), 403

    mac = hmac.new(secret.encode(), msg=raw_body, digestmod=hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()

    if not hmac.compare_digest(expected, signature):
        return jsonify({"ok": False, "error": "invalid_signature"}), 403

    # להריץ deploy של דף הבית
    subprocess.Popen(
        ["nohup", "/bin/bash", "/root/erlix/home-deploy.sh"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    return jsonify({"ok": True, "status": "home_deploy_started"}), 202