import json
import os
import re
import unicodedata
import base64
import ssl
import socket
from datetime import datetime, timezone
from difflib import SequenceMatcher
from urllib.parse import urlparse, urljoin, unquote

import requests
import whois
from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)
gemini_api_key = os.getenv("GEMINI_API_KEY")

BRAND_PATTERNS = ("nike", "paypal", "benetton", "amazon")
PROTECTED_BRANDS = ("bankisrael", "paypal", "amazon", "nike", "benetton")
BRAND_CANONICAL_DOMAINS = {
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com"},
    "nike": {"nike.com"},
    "benetton": {"benetton.com"},
    "apple": {"apple.com"},
    "google": {"google.com"},
    "microsoft": {"microsoft.com"},
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
    "apple.com",
    "google.com",
    "microsoft.com",
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
)
NON_WARNING_LOCAL_KEYS = {"short_link_expanded"}
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
CYRILLIC_OR_GREEK_CHARS = re.compile(r"[\u0370-\u03ff\u0400-\u04ff]")
I18N = {
    "en": {
        "invalid_url": "The link format looks invalid.",
        "brand": "Looks like a known brand imitation.",
        "brand_mismatch": "Brand name appears in the link, but the real domain ownership does not match that brand.",
        "suspicious_words": "Contains words commonly used in phishing.",
        "lookalike_brand": "Domain name is almost identical to a known brand/domain (one-character trick).",
        "at_sign_userinfo": "URL uses '@' to hide the real destination domain.",
        "case_confusable": "Domain uses mixed uppercase/lowercase letters to mimic another character.",
        "mixed_scripts": "Link mixes different alphabets (common phishing trick).",
        "unicode_lookalike": "Link uses lookalike Unicode characters.",
        "punycode": "Link uses encoded international domain format (IDN).",
        "suspicious_tld": "Uses a risky domain ending.",
        "long_url": "The link is unusually long.",
        "many_hyphens": "Too many '-' signs in the link.",
        "no_https": "The link is not secure (no HTTPS).",
        "message_pressure": "The message uses pressure or urgency language.",
        "message_short_link": "Short message with a link can be suspicious.",
        "message_aggressive": "Aggressive punctuation detected.",
        "ai_social_engineering": "Message intent looks like social engineering (pressure + action request).",
        "ai_authority_impersonation": "Message appears to impersonate an official organization/brand.",
        "ai_sensitive_request": "Message asks for sensitive action (login/payment/verification).",
        "ai_threat_or_reward": "Message uses threat or reward language to force quick action.",
        "ai_model_social_engineering": "AI detected social-engineering intent in the message.",
        "ai_model_impersonation": "AI detected likely impersonation of a trusted organization.",
        "ai_model_sensitive_action": "AI detected request for sensitive user action.",
        "ai_model_unavailable": "AI semantic analysis is currently unavailable.",
        "intel_configured": "Advanced safety checks are connected: {sources}.",
        "intel_missing": "Some advanced safety checks are not connected yet.",
        "vt_malicious": "Global virus and threat databases marked this link as malicious.",
        "vt_suspicious": "Global virus and threat databases found suspicious signs for this link.",
        "vt_clean": "Global virus and threat databases did not report this link as malicious.",
        "vt_pending": "A check in global threat databases has started and is still updating.",
        "vt_unavailable": "Global threat database check is unavailable right now.",
        "urlscan_malicious": "A global website scanning service marked this link as malicious.",
        "urlscan_suspicious": "A global website scanning service found suspicious signs.",
        "urlscan_clean": "A global website scanning service did not find malicious signs.",
        "urlscan_pending": "A global website scanning service is still checking this link.",
        "urlscan_unavailable": "Website scanning service is unavailable right now.",
        "short_link_expanded": "Shortened link was expanded to its real destination.",
        "short_link_unresolved": "Could not fully expand the shortened link destination.",
        "need_input": "Please enter a URL or full message text.",
        "no_major_signals": "No strong phishing signs were found.",
        "safe_now": "No warning signs were found in this check.",
        "insufficient_trust_signals": "Not enough trust signals for a green/safe result.",
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
        "case_confusable": "הדומיין משתמש בערבוב אותיות גדולות/קטנות כדי להטעות חזותית.",
        "mixed_scripts": "הקישור מערב כמה סוגי אותיות (טריק פישינג נפוץ).",
        "unicode_lookalike": "בקישור יש תווי יוניקוד דומים לאותיות רגילות.",
        "punycode": "הקישור משתמש בפורמט דומיין מקודד (IDN).",
        "suspicious_tld": "סיומת הדומיין נחשבת חשודה.",
        "long_url": "הקישור ארוך בצורה חריגה.",
        "many_hyphens": "יש יותר מדי סימני '-' בקישור.",
        "no_https": "הקישור לא מאובטח (ללא HTTPS).",
        "message_pressure": "יש בהודעה ניסוח מלחיץ או דחוף.",
        "message_short_link": "הודעה קצרה עם קישור יכולה להיות חשודה.",
        "message_aggressive": "נמצאו סימני פיסוק אגרסיביים.",
        "ai_social_engineering": "נראית כוונת הנדסה חברתית בהודעה (לחץ + בקשה לפעולה).",
        "ai_authority_impersonation": "נראה שההודעה מתחזה לגורם רשמי/מותג מוכר.",
        "ai_sensitive_request": "ההודעה מבקשת פעולה רגישה (כניסה/תשלום/אימות).",
        "ai_threat_or_reward": "ההודעה משתמשת באיום או פיתוי כדי לדחוף לפעולה מהירה.",
        "ai_model_social_engineering": "מנוע ה-AI זיהה כוונת הנדסה חברתית בהודעה.",
        "ai_model_impersonation": "מנוע ה-AI זיהה חשד להתחזות לגורם אמין.",
        "ai_model_sensitive_action": "מנוע ה-AI זיהה בקשה לפעולה רגישה מצד המשתמש.",
        "ai_model_unavailable": "ניתוח סמנטי מבוסס AI אינו זמין כרגע.",
        "intel_configured": "בדיקות בטיחות מתקדמות מחוברות: {sources}.",
        "intel_missing": "חלק מבדיקות הבטיחות המתקדמות עדיין לא מחוברות.",
        "vt_malicious": "בדיקה במאגרי וירוסים ואיומים עולמיים סימנה את הקישור כזדוני.",
        "vt_suspicious": "בדיקה במאגרי וירוסים ואיומים עולמיים מצאה סימנים חשודים בקישור.",
        "vt_clean": "בדיקה במאגרי וירוסים ואיומים עולמיים לא מצאה שהקישור זדוני.",
        "vt_pending": "בדיקה במאגרי וירוסים ואיומים עולמיים התחילה ועדיין מתעדכנת.",
        "vt_unavailable": "בדיקה במאגרי האיומים העולמיים אינה זמינה כרגע.",
        "urlscan_malicious": "שירות עולמי לסריקת אתרים סימן את הקישור כזדוני.",
        "urlscan_suspicious": "שירות עולמי לסריקת אתרים מצא סימנים חשודים בקישור.",
        "urlscan_clean": "שירות עולמי לסריקת אתרים לא מצא סימנים זדוניים.",
        "urlscan_pending": "שירות עולמי לסריקת אתרים עדיין בודק את הקישור.",
        "urlscan_unavailable": "שירות סריקת האתרים אינו זמין כרגע.",
        "short_link_expanded": "לינק מקוצר נחשף ליעד האמיתי שלו.",
        "short_link_unresolved": "לא ניתן היה לחשוף במלואו את היעד של הלינק המקוצר.",
        "need_input": "יש להזין קישור או טקסט הודעה מלא.",
        "no_major_signals": "לא נמצאו סימני פישינג חזקים.",
        "safe_now": "בבדיקה הזו לא נמצאו סימני אזהרה.",
        "insufficient_trust_signals": "אין מספיק אותות אמון כדי לתת מצב ירוק/בטוח.",
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


def count_term_hits(text: str, terms: tuple[str, ...] | list[str]) -> int:
    return sum(1 for term in terms if term in text)


def detect_brand_token_in_hostname(hostname: str) -> str:
    host = (hostname or "").lower()
    labels = [label for label in host.split(".") if label]
    for label in labels:
        for token in BRAND_CANONICAL_DOMAINS:
            if token in label:
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
    """Get main domain label (handles normal and .co.il style domains)."""
    host = hostname.lower()
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    if len(parts) < 2:
        return host
    # Handle common Israeli second-level domains: *.co.il, *.org.il, *.gov.il, etc.
    il_second_level = {"ac", "co", "org", "gov", "net", "muni", "k12", "idf"}
    if len(parts) >= 3 and parts[-1] == "il" and parts[-2] in il_second_level:
        return parts[-3]
    return parts[-2]


def get_registrable_domain(hostname: str) -> str:
    """Return the main registrable domain (e.g. verify-user.co, example.co.il)."""
    host = (hostname or "").lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    if len(parts) < 2:
        return host

    il_second_level = {"ac", "co", "org", "gov", "net", "muni", "k12", "idf"}
    if len(parts) >= 3 and parts[-1] == "il" and parts[-2] in il_second_level:
        return f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
    return f"{parts[-2]}.{parts[-1]}"


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


def extract_first_url(text: str) -> str:
    """Extract first URL from text if present."""
    if not text:
        return ""
    match = URL_REGEX.search(text)
    if match:
        candidate = match.group(0).strip(".,);]")
        if candidate.startswith("www."):
            return f"https://{candidate}"
        return candidate
    # Catch known shortener domains without protocol prefix (e.g. "bit.ly/abc")
    for domain in SHORTENER_DOMAINS:
        pattern = re.compile(rf"\b{re.escape(domain)}/\S+", re.IGNORECASE)
        m = pattern.search(text)
        if m:
            return f"https://{m.group(0).strip('.,);]')}"
    return ""


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


def expand_short_url(url: str) -> tuple[str, list[str], list[str]]:
    """
    Expand known shortened links to their final destination.
    Returns (final_url, reason_keys, redirect_chain).
    """
    reason_keys: list[str] = []
    redirect_chain: list[str] = []
    normalized = normalize_url_for_checks(url)
    if not normalized:
        return normalized, reason_keys, redirect_chain

    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower()
    is_short_domain = any(hostname == d or hostname.endswith(f".{d}") for d in SHORTENER_DOMAINS)
    if not is_short_domain:
        return normalized, reason_keys, redirect_chain

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }
    session = requests.Session()

    # Strategy 1: HEAD with redirects (fast path)
    try:
        head_resp = session.head(normalized, allow_redirects=True, headers=headers, timeout=8)
        head_chain = [r.url for r in head_resp.history] + [head_resp.url]
        if head_chain:
            redirect_chain = head_chain
        if head_resp.url and head_resp.url != normalized:
            reason_keys.append("short_link_expanded")
            return head_resp.url, reason_keys, redirect_chain
    except Exception:
        pass

    # Strategy 2: GET with redirects (some providers ignore HEAD)
    try:
        get_resp = session.get(normalized, allow_redirects=True, headers=headers, timeout=10)
        get_chain = [r.url for r in get_resp.history] + [get_resp.url]
        if get_chain:
            redirect_chain = get_chain
        if get_resp.url and get_resp.url != normalized:
            reason_keys.append("short_link_expanded")
            return get_resp.url, reason_keys, redirect_chain
    except Exception:
        pass

    # Strategy 3: manual hop-by-hop follow of Location headers
    try:
        current = normalized
        manual_chain = [current]
        for _ in range(8):
            hop = session.get(current, allow_redirects=False, headers=headers, timeout=8)
            location = hop.headers.get("Location")
            if not location:
                break
            next_url = urljoin(current, location)
            manual_chain.append(next_url)
            current = next_url
        if len(manual_chain) > 1:
            redirect_chain = manual_chain
            reason_keys.append("short_link_expanded")
            return manual_chain[-1], reason_keys, redirect_chain
    except Exception:
        pass

    reason_keys.append("short_link_unresolved")
    if not redirect_chain:
        redirect_chain = [normalized]
    return normalized, reason_keys, redirect_chain


def analyze_url(url: str) -> tuple[int, list[str], dict]:
    """Analyze URL heuristics and return partial score + reasons."""
    score = 0
    reasons = []
    normalized_url = (url or "").strip()

    context = {}
    if not normalized_url:
        return 0, reasons, context

    lower_url = normalized_url.lower()

    # Rule: suspicious account/action words are common in phishing.
    if any(word in lower_url for word in SUSPICIOUS_WORDS):
        score += 15
        reasons.append("suspicious_words")

    # Parse URL parts; add temporary https scheme if missing for robust parsing.
    parsed = urlparse(normalized_url if "://" in normalized_url else f"https://{normalized_url}")
    hostname = (parsed.hostname or "").lower()
    path_value = parsed.path or ""
    host_case_raw = extract_host_preserve_case(parsed)
    netloc_raw = parsed.netloc or ""

    # Basic format validation: require a hostname like example.com.
    if not hostname or "." not in hostname:
        reasons.append("invalid_url")
        return score, reasons, context

    registrable_domain = get_registrable_domain(hostname)
    brand_token = detect_brand_token_in_hostname(hostname)
    if brand_token:
        canonical_domains = BRAND_CANONICAL_DOMAINS.get(brand_token, set())
        if canonical_domains and registrable_domain not in canonical_domains:
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

    # Rule: generic brand-like words can indicate impersonation attempts.
    # Keep as supporting signal only when no structural mismatch already exists.
    brand_hit = next((pattern for pattern in BRAND_PATTERNS if pattern in lower_url), "")
    if brand_hit and "brand_mismatch" not in reasons:
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

    # Rule: unicode lookalikes that change when mapped to ASCII skeleton.
    if CYRILLIC_OR_GREEK_CHARS.search(hostname):
        skeleton = ascii_skeleton(hostname)
        ascii_only = re.sub(r"[^a-z0-9.-]", "", skeleton)
        if ascii_only and ascii_only != hostname:
            score += 30
            reasons.append("unicode_lookalike")

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
    has_upper = any(ch.isalpha() and ch.isupper() for ch in host_case_raw)
    has_lower = any(ch.isalpha() and ch.islower() for ch in host_case_raw)
    if has_upper and has_lower:
        score += 70
        reasons.append("case_confusable")

    # Rule: URLs with userinfo (@) are a classic phishing obfuscation trick.
    if "@" in netloc_raw:
        score += 100
        reasons.append("at_sign_userinfo")

    # Rule: very long URLs often hide malicious intent.
    if len(normalized_url) > 75:
        score += 10
        reasons.append("long_url")

    # Rule: many hyphens can indicate deceptive domain naming.
    if normalized_url.count("-") >= 3:
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
    has_link = bool(URL_REGEX.search(text)) or any(
        re.search(rf"\b{re.escape(d)}/\S+", text, re.IGNORECASE) for d in SHORTENER_DOMAINS
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
- Official informational/marketing messages are NOT phishing by default.
- Mark sensitive_action=true only when there is an explicit request to login, pay, verify, share credentials, or perform account-security action.
- Mark impersonation=true only when there are clear signs the sender pretends to be another trusted entity.
- If the message is informational and has no pressure/threat/urgent demand, keep all flags false.
Return STRICT JSON only with these boolean keys:
- social_engineering
- impersonation
- sensitive_action
"""

    try:
        endpoint = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            "gemini-2.5-flash:generateContent"
        )
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": (
                                f"{schema_prompt}\n\n"
                                f"message: {message}\n"
                                f"url: {url}\n"
                            )
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0,
                "responseMimeType": "application/json"
            }
        }
        resp = requests.post(
            f"{endpoint}?key={gemini_api_key}",
            json=payload,
            timeout=10
        )
        if not resp.ok:
            return 0, ["ai_model_unavailable"]

        body = resp.json()
        text = (
            body.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "{}")
        )
        parsed = json.loads(text)

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
    except Exception:
        return 0, ["ai_model_unavailable"]


def external_intel_status(url: str) -> tuple[str, list[str]]:
    if not url:
        return "", []

    enabled_sources = []
    if os.getenv("VIRUSTOTAL_API_KEY"):
        enabled_sources.append("VirusTotal")
    if os.getenv("URLSCAN_API_KEY"):
        enabled_sources.append("URLScan")

    if enabled_sources:
        return "intel_configured", enabled_sources
    return "intel_missing", []


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
            timeout=8
        )

        if report_resp.status_code == 404:
            submit_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=8
            )
            if submit_resp.ok:
                return 0, ["vt_pending"], intel_note_key
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

        if malicious > 0:
            return min(60, 35 + malicious), ["vt_malicious"], intel_note_key
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
            timeout=8
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
            timeout=8
        )
        if submit_resp.ok:
            return 0, ["urlscan_pending"], "intel_configured"
        return 0, [], "urlscan_unavailable"
    except Exception:
        return 0, [], "urlscan_unavailable"


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
    try:
        head_resp = requests.head(
            normalized,
            allow_redirects=True,
            headers=headers,
            timeout=8
        )
        if head_resp.status_code and head_resp.status_code != 405:
            return int(head_resp.status_code)
    except Exception:
        pass

    try:
        get_resp = requests.get(
            normalized,
            allow_redirects=True,
            headers=headers,
            timeout=10,
            stream=True
        )
        return int(get_resp.status_code)
    except Exception:
        return None


def domain_age_days(hostname: str) -> int | None:
    try:
        data = whois.whois(hostname)
        created = data.creation_date
        if isinstance(created, list):
            created = created[0] if created else None
        if not created:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return max(0, (now - created).days)
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


@app.post("/analyze")
def analyze():
    payload = request.get_json(silent=True) or {}
    language = "he" if (payload.get("language", "") or "").lower() == "he" else "en"
    raw_url = (payload.get("url", "") or "").strip()
    message = (payload.get("message", "") or "").strip()

    # If user provided full message, extract URL automatically.
    extracted_url = extract_first_url(message)
    submitted_url = raw_url or extracted_url
    normalized_submitted = normalize_url_for_checks(submitted_url)
    expanded_url, short_link_reason_keys, redirect_chain = expand_short_url(normalized_submitted)
    expanded_or_submitted = expanded_url or normalized_submitted
    decoded_url = decode_url_for_analysis(expanded_or_submitted)
    url_to_check = decoded_url or expanded_or_submitted
    original_host = (urlparse(normalized_submitted).hostname or "").lower() if normalized_submitted else ""
    was_short_link = any(
        original_host == d or original_host.endswith(f".{d}") for d in SHORTENER_DOMAINS
    ) if original_host else False
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
    model_intent_score, model_intent_reason_keys = analyze_message_intent_with_model(message, url_to_check)
    intel_key, intel_sources = external_intel_status(url_to_check)
    intel_score = 0
    intel_reason_keys: list[str] = []

    if url_to_check and os.getenv("VIRUSTOTAL_API_KEY"):
        vt_score, vt_reason_keys, vt_note_key = query_virustotal(
            url_to_check, os.getenv("VIRUSTOTAL_API_KEY", "")
        )
        intel_score += vt_score
        intel_reason_keys.extend(vt_reason_keys)
        intel_key = vt_note_key

    if url_to_check and os.getenv("URLSCAN_API_KEY"):
        us_score, us_reason_keys, us_note_key = query_urlscan(
            url_to_check, os.getenv("URLSCAN_API_KEY", "")
        )
        intel_score += us_score
        intel_reason_keys.extend(us_reason_keys)
        intel_key = us_note_key

    # When URL has no heuristic warnings, message scores are informational only (capped).
    url_has_warnings = len([key for key in url_reason_keys if key not in NON_WARNING_LOCAL_KEYS]) > 0
    if url_has_warnings:
        total_score = min(100, url_score + text_score + intent_score + model_intent_score + intel_score)
    else:
        total_score = min(100, url_score + intel_score)
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

    parsed = urlparse(url_to_check if "://" in url_to_check else f"https://{url_to_check}")
    hostname = (parsed.hostname or "").lower()
    registrable_domain = get_registrable_domain(hostname) if hostname else ""
    host_no_www = hostname[4:] if hostname.startswith("www.") else hostname
    has_subdomains = bool(host_no_www and registrable_domain and host_no_www != registrable_domain)
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
    vt_clean = not vt_configured or "vt_clean" in intel_reason_keys
    vt_checked = vt_configured
    urlscan_clean = not urlscan_configured or "urlscan_clean" in intel_reason_keys
    urlscan_checked = urlscan_configured
    url_only_warning_keys = [key for key in url_reason_keys if key not in NON_WARNING_LOCAL_KEYS]
    no_url_warnings = len(url_only_warning_keys) == 0
    domain_old_enough = age_days is not None and age_days >= 180

    age_status = "na"
    if age_days is not None:
        age_status = "pass" if age_days >= 180 else "fail"

    green_checks = [
        {"key": "no_local_warnings", "status": "pass" if no_url_warnings else "fail"},
        {"key": "vt_clean", "status": ("pass" if vt_clean else "fail") if vt_checked else "na"},
        {"key": "urlscan_clean", "status": ("pass" if urlscan_clean else "fail") if urlscan_checked else "na"},
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
    vt_passes = (not vt_checked) or vt_clean
    urlscan_passes = (not urlscan_checked) or urlscan_clean
    page_passes = (page_status_code is None) or page_exists
    core_pass = no_url_warnings and vt_passes and urlscan_passes and dns_ok and tls_ok and page_passes
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

    reasons = [t(language, key) for key in reason_keys]
    intel_note = ""
    if intel_key == "intel_configured":
        intel_note = t(language, intel_key, sources=", ".join(intel_sources))
    elif intel_key:
        intel_note = t(language, intel_key)

    if not reasons:
        reasons = [t(language, "safe_now")]

    # Green is granted only when all required trust signals pass.
    if is_green_safe:
        risk_level = "Low"
    else:
        risk_level = "High" if total_score > 60 else "Medium"
    if vt_malicious_hit:
        risk_level = "High"
    if brand_mismatch_hit:
        risk_level = "High"

    return jsonify(
        {
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
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
