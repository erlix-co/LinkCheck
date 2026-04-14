import os
import re
import unicodedata
from urllib.parse import urlparse

from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

BRAND_PATTERNS = ("nike", "paypal", "benetton", "amazon")
PROTECTED_BRANDS = ("bankisrael", "paypal", "amazon", "nike", "benetton")
SUSPICIOUS_WORDS = ("login", "verify", "secure", "account", "update")
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
URL_REGEX = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)
CYRILLIC_OR_GREEK_CHARS = re.compile(r"[\u0370-\u03ff\u0400-\u04ff]")
I18N = {
    "en": {
        "invalid_url": "The link format looks invalid.",
        "brand": "Looks like a known brand imitation.",
        "suspicious_words": "Contains words commonly used in phishing.",
        "lookalike_brand": "Link looks like a fake brand/domain imitation.",
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
        "intel_configured": "Security data sources are connected: {sources}.",
        "intel_missing": "Advanced security sources are not connected yet.",
        "need_input": "Please enter a URL or full message text.",
        "no_major_signals": "No strong phishing signs were found."
    },
    "he": {
        "invalid_url": "פורמט הקישור נראה לא תקין.",
        "brand": "נראה כמו התחזות למותג מוכר.",
        "suspicious_words": "יש מילים אופייניות לניסיונות פישינג.",
        "lookalike_brand": "נראה שהקישור מחקה דומיין/מותג אמיתי.",
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
        "intel_configured": "מקורות מידע אבטחתי מחוברים: {sources}.",
        "intel_missing": "מקורות מידע אבטחתי מתקדמים עדיין לא מחוברים.",
        "need_input": "יש להזין קישור או טקסט הודעה מלא.",
        "no_major_signals": "לא נמצאו סימני פישינג חזקים."
    }
}


def t(language: str, key: str, **kwargs) -> str:
    lang = "he" if language == "he" else "en"
    template = I18N[lang][key]
    return template.format(**kwargs) if kwargs else template


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


def extract_first_url(text: str) -> str:
    """Extract first URL from text if present."""
    if not text:
        return ""
    match = URL_REGEX.search(text)
    if not match:
        return ""
    candidate = match.group(0).strip(".,);]")
    if candidate.startswith("www."):
        return f"https://{candidate}"
    return candidate


def analyze_url(url: str) -> tuple[int, list[str]]:
    """Analyze URL heuristics and return partial score + reasons."""
    score = 0
    reasons = []
    normalized_url = (url or "").strip()

    if not normalized_url:
        return 0, reasons

    lower_url = normalized_url.lower()

    # Rule: brand-like words can indicate impersonation attempts.
    if any(pattern in lower_url for pattern in BRAND_PATTERNS):
        score += 20
        reasons.append("brand")

    # Rule: suspicious account/action words are common in phishing.
    if any(word in lower_url for word in SUSPICIOUS_WORDS):
        score += 15
        reasons.append("suspicious_words")

    # Parse URL parts; add temporary https scheme if missing for robust parsing.
    parsed = urlparse(normalized_url if "://" in normalized_url else f"https://{normalized_url}")
    hostname = (parsed.hostname or "").lower()

    # Basic format validation: require a hostname like example.com.
    if not hostname or "." not in hostname:
        reasons.append("invalid_url")
        return score, reasons

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
    for brand in PROTECTED_BRANDS:
        if label == brand:
            continue
        if label_normalized == brand or is_one_edit_away(label_normalized, brand):
            is_lookalike = True
            break

    if is_lookalike:
        score += 50
        reasons.append("lookalike_brand")

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

    return score, reasons


def analyze_message_text(message: str) -> tuple[int, list[str]]:
    """Analyze phishing language patterns in full SMS/email text."""
    score = 0
    reasons = []
    text = (message or "").strip().lower()
    if not text:
        return score, reasons

    # Urgency and pressure wording is common in social engineering.
    hit_count = sum(1 for term in SUSPICIOUS_MESSAGE_TERMS if term in text)
    if hit_count:
        score += min(20, hit_count * 8)
        reasons.append("message_pressure")

    # Very short message with link-only pattern is suspicious.
    if len(text) < 35 and URL_REGEX.search(text):
        score += 10
        reasons.append("message_short_link")

    # Excessive punctuation is often used for pressure.
    if "!!!" in text:
        score += 5
        reasons.append("message_aggressive")

    return score, reasons


def external_intel_status(url: str) -> tuple[str, list[str]]:
    """
    Placeholder for external intelligence sources.
    We intentionally keep this MVP safe and explicit:
    integrations require API keys and provider-specific workflows.
    """
    if not url:
        return "", []

    enabled_sources = []

    if os.getenv("VIRUSTOTAL_API_KEY"):
        enabled_sources.append("VirusTotal")
    if os.getenv("URLSCAN_API_KEY"):
        enabled_sources.append("URLScan")
    if os.getenv("WHOISXML_API_KEY"):
        enabled_sources.append("WHOIS")
    if os.getenv("DNS_CHECK_API_KEY"):
        enabled_sources.append("DNS")

    if enabled_sources:
        return "intel_configured", enabled_sources
    return "intel_missing", []


def classify_risk(score: int) -> str:
    if score <= 30:
        return "Low"
    if score <= 60:
        return "Medium"
    return "High"


@app.post("/analyze")
def analyze():
    payload = request.get_json(silent=True) or {}
    language = "he" if (payload.get("language", "") or "").lower() == "he" else "en"
    raw_url = (payload.get("url", "") or "").strip()
    message = (payload.get("message", "") or "").strip()

    # If user provided full message, extract URL automatically.
    extracted_url = extract_first_url(message)
    url_to_check = raw_url or extracted_url

    if not url_to_check and not message:
        return jsonify(
            {
                "score": 0,
                "risk_level": "Low",
                "reasons": [t(language, "need_input")]
            }
        ), 400

    url_score, url_reason_keys = analyze_url(url_to_check)
    text_score, text_reason_keys = analyze_message_text(message)
    intel_key, intel_sources = external_intel_status(url_to_check)

    total_score = min(100, url_score + text_score)
    reason_keys = url_reason_keys + text_reason_keys
    reasons = [t(language, key) for key in reason_keys]
    if intel_key == "intel_configured":
        reasons.append(t(language, intel_key, sources=", ".join(intel_sources)))
    elif intel_key:
        reasons.append(t(language, intel_key))

    if not reasons:
        reasons = [t(language, "no_major_signals")]

    return jsonify(
        {
            "score": total_score,
            "risk_level": classify_risk(total_score),
            "reasons": reasons,
            "analyzed_url": url_to_check
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
