import { useState } from "react";

/* ═══════════════════════════════════════
   TYPES
   ═══════════════════════════════════════ */

type RiskLevel = "Low" | "Medium" | "High";

type GreenCheck = {
  key: string;
  status: "pass" | "fail" | "na";
  value?: number | null;
};

type AnalysisResponse = {
  score: number;
  risk_level: RiskLevel;
  is_green_safe?: boolean;
  green_checks?: GreenCheck[];
  submitted_url?: string;
  redirect_chain?: string[];
  registrable_domain?: string;
  has_subdomains?: boolean;
  reason_keys?: string[];
  reasons: string[];
  explanation?: string;
  intel_note?: string;
  analyzed_url?: string;
};

type Language = "en" | "he";

/* ═══════════════════════════════════════
   I18N — UI STRINGS
   ═══════════════════════════════════════ */

const translations = {
  en: {
    subtitle: "Got a suspicious link or message? Paste it here and we'll check it for you.",
    messageLabel: "Message text",
    messagePlaceholder: "Paste the SMS or email you received here...",
    urlLabel: "Or just the link",
    urlPlaceholder: "https://example.com",
    scan: "Scan Now",
    scanning: "Scanning...",
    needInput: "Please enter a link or paste a message.",
    invalidUrl: "This doesn't look like a valid link.",
    safe: "Looks Safe",
    safeDesc: "No warning signs found. This link passed all our checks.",
    medium: "Be Careful",
    mediumDesc: "Some warning signs found. Don't click unless you can verify the source.",
    high: "Dangerous",
    highDesc: "Strong phishing signals detected. Do not open this link.",
    whyTitle: "Why this result",
    urlInfoTitle: "Link details",
    originalUrl: "Short link",
    analyzedUrl: "Real destination",
    redirectChain: "Redirect path",
    mainDomain: "Main domain",
    reasons: "What we found",
    greenChecks: "Safety checks",
    statusPass: "Passed",
    statusFail: "Failed",
    statusNa: "N/A",
    footer: "Powered by Erlix"
  },
  he: {
    subtitle: "קיבלת הודעה חשודה או קישור מוזר? הדבק כאן ונבדוק בשבילך.",
    messageLabel: "טקסט ההודעה",
    messagePlaceholder: "הדבק כאן את ההודעה שקיבלת...",
    urlLabel: "או רק את הקישור",
    urlPlaceholder: "https://example.com",
    scan: "בדיקה",
    scanning: "בודק...",
    needInput: "יש להזין קישור או הודעה.",
    invalidUrl: "זה לא נראה כמו קישור תקין.",
    safe: "נראה בטוח",
    safeDesc: "לא נמצאו סימני אזהרה. הקישור עבר את כל הבדיקות שלנו.",
    medium: "יש לשים לב",
    mediumDesc: "נמצאו סימני אזהרה. לא ללחוץ לפני אימות מול המקור.",
    high: "מסוכן",
    highDesc: "זוהו סימנים חזקים לפישינג. לא לפתוח את הקישור.",
    whyTitle: "למה התקבלה התוצאה",
    urlInfoTitle: "פרטי הקישור",
    originalUrl: "קישור מקוצר",
    analyzedUrl: "היעד האמיתי",
    redirectChain: "מסלול הפניות",
    mainDomain: "דומיין ראשי",
    reasons: "מה מצאנו",
    greenChecks: "בדיקות אבטחה",
    statusPass: "עבר",
    statusFail: "נכשל",
    statusNa: "לא רלוונטי",
    footer: "מופעל על ידי Erlix"
  }
} as const;

/* ═══════════════════════════════════════
   I18N — REASON KEYS
   ═══════════════════════════════════════ */

const reasonI18n = {
  en: {
    invalid_url: "The link format looks invalid.",
    brand: "Looks like a known brand imitation.",
    suspicious_words: "Contains words commonly used in phishing.",
    lookalike_brand: "Domain name is almost identical to a known brand (one-character trick).",
    at_sign_userinfo: "URL uses '@' to hide the real destination.",
    case_confusable: "Domain mixes upper/lowercase to mislead.",
    mixed_scripts: "Link mixes different alphabets (common phishing trick).",
    unicode_lookalike: "Link uses lookalike Unicode characters.",
    punycode: "Link uses encoded international domain format.",
    suspicious_tld: "Uses a risky domain ending.",
    long_url: "The link is unusually long.",
    many_hyphens: "Too many dashes in the link.",
    no_https: "The link is not secure (no HTTPS).",
    message_pressure: "Message uses pressure/urgency language.",
    message_short_link: "Short message with a link can be suspicious.",
    message_aggressive: "Aggressive punctuation detected.",
    ai_social_engineering: "Social engineering pattern detected in the message.",
    ai_authority_impersonation: "Message appears to impersonate an official source.",
    ai_sensitive_request: "Message asks for sensitive action (login/payment).",
    ai_threat_or_reward: "Message uses threat or reward to push for action.",
    ai_model_social_engineering: "AI detected social-engineering intent.",
    ai_model_impersonation: "AI detected impersonation of a trusted source.",
    ai_model_sensitive_action: "AI detected request for sensitive user action.",
    ai_model_unavailable: "AI analysis temporarily unavailable.",
    vt_malicious: "Flagged as malicious by VirusTotal.",
    vt_suspicious: "Suspicious detections reported by VirusTotal.",
    vt_clean: "Clean result from VirusTotal.",
    vt_pending: "VirusTotal scan in progress.",
    vt_unavailable: "VirusTotal unavailable right now.",
    urlscan_malicious: "Flagged as malicious by URLScan.",
    urlscan_suspicious: "Suspicious indicators found by URLScan.",
    urlscan_clean: "Clean result from URLScan.",
    urlscan_pending: "URLScan analysis in progress.",
    urlscan_unavailable: "URLScan unavailable right now.",
    short_link_expanded: "Shortened link expanded to real destination.",
    short_link_unresolved: "Could not fully expand the shortened link.",
    insufficient_trust_signals: "Not enough trust signals for a safe verdict.",
    intel_configured: "Security data sources connected.",
    intel_missing: "Advanced security sources not connected."
  },
  he: {
    invalid_url: "פורמט הקישור לא תקין.",
    brand: "נראה כמו חיקוי של מותג מוכר.",
    suspicious_words: "מילים אופייניות לניסיונות פישינג.",
    lookalike_brand: "שם הדומיין כמעט זהה למותג מוכר (שינוי של תו אחד).",
    at_sign_userinfo: "הקישור משתמש ב-'@' כדי להסתיר את היעד האמיתי.",
    case_confusable: "הדומיין מערב אותיות גדולות וקטנות כדי להטעות.",
    mixed_scripts: "הקישור מערב כמה סוגי אותיות (טריק פישינג נפוץ).",
    unicode_lookalike: "נמצאו תווים דומים לאותיות רגילות.",
    punycode: "הקישור משתמש בקידוד דומיין בינלאומי.",
    suspicious_tld: "סיומת דומיין חשודה.",
    long_url: "הקישור ארוך בצורה חריגה.",
    many_hyphens: "יותר מדי מקפים בקישור.",
    no_https: "הקישור לא מאובטח.",
    message_pressure: "ניסוח מלחיץ או דחוף בהודעה.",
    message_short_link: "הודעה קצרה עם קישור יכולה להיות חשודה.",
    message_aggressive: "סימני פיסוק אגרסיביים.",
    ai_social_engineering: "זוהה דפוס הנדסה חברתית בהודעה.",
    ai_authority_impersonation: "ההודעה מתחזה לגורם רשמי.",
    ai_sensitive_request: "ההודעה מבקשת פעולה רגישה.",
    ai_threat_or_reward: "ההודעה משתמשת באיום או פיתוי.",
    ai_model_social_engineering: "מנוע AI זיהה כוונת הנדסה חברתית.",
    ai_model_impersonation: "מנוע AI זיהה חשד להתחזות.",
    ai_model_sensitive_action: "מנוע AI זיהה בקשה לפעולה רגישה.",
    ai_model_unavailable: "ניתוח AI אינו זמין כרגע.",
    vt_malicious: "סומן כזדוני על ידי VirusTotal.",
    vt_suspicious: "זוהו אינדיקציות חשודות ב-VirusTotal.",
    vt_clean: "VirusTotal לא מצא ממצאים.",
    vt_pending: "סריקת VirusTotal בתהליך.",
    vt_unavailable: "VirusTotal לא זמין כרגע.",
    urlscan_malicious: "סומן כזדוני על ידי URLScan.",
    urlscan_suspicious: "זוהו אינדיקציות חשודות ב-URLScan.",
    urlscan_clean: "URLScan לא מצא ממצאים.",
    urlscan_pending: "סריקת URLScan בתהליך.",
    urlscan_unavailable: "URLScan לא זמין כרגע.",
    short_link_expanded: "קישור מקוצר נחשף ליעד האמיתי.",
    short_link_unresolved: "לא ניתן היה לחשוף את יעד הקישור המקוצר.",
    insufficient_trust_signals: "אין מספיק אותות אמון לתוצאה בטוחה.",
    intel_configured: "מקורות מידע אבטחתי מחוברים.",
    intel_missing: "מקורות מידע אבטחתי מתקדמים לא מחוברים."
  }
} as const;

/* ═══════════════════════════════════════
   I18N — GREEN CHECK LABELS
   ═══════════════════════════════════════ */

const checkLabels: Record<string, Record<Language, string>> = {
  no_local_warnings: { en: "No suspicious URL signals", he: "ללא סימני אזהרה בקישור" },
  vt_clean: { en: "VirusTotal clean", he: "VirusTotal נקי" },
  urlscan_clean: { en: "URLScan clean", he: "URLScan נקי" },
  dns_resolves: { en: "DNS resolves", he: "DNS תקין" },
  tls_valid: { en: "HTTPS certificate valid", he: "תעודת HTTPS תקינה" },
  short_link_resolved: { en: "Short link resolved", he: "קישור מקוצר פוענח" },
};

/* ═══════════════════════════════════════
   HELPERS
   ═══════════════════════════════════════ */

const urlRegex = /^(https?:\/\/)?([^\s/$.?#].[^\s]*)$/i;
const detectedLanguage: Language = navigator.language.toLowerCase().startsWith("en") ? "en" : "he";

/* ═══════════════════════════════════════
   APP COMPONENT
   ═══════════════════════════════════════ */

export function App() {
  const [language, setLanguage] = useState<Language>(detectedLanguage);
  const [message, setMessage] = useState("");
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const t = translations[language];

  const riskVariant = (level: RiskLevel) =>
    level === "Low" ? "safe" : level === "Medium" ? "warn" : "danger";

  const riskIcon = (level: RiskLevel) =>
    level === "Low" ? "\u{1F6E1}\uFE0F" : level === "High" ? "\u26D4" : "\u26A0\uFE0F";

  const riskLabel = (level: RiskLevel) =>
    level === "Low" ? t.safe : level === "Medium" ? t.medium : t.high;

  const riskDesc = (level: RiskLevel) =>
    level === "Low" ? t.safeDesc : level === "Medium" ? t.mediumDesc : t.highDesc;

  const getGreenCheckLabel = (check: GreenCheck): string => {
    if (check.key === "domain_age_180d") {
      const base = language === "he" ? "גיל דומיין מעל 180 יום" : "Domain age over 180 days";
      return check.value != null ? `${base} (${check.value})` : base;
    }
    return checkLabels[check.key]?.[language] ?? check.key;
  };

  const getLocalizedReasons = (data: AnalysisResponse): string[] => {
    if (data.reason_keys?.length) {
      return data.reason_keys.map(
        (key) => reasonI18n[language][key as keyof (typeof reasonI18n)["en"]] ?? key
      );
    }
    return data.reasons;
  };

  const getReasonIcon = (key: string): string => {
    if (key.startsWith("vt_clean") || key.startsWith("urlscan_clean") || key === "short_link_expanded")
      return "\u2705";
    if (key.startsWith("vt_") || key.startsWith("urlscan_") || key.includes("malicious"))
      return "\u{1F6A8}";
    if (key.includes("ai_model") || key.includes("ai_social") || key.includes("ai_authority") || key.includes("ai_sensitive") || key.includes("ai_threat"))
      return "\u{1F916}";
    if (key.includes("message_"))
      return "\u{1F4AC}";
    return "\u{1F50D}";
  };

  const onAnalyze = async () => {
    const trimmed = url.trim();
    const trimmedMessage = message.trim();
    setError("");
    setResult(null);

    if (!trimmed && !trimmedMessage) {
      setError(t.needInput);
      return;
    }

    if (trimmed && !urlRegex.test(trimmed)) {
      setError(t.invalidUrl);
      return;
    }

    setLoading(true);
    try {
      const response = await fetch("http://localhost:5000/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: trimmed, message: trimmedMessage, language }),
      });

      if (!response.ok) throw new Error(`Status ${response.status}`);
      setResult(await response.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey && !loading) {
      e.preventDefault();
      onAnalyze();
    }
  };

  const v = result ? riskVariant(result.risk_level) : null;
  const hasRedirect = result?.redirect_chain && result.redirect_chain.length > 1;
  const hasUrlDiff = result?.submitted_url && result.submitted_url !== result.analyzed_url;

  return (
    <main className="page" dir={language === "he" ? "rtl" : "ltr"} lang={language}>
      {/* Language toggle */}
      <div className="lang-toggle">
        <button
          type="button"
          className={`lang-toggle__btn ${language === "en" ? "lang-toggle__btn--active" : ""}`}
          onClick={() => setLanguage("en")}
        >
          EN
        </button>
        <button
          type="button"
          className={`lang-toggle__btn ${language === "he" ? "lang-toggle__btn--active" : ""}`}
          onClick={() => setLanguage("he")}
        >
          עב
        </button>
      </div>

      {/* Header */}
      <header className="header">
        <div className="header__logo-wrap">
          <div className="header__logo-glow" />
          <img src="/logo.png" alt="Erlix" className="header__logo" />
        </div>
        <h1 className="header__title">LinkCheck</h1>
        <p className="header__subtitle">{t.subtitle}</p>
      </header>

      {/* Form card */}
      <section className="card">
        <div className="form-group">
          <label className="form-label" htmlFor="msg">{t.messageLabel}</label>
          <textarea
            id="msg"
            className="form-textarea"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder={t.messagePlaceholder}
            rows={4}
            onKeyDown={handleKeyDown}
          />
        </div>

        <div className="form-group">
          <label className="form-label" htmlFor="link">{t.urlLabel}</label>
          <input
            id="link"
            className="form-input"
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder={t.urlPlaceholder}
            dir="ltr"
            onKeyDown={handleKeyDown}
          />
        </div>

        <button type="button" className="scan-btn" onClick={onAnalyze} disabled={loading}>
          <span className="scan-btn__icon">{loading ? "" : "\u{1F6E1}\uFE0F"}</span>
          {loading ? t.scanning : t.scan}
        </button>

        {error && <p className="error-msg">{error}</p>}

        {/* Loading */}
        {loading && (
          <div className="scanner">
            <div className="scanner__ring" />
            <span className="scanner__text">{t.scanning}</span>
          </div>
        )}

        {/* Results */}
        {result && !loading && (
          <div className="verdict">
            {/* Risk banner */}
            <div className={`verdict__banner verdict__banner--${v}`}>
              <div className={`verdict__shield verdict__shield--${v}`}>
                {riskIcon(result.risk_level)}
              </div>
              <div>
                <div className={`verdict__label verdict__label--${v}`}>
                  {riskLabel(result.risk_level)}
                </div>
                <div className="verdict__sublabel">
                  {riskDesc(result.risk_level)}
                </div>
              </div>
            </div>

            {/* URL info */}
            {(hasUrlDiff || hasRedirect || (result.has_subdomains && result.registrable_domain)) && (
              <div className="result-section">
                <div className="result-section__title">{t.urlInfoTitle}</div>

                {hasUrlDiff && (
                  <>
                    <div className="url-row">
                      <span className="url-row__label">{t.originalUrl}</span>
                      <span className="url-row__value">{result.submitted_url}</span>
                    </div>
                    <div className="url-row">
                      <span className="url-row__label">{t.analyzedUrl}</span>
                      <span className="url-row__value">{result.analyzed_url}</span>
                    </div>
                  </>
                )}

                {result.has_subdomains && result.registrable_domain && (
                  <div className="url-row">
                    <span className="url-row__label">{t.mainDomain}</span>
                    <span className="url-row__value">{result.registrable_domain}</span>
                  </div>
                )}

                {hasRedirect && (
                  <>
                    <div className="url-row__label" style={{ marginTop: 8 }}>{t.redirectChain}</div>
                    {result.redirect_chain!.map((step, i) => (
                      <div key={i}>
                        {i > 0 && <div className="chain-step__arrow">&#8595;</div>}
                        <div className="chain-step">
                          <span className={`chain-step__dot ${i === result.redirect_chain!.length - 1 ? "chain-step__dot--final" : ""}`} />
                          <span className="chain-step__url">{step}</span>
                        </div>
                      </div>
                    ))}
                  </>
                )}
              </div>
            )}

            {/* Reasons */}
            <div className="result-section">
              <div className="result-section__title">{t.reasons}</div>
              {getLocalizedReasons(result).map((reason, i) => (
                <div className="reason-item" key={i}>
                  <span className="reason-item__icon">
                    {result.reason_keys?.[i] ? getReasonIcon(result.reason_keys[i]) : "\u{1F50D}"}
                  </span>
                  <span>{reason}</span>
                </div>
              ))}
            </div>

            {/* Green checks */}
            {result.green_checks?.length ? (
              <div className="result-section">
                <div className="result-section__title">{t.greenChecks}</div>
                <div className="checks-grid">
                  {result.green_checks.map((check) => (
                    <div className="check-row" key={check.key}>
                      <span className={`check-row__indicator check-row__indicator--${check.status}`}>
                        {check.status === "pass" ? "\u2713" : check.status === "fail" ? "!" : "\u2013"}
                      </span>
                      <span className="check-row__text">{getGreenCheckLabel(check)}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            {/* Intel note */}
            {result.intel_note && <div className="intel-note">{result.intel_note}</div>}
          </div>
        )}
      </section>

      {/* Footer */}
      <footer className="footer">
        <p className="footer__text">{t.footer}</p>
      </footer>
    </main>
  );
}
