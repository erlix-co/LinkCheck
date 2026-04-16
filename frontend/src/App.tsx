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
  decoded_url?: string;
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
    decodedUrl: "Readable link after decoding",
    redirectChain: "Redirect path",
    mainDomain: "Main domain",
    reasons: "What affected the result",
    greenChecks: "Trust and safety checks",
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
    decodedUrl: "הקישור אחרי פענוח",
    redirectChain: "מסלול הפניות",
    mainDomain: "דומיין ראשי",
    reasons: "מה השפיע על התוצאה",
    greenChecks: "בדיקות אמון ובטיחות",
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
    brand: "The link looks like it may be imitating a known brand.",
    suspicious_words: "The link contains words often used in scam or phishing messages.",
    lookalike_brand: "The site name looks very similar to a well-known brand or website.",
    at_sign_userinfo: "The link uses a trick to hide the real destination.",
    case_confusable: "The site name uses confusing letter shapes to mislead people.",
    mixed_scripts: "The link mixes different alphabets, which is a common scam trick.",
    unicode_lookalike: "The link uses characters that look normal but may be misleading.",
    punycode: "The link uses an encoded domain format that can hide misleading characters.",
    suspicious_tld: "The link uses a domain ending that is more commonly abused.",
    long_url: "The link is unusually long, which can be used to hide suspicious parts.",
    many_hyphens: "The link contains many dashes, which can be a warning sign.",
    no_https: "The link is not protected with secure HTTPS.",
    message_pressure: "The message tries to create pressure or urgency.",
    message_short_link: "A very short message with a link can be suspicious.",
    message_aggressive: "The message uses aggressive punctuation to push quick action.",
    ai_social_engineering: "The message looks like it is trying to pressure the reader into acting quickly.",
    ai_authority_impersonation: "The message may be pretending to come from an official company or service.",
    ai_sensitive_request: "The message asks for a sensitive action like login, payment, or verification.",
    ai_threat_or_reward: "The message uses fear or temptation to push action.",
    ai_model_social_engineering: "AI found signs of manipulation or pressure in the message.",
    ai_model_impersonation: "AI found signs that the message may be pretending to be from a trusted source.",
    ai_model_sensitive_action: "AI found a request for a sensitive user action.",
    ai_model_unavailable: "AI message analysis is temporarily unavailable.",
    vt_malicious: "Global virus and threat databases marked this link as malicious.",
    vt_suspicious: "Global virus and threat databases found suspicious signs for this link.",
    vt_clean: "Global virus and threat databases did not report this link as malicious.",
    vt_pending: "A check in global threat databases has started and is still updating.",
    vt_unavailable: "Global threat database check is unavailable right now.",
    urlscan_malicious: "A global website scanning service marked this link as malicious.",
    urlscan_suspicious: "A global website scanning service found suspicious signs.",
    urlscan_clean: "A global website scanning service did not find malicious signs.",
    urlscan_pending: "A global website scanning service is still checking this link.",
    urlscan_unavailable: "Website scanning service is unavailable right now.",
    short_link_expanded: "The shortened link was opened to reveal its real destination.",
    short_link_unresolved: "The shortened link could not be fully opened to its final destination.",
    insufficient_trust_signals: "There were not enough trust signals to mark this link as safe.",
    intel_configured: "Advanced security sources are connected.",
    intel_missing: "Some advanced security sources are not connected yet."
  },
  he: {
    invalid_url: "פורמט הקישור לא תקין.",
    brand: "הקישור נראה כמו ניסיון לחקות מותג מוכר.",
    suspicious_words: "בקישור יש מילים שמופיעות הרבה בהונאות ופישינג.",
    lookalike_brand: "שם האתר דומה מאוד למותג או לאתר מוכר.",
    at_sign_userinfo: "הקישור משתמש בטריק שמסתיר את היעד האמיתי.",
    case_confusable: "שם האתר משתמש בצורת אותיות מבלבלת כדי להטעות.",
    mixed_scripts: "הקישור מערב כמה סוגי אותיות, וזה טריק נפוץ בהונאות.",
    unicode_lookalike: "בקישור יש תווים שנראים רגילים, אבל עלולים להטעות.",
    punycode: "הקישור משתמש בפורמט מקודד שיכול להסתיר תווים מטעים.",
    suspicious_tld: "סיומת הדומיין הזאת נפוצה יותר בקישורים בעייתיים.",
    long_url: "הקישור ארוך מהרגיל, ולעיתים זה משמש להסתרת חלקים חשודים.",
    many_hyphens: "יש הרבה מקפים בקישור, וזה יכול להיות סימן אזהרה.",
    no_https: "הקישור אינו מוגן ב-HTTPS מאובטח.",
    message_pressure: "בהודעה יש לחץ או דחיפות.",
    message_short_link: "הודעה קצרה מאוד עם קישור יכולה להיות חשודה.",
    message_aggressive: "בהודעה יש סימני פיסוק אגרסיביים שמנסים לדחוף לפעולה מהירה.",
    ai_social_engineering: "נראה שההודעה מנסה להלחיץ את הקורא כדי שיפעל מהר.",
    ai_authority_impersonation: "נראה שההודעה מנסה להיראות כאילו נשלחה מגוף רשמי או מוכר.",
    ai_sensitive_request: "ההודעה מבקשת פעולה רגישה כמו התחברות, תשלום או אימות.",
    ai_threat_or_reward: "ההודעה משתמשת באיום או בפיתוי כדי לגרום לפעולה.",
    ai_model_social_engineering: "מנוע ה-AI מצא בהודעה סימנים ללחץ או מניפולציה.",
    ai_model_impersonation: "מנוע ה-AI מצא סימנים לכך שההודעה אולי מתחזה לגורם אמין.",
    ai_model_sensitive_action: "מנוע ה-AI מצא בקשה לפעולה רגישה מצד המשתמש.",
    ai_model_unavailable: "בדיקת ה-AI של ההודעה אינה זמינה כרגע.",
    vt_malicious: "בדיקה במאגרי וירוסים ואיומים עולמיים סימנה את הקישור כזדוני.",
    vt_suspicious: "בדיקה במאגרי וירוסים ואיומים עולמיים מצאה סימנים חשודים בקישור.",
    vt_clean: "בדיקה במאגרי וירוסים ואיומים עולמיים לא מצאה שהקישור זדוני.",
    vt_pending: "בדיקה במאגרי וירוסים ואיומים עולמיים התחילה ועדיין מתעדכנת.",
    vt_unavailable: "בדיקה במאגרי האיומים העולמיים אינה זמינה כרגע.",
    urlscan_malicious: "שירות עולמי לסריקת אתרים סימן את הקישור כזדוני.",
    urlscan_suspicious: "שירות עולמי לסריקת אתרים מצא סימנים חשודים בקישור.",
    urlscan_clean: "שירות עולמי לסריקת אתרים לא מצא סימנים זדוניים.",
    urlscan_pending: "שירות עולמי לסריקת אתרים עדיין בודק את הקישור.",
    urlscan_unavailable: "שירות סריקת האתרים אינו זמין כרגע.",
    short_link_expanded: "הקישור המקוצר נפתח ונחשף היעד האמיתי שלו.",
    short_link_unresolved: "לא הצלחנו לפתוח את הקישור המקוצר עד ליעד הסופי שלו.",
    insufficient_trust_signals: "לא היו מספיק סימני אמון כדי לסמן את הקישור כבטוח.",
    intel_configured: "מקורות בדיקה מתקדמים מחוברים.",
    intel_missing: "חלק ממקורות הבדיקה המתקדמים עדיין לא מחוברים."
  }
} as const;

/* ═══════════════════════════════════════
   I18N — GREEN CHECK LABELS
   ═══════════════════════════════════════ */

const checkLabels: Record<string, Record<Language, string>> = {
  no_local_warnings: { en: "Suspicious signs in the link itself", he: "סימנים חשודים בקישור עצמו" },
  vt_clean: { en: "Check in global virus and threat databases", he: "בדיקה במאגרי וירוסים ואיומים עולמיים" },
  urlscan_clean: { en: "Global website behavior scan", he: "סריקה עולמית של התנהגות האתר" },
  dns_resolves: { en: "Website address is active on the internet", he: "כתובת האתר פעילה ברשת" },
  tls_valid: { en: "Secure HTTPS certificate", he: "תעודת HTTPS מאובטחת ותקינה" },
  short_link_resolved: { en: "Shortened link opened to real destination", he: "פתיחת הקישור המקוצר עד ליעד האמיתי" },
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
      const base = language === "he" ? "ותק האתר מעל 180 יום" : "Website age over 180 days";
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
  const hasDecodedDiff = result?.decoded_url && result.decoded_url !== result.analyzed_url;

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
            {(hasUrlDiff || hasDecodedDiff || hasRedirect || (result.has_subdomains && result.registrable_domain)) && (
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

                {hasDecodedDiff && (
                  <div className="url-row">
                    <span className="url-row__label">{t.decodedUrl}</span>
                    <span className="url-row__value">{result.decoded_url}</span>
                  </div>
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
                        {check.status === "pass" ? "V" : check.status === "fail" ? "X" : "-"}
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
