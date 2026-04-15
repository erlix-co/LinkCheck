import { useState } from "react";

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
  reason_keys?: string[];
  reasons: string[];
  explanation?: string;
  intel_note?: string;
  analyzed_url?: string;
};

type Language = "en" | "he";

const translations = {
  en: {
    title: "LinkCheck",
    subtitle: "Analyze a URL or full message for phishing risk.",
    language: "Language",
    english: "English",
    hebrew: "Hebrew",
    messageLabel: "Full message (optional)",
    messagePlaceholder:
      "Paste the full SMS/email text here. If it contains a link, we will extract and analyze it.",
    urlLabel: "URL (optional)",
    urlPlaceholder: "https://example.com",
    analyze: "Analyze",
    analyzing: "Analyzing...",
    needInput: "Please enter a URL or a full message.",
    invalidUrl: "Invalid URL format. Try something like https://example.com",
    riskLevel: "Risk Level",
    low: "Safe",
    medium: "Medium",
    high: "High",
    score: "Score",
    scoreWithValue: "Score: {value}/100",
    reasons: "Reasons",
    originalUrl: "Shortened URL",
    analyzedUrl: "Real full URL",
    redirectChain: "Redirect chain",
    explanationTitle: "Why this result"
    ,
    greenConditions: "Green safety conditions",
    statusPass: "Pass",
    statusFail: "Missing",
    statusNa: "Not available",
    explainNotHigh: "There are warning signs, but not enough for high risk. Treat this link carefully.",
    explainMedium: "Several warning signs were found. Avoid clicking unless verified from an official source.",
    explainHigh: "Strong phishing indicators were found. Do not open this link."
  },
  he: {
    title: "LinkCheck",
    subtitle: "ניתוח קישור או הודעה מלאה לזיהוי סיכון פישינג.",
    language: "שפה",
    english: "אנגלית",
    hebrew: "עברית",
    messageLabel: "הודעה מלאה (אופציונלי)",
    messagePlaceholder:
      "הדבק כאן את כל הודעת ה-SMS/אימייל. אם יש בה לינק, נחלץ אותו לניתוח.",
    urlLabel: "קישור (אופציונלי)",
    urlPlaceholder: "https://example.com",
    analyze: "בדיקה",
    analyzing: "בודק...",
    needInput: "יש להזין קישור או הודעה מלאה.",
    invalidUrl: "פורמט קישור לא תקין. לדוגמה: https://example.com",
    riskLevel: "רמת סיכון",
    low: "בטוח",
    medium: "בינונית",
    high: "גבוהה",
    score: "ציון",
    scoreWithValue: "ציון: {value}/100",
    reasons: "סיבות",
    originalUrl: "קישור מקוצר",
    analyzedUrl: "הקישור האמיתי המלא",
    redirectChain: "שרשרת הפניות",
    explanationTitle: "למה התקבלה התוצאה"
    ,
    greenConditions: "תנאים למצב ירוק",
    statusPass: "עבר",
    statusFail: "חסר",
    statusNa: "לא זמין",
    explainNotHigh: "זוהו סימני אזהרה, אבל לא ברמה גבוהה. מומלץ להתייחס לקישור בזהירות.",
    explainMedium: "זוהו כמה סימני אזהרה משמעותיים. לא ללחוץ לפני אימות מול מקור רשמי.",
    explainHigh: "זוהו סימנים חזקים לפישינג. לא לפתוח את הקישור."
  }
} as const;

const reasonI18n = {
  en: {
    invalid_url: "The link format looks invalid.",
    brand: "Looks like a known brand imitation.",
    suspicious_words: "Contains words commonly used in phishing.",
    lookalike_brand: "Domain name is almost identical to a known brand/domain (one-character trick).",
    case_confusable: "Domain uses mixed uppercase/lowercase letters to mimic another character.",
    mixed_scripts: "Link mixes different alphabets (common phishing trick).",
    unicode_lookalike: "Link uses lookalike Unicode characters.",
    punycode: "Link uses encoded international domain format (IDN).",
    suspicious_tld: "Uses a risky domain ending.",
    long_url: "The link is unusually long.",
    many_hyphens: "Too many '-' signs in the link.",
    no_https: "The link is not secure (no HTTPS).",
    message_pressure: "The message uses pressure or urgency language.",
    message_short_link: "Short message with a link can be suspicious.",
    message_aggressive: "Aggressive punctuation detected.",
    vt_malicious: "VirusTotal reports this link as malicious.",
    vt_suspicious: "VirusTotal reports suspicious detections for this link.",
    vt_clean: "VirusTotal did not report malicious detections for this link.",
    vt_pending: "VirusTotal scan started; results are still pending.",
    vt_unavailable: "VirusTotal could not be reached right now.",
    urlscan_malicious: "URLScan flagged this link as malicious.",
    urlscan_suspicious: "URLScan detected suspicious indicators for this link.",
    urlscan_clean: "URLScan did not find malicious indicators for this link.",
    urlscan_pending: "URLScan scan started; results are still pending.",
    urlscan_unavailable: "URLScan could not be reached right now.",
    short_link_expanded: "Shortened link was expanded to its real destination.",
    short_link_unresolved: "Could not fully expand the shortened link destination.",
    insufficient_trust_signals: "Not enough trust signals for a green/safe result.",
    intel_configured: "Security data sources are connected.",
    intel_missing: "Advanced security sources are not connected yet."
  },
  he: {
    invalid_url: "פורמט הקישור נראה לא תקין.",
    brand: "נראה כמו התחזות למותג מוכר.",
    suspicious_words: "יש מילים אופייניות לניסיונות פישינג.",
    lookalike_brand: "שם הדומיין כמעט זהה למותג/דומיין מוכר (טריק של שינוי תו אחד).",
    case_confusable: "הדומיין משתמש בערבוב אותיות גדולות/קטנות כדי להטעות חזותית.",
    mixed_scripts: "הקישור מערב כמה סוגי אותיות (טריק פישינג נפוץ).",
    unicode_lookalike: "בקישור יש תווי יוניקוד דומים לאותיות רגילות.",
    punycode: "הקישור משתמש בפורמט דומיין מקודד (IDN).",
    suspicious_tld: "סיומת הדומיין נחשבת חשודה.",
    long_url: "הקישור ארוך בצורה חריגה.",
    many_hyphens: "יש יותר מדי סימני '-' בקישור.",
    no_https: "הקישור לא מאובטח (ללא HTTPS).",
    message_pressure: "יש בהודעה ניסוח מלחיץ או דחוף.",
    message_short_link: "הודעה קצרה עם קישור יכולה להיות חשודה.",
    message_aggressive: "נמצאו סימני פיסוק אגרסיביים.",
    vt_malicious: "VirusTotal מדווח שהקישור זדוני.",
    vt_suspicious: "VirusTotal מדווח על אינדיקציות חשודות לקישור.",
    vt_clean: "VirusTotal לא מצא אינדיקציות זדוניות בקישור.",
    vt_pending: "נסרקה בקשה ל-VirusTotal, התוצאה עדיין מתעדכנת.",
    vt_unavailable: "לא ניתן היה להגיע ל-VirusTotal כרגע.",
    urlscan_malicious: "URLScan סימן את הקישור כזדוני.",
    urlscan_suspicious: "URLScan זיהה אינדיקציות חשודות בקישור.",
    urlscan_clean: "URLScan לא מצא אינדיקציות זדוניות בקישור.",
    urlscan_pending: "נסרקה בקשה ל-URLScan, התוצאה עדיין מתעדכנת.",
    urlscan_unavailable: "לא ניתן היה להגיע ל-URLScan כרגע.",
    short_link_expanded: "לינק מקוצר נחשף ליעד האמיתי שלו.",
    short_link_unresolved: "לא ניתן היה לחשוף במלואו את היעד של הלינק המקוצר.",
    insufficient_trust_signals: "אין מספיק אותות אמון כדי לתת מצב ירוק/בטוח.",
    intel_configured: "מקורות מידע אבטחתי מחוברים.",
    intel_missing: "מקורות מידע אבטחתי מתקדמים עדיין לא מחוברים."
  }
} as const;

const urlRegex = /^(https?:\/\/)?([\w-]+\.)+[\w-]+([/?#].*)?$/i;
const detectedLanguage: Language = navigator.language.toLowerCase().startsWith("he") ? "he" : "en";

export function App() {
  const [language, setLanguage] = useState<Language>(detectedLanguage);
  const [message, setMessage] = useState("");
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const t = translations[language];

  const getRiskClass = (riskLevel: RiskLevel): string => {
    if (riskLevel === "Low") return "risk-low";
    if (riskLevel === "Medium") return "risk-medium";
    return "risk-high";
  };

  const getRiskLabel = (riskLevel: RiskLevel): string => {
    if (riskLevel === "Low") return t.low;
    if (riskLevel === "Medium") return t.medium;
    return t.high;
  };

  const getRiskIcon = (riskLevel: RiskLevel): string => {
    if (riskLevel === "Low") return "✅";
    if (riskLevel === "High") return "⛔";
    return "⚠️";
  };

  const getScoreLabel = (scoreValue: number): string =>
    t.scoreWithValue.replace("{value}", String(scoreValue));

  const getExplanationText = (riskLevel: RiskLevel): string => {
    if (riskLevel === "High") return t.explainHigh;
    if (riskLevel === "Low") return t.explainNotHigh;
    return t.explainMedium;
  };

  const getGreenCheckLabel = (check: GreenCheck): string => {
    if (check.key === "no_local_warnings") return language === "he" ? "ללא סימני אזהרה מקומיים" : "No local warning signals";
    if (check.key === "vt_clean") return language === "he" ? "VirusTotal נקי" : "VirusTotal clean result";
    if (check.key === "urlscan_clean") return language === "he" ? "URLScan נקי" : "URLScan clean result";
    if (check.key === "dns_resolves") return language === "he" ? "DNS נפתר בהצלחה" : "DNS resolves correctly";
    if (check.key === "tls_valid") return language === "he" ? "תעודת HTTPS תקינה" : "Valid HTTPS certificate";
    if (check.key === "short_link_resolved") return language === "he" ? "לינק מקוצר פוענח בהצלחה" : "Shortened link successfully resolved";
    if (check.key === "domain_age_180d") {
      if (language === "he") {
        return check.value != null ? `גיל דומיין מעל 180 יום (${check.value} ימים)` : "גיל דומיין מעל 180 יום";
      }
      return check.value != null ? `Domain age above 180 days (${check.value} days)` : "Domain age above 180 days";
    }
    return check.key;
  };

  const getLocalizedReasons = (data: AnalysisResponse): string[] => {
    if (data.reason_keys && data.reason_keys.length > 0) {
      return data.reason_keys.map((key) => reasonI18n[language][key as keyof (typeof reasonI18n)["en"]] ?? key);
    }
    return data.reasons;
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
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url: trimmed, message: trimmedMessage, language })
      });

      if (!response.ok) {
        throw new Error(`Request failed with status ${response.status}`);
      }

      const data: AnalysisResponse = await response.json();
      setResult(data);
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "Something went wrong while analyzing the URL."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="page" dir={language === "he" ? "rtl" : "ltr"} lang={language}>
      <section className="card">
        <h1>LinkCheck</h1>
        <p className="subtitle">{t.subtitle}</p>

        <div className="language-row">
          <span>{t.language}:</span>
          <button
            className="lang-btn"
            type="button"
            onClick={() => setLanguage("en")}
            disabled={language === "en"}
          >
            {t.english}
          </button>
          <button
            className="lang-btn"
            type="button"
            onClick={() => setLanguage("he")}
            disabled={language === "he"}
          >
            {t.hebrew}
          </button>
        </div>

        <label htmlFor="message-input">{t.messageLabel}</label>
        <textarea
          id="message-input"
          value={message}
          onChange={(event) => setMessage(event.target.value)}
          placeholder={t.messagePlaceholder}
          rows={5}
        />

        <label htmlFor="url-input">{t.urlLabel}</label>
        <input
          id="url-input"
          type="text"
          value={url}
          onChange={(event) => setUrl(event.target.value)}
          placeholder={t.urlPlaceholder}
        />

        <button type="button" onClick={onAnalyze} disabled={loading}>
          {loading ? t.analyzing : t.analyze}
        </button>

        {error && <p className="error">{error}</p>}

        {result && (
          <div className="result">
            <p>
              {t.riskLevel}:{" "}
              <span className={getRiskClass(result.risk_level)}>
                {getRiskIcon(result.risk_level)} {getRiskLabel(result.risk_level)}
              </span>
            </p>
            <p>
              {getScoreLabel(result.score)}
            </p>
            {result.risk_level !== "Low" && (
              <p>
                <strong>{t.explanationTitle}:</strong>{" "}
                {result.explanation ?? getExplanationText(result.risk_level)}
              </p>
            )}
            {result.submitted_url && result.submitted_url !== result.analyzed_url && (
              <p className="mixed-line">
                {t.originalUrl}: <code>{result.submitted_url}</code>
              </p>
            )}
            {result.analyzed_url && (
              <p className="mixed-line">
                {t.analyzedUrl}: <code>{result.analyzed_url}</code>
              </p>
            )}
            {result.redirect_chain && result.redirect_chain.length > 1 && (
              <>
                <p>{t.redirectChain}:</p>
                <ul className="reasons-list">
                  {result.redirect_chain.map((step) => (
                    <li key={step} className="mixed-line">
                      <code>{step}</code>
                    </li>
                  ))}
                </ul>
              </>
            )}
            <p>{t.reasons}:</p>
            <ul className="reasons-list">
              {getLocalizedReasons(result).map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
            {result.green_checks && result.green_checks.length > 0 && (
              <>
                <p>{t.greenConditions}:</p>
                <ul className="reasons-list">
                  {result.green_checks.map((check) => (
                    <li key={check.key}>
                      {check.status === "pass" ? "✅" : check.status === "fail" ? "⚠️" : "ℹ️"}{" "}
                      {getGreenCheckLabel(check)} -{" "}
                      {check.status === "pass"
                        ? t.statusPass
                        : check.status === "fail"
                          ? t.statusFail
                          : t.statusNa}
                    </li>
                  ))}
                </ul>
              </>
            )}
            {result.intel_note && <p className="mixed-line">{result.intel_note}</p>}
          </div>
        )}
      </section>
    </main>
  );
}
