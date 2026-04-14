import { useState } from "react";

type RiskLevel = "Medium" | "High";

type AnalysisResponse = {
  score: number;
  risk_level: RiskLevel;
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
    medium: "Medium",
    high: "High",
    score: "Score",
    scoreWithValue: "Score: {value}/100",
    reasons: "Reasons",
    analyzedUrl: "Analyzed URL",
    explanationTitle: "Why this result"
    ,
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
    medium: "בינונית",
    high: "גבוהה",
    score: "ציון",
    scoreWithValue: "ציון: {value}/100",
    reasons: "סיבות",
    analyzedUrl: "קישור שנותח",
    explanationTitle: "למה התקבלה התוצאה"
    ,
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
    lookalike_brand: "Link looks like a fake brand/domain imitation.",
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
    intel_configured: "Security data sources are connected.",
    intel_missing: "Advanced security sources are not connected yet."
  },
  he: {
    invalid_url: "פורמט הקישור נראה לא תקין.",
    brand: "נראה כמו התחזות למותג מוכר.",
    suspicious_words: "יש מילים אופייניות לניסיונות פישינג.",
    lookalike_brand: "נראה שהקישור מחקה דומיין/מותג אמיתי.",
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
    if (riskLevel === "Medium") return "risk-medium";
    return "risk-high";
  };

  const getRiskLabel = (riskLevel: RiskLevel): string => {
    if (riskLevel === "Medium") return t.medium;
    return t.high;
  };

  const getRiskIcon = (riskLevel: RiskLevel): string => {
    if (riskLevel === "High") return "⛔";
    return "⚠️";
  };

  const getScoreLabel = (scoreValue: number): string =>
    t.scoreWithValue.replace("{value}", String(scoreValue));

  const getExplanationText = (riskLevel: RiskLevel): string => {
    if (riskLevel === "High") return t.explainHigh;
    return t.explainMedium;
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
    <main className="page">
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
            <p>
              <strong>{t.explanationTitle}:</strong>{" "}
              {result.explanation ?? getExplanationText(result.risk_level)}
            </p>
            {result.analyzed_url && (
              <p>
                {t.analyzedUrl}: <code>{result.analyzed_url}</code>
              </p>
            )}
            <p>{t.reasons}:</p>
            <ul>
              {getLocalizedReasons(result).map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
            {result.intel_note && <p>{result.intel_note}</p>}
          </div>
        )}
      </section>
    </main>
  );
}
