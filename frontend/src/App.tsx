import { useState } from "react";

type RiskLevel = "Low" | "Medium" | "High";

type AnalysisResponse = {
  score: number;
  risk_level: RiskLevel;
  reasons: string[];
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
    low: "Low",
    medium: "Medium",
    high: "High",
    score: "Score",
    scoreWithValue: "Score: {value}/100",
    reasons: "Reasons",
    analyzedUrl: "Analyzed URL"
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
    low: "נמוכה",
    medium: "בינונית",
    high: "גבוהה",
    score: "ציון",
    scoreWithValue: "ציון: {value}/100",
    reasons: "סיבות",
    analyzedUrl: "קישור שנותח"
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

  const getScoreLabel = (scoreValue: number): string =>
    t.scoreWithValue.replace("{value}", String(scoreValue));

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
              <span className={getRiskClass(result.risk_level)}>{getRiskLabel(result.risk_level)}</span>
            </p>
            <p>
              {getScoreLabel(result.score)}
            </p>
            {result.analyzed_url && (
              <p>
                {t.analyzedUrl}: <code>{result.analyzed_url}</code>
              </p>
            )}
            <p>{t.reasons}:</p>
            <ul>
              {result.reasons.map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          </div>
        )}
      </section>
    </main>
  );
}
