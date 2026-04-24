import { useEffect, useRef, useState } from "react";
import { CONTACT_EMAIL } from "./data/termsOfUse";
import { FooterLegal, ReportIssueModal, TermsInline, TermsModal } from "./TermsUi";
import linkCheckLogo from "../Logo LinkCheck smal.png";

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
  lookalike_target?: string;
  lookalike_seen?: string;
  brand_target?: string;
  case_confusable_char?: string;
  case_confusable_lower_host?: string;
  mixed_scripts_char?: string;
  unicode_lookalike_char?: string;
  domain_tld?: string;
  tld_country_code?: string;
  page_audience?: string;
  domain_verdict?: {
    url?: string;
    risk_level?: RiskLevel;
    score?: number;
    is_safe?: boolean;
    reason_keys?: string[];
  };
  link_verdict?: {
    url?: string;
    risk_level?: RiskLevel;
    score?: number;
    is_safe?: boolean;
    reason_keys?: string[];
  };
  ai_model_summary?: string;
};

type LiveStep = {
  key: string;
  label: string;
  status: "done" | "in_progress" | "pending";
};

type LiveMeta = {
  analysis_id: string;
  final: boolean;
  stage: number;
  progress: number;
  risk_level: RiskLevel;
  status_text: string;
  steps: LiveStep[];
};

type Language = "en" | "he";
type ScanPayload = {
  url: string;
  message: string;
  language: Language;
};

/* ═══════════════════════════════════════
   I18N — UI STRINGS
   ═══════════════════════════════════════ */

const translations = {
  en: {
    subtitle: "Got a suspicious link or message? Paste it here and we'll check it for you.",
    betaBadge: "Beta",
    betaNotice:
      "Experimental version — results are estimates only and are not guaranteed. Do not rely on this tool as your only protection.",
    messageLabel: "Message text",
    messagePlaceholder: "Paste the SMS or email you received here...",
    urlLabel: "Or just the link",
    urlPlaceholder: "https://example.com",
    scan: "Scan Now",
    scanning: "Scanning...",
    scanHint: "",
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
    redirectPathToggle: "Show redirect path",
    mainDomain: "Main domain",
    shownSubdomain: "Shown subdomain",
    siteLocation: "Website location",
    locationUnknown: "Unknown",
    reasons: "What affected the result",
    greenChecks: "Trust and safety checks",
    splitVerdictTitle: "Domain vs specific link",
    domainVerdictSafe: "The main domain looks safe.",
    domainVerdictWarn: "The main domain needs caution.",
    linkVerdictSafe: "This specific link looks safe.",
    linkVerdictWarn: "This specific link needs caution.",
    fullLinksToggle: "Show full links",
    fullLinksTitle: "Full links",
    statusPass: "Passed",
    statusFail: "Failed",
    statusNa: "N/A",
    footer: "Powered by Erlix",
    footerTerms: "Terms of use",
    footerContact: "Contact",
    footerReport: "Report an issue",
    termsRequired: "Please accept the Terms of Use to run a check.",
    contactLine: `Contact: ${CONTACT_EMAIL}`,
    reportTitle: "Report an issue",
    reportContextTitle: "Included with your report (from this page):",
    reportContextEmpty: "No link or message in the scan fields — your description below is still sent.",
    reportContextUrlLabel: "Link",
    reportContextMessageLabel: "Message",
    reportIncludeInReport: "Include in report",
    reportExcludedFromReport: "Not included in this report.",
    reportIntro: "Describe what happened and send your report from this page.",
    reportViaEmailOnly: "Report via email only",
    reportViaEmailOnlyHint:
      "Opens your mail app with this page’s URL and message — you write there.",
    reportFormSection: "Your report:",
    reportLabel: "What went wrong?",
    reportPlaceholder: "e.g. wrong risk level, slow response, error message…",
    reportSend: "Send report",
    reportSending: "Sending…",
    reportSuccess: "Report sent. Thank you.",
    reportSuccessViaMail:
      "Email is not sent from our server. Tap below to open your mail app with the text you wrote, then send.",
    reportFail: "Could not send. Try again later.",
    reportUnavailable: "Reporting is not available right now. Please contact the site operator.",
    reportOpenMail: "Open email app",
    reportClose: "Close",
    liveStatus: "Results are updated in real time as more data is analyzed",
    waitingExternal: "Waiting for external analysis...",
    analysisCompleted: "Analysis completed.",
    analysisSteps: "Analysis steps",
    parallelCheckNotice: "The check runs across multiple servers in parallel and usually takes about half a minute.",
    countdownLabel: "Estimated time left",
    liveRateLimited: "Too many checks were sent in a short time. Please wait a few seconds and try again.",
    liveNetworkSlow: "The network is slow or unstable. Please try again.",
    liveServerUnavailable: "The service is temporarily unavailable. Please try again shortly.",
    partialResultNotice: "External checks are still updating. Showing the latest available result for now.",
    pendingIntelAutoStart: "External threat checks are still updating. We are refreshing this result automatically now.",
    pendingIntelAutoProgress: "Automatic update in progress",
    pendingIntelAutoDone: "External checks were updated automatically.",
    pendingIntelAutoStillPending: "Some external checks are still updating. Keep this page open; the current result is still valid for now.",
    forcedDisplayAfterTimeout: "External checks are still updating. Showing the latest available result now (after 60 seconds).",
  },
  he: {
    subtitle: "קיבלת הודעה חשודה או קישור מוזר? הדבק כאן ונבדוק בשבילך.",
    betaBadge: "גרסת ניסוי",
    betaNotice:
      "גרסת ניסוי — התוצאות הן הערכה בלבד ואינן מובטחות. אל תסתמך על הכלי כהגנה יחידה.",
    messageLabel: "טקסט ההודעה",
    messagePlaceholder: "הדבק כאן את ההודעה שקיבלת...",
    urlLabel: "או רק את הקישור",
    urlPlaceholder: "https://example.com",
    scan: "בדיקה",
    scanning: "בודק...",
    scanHint: "",
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
    redirectPathToggle: "הצג מסלול הפניות",
    mainDomain: "דומיין ראשי",
    shownSubdomain: "תת-הדומיין שמוצג",
    siteLocation: "האתר ממוקם ב",
    locationUnknown: "לא ידוע",
    reasons: "מה השפיע על התוצאה",
    greenChecks: "בדיקות אמון ובטיחות",
    splitVerdictTitle: "דומיין ראשי מול קישור ספציפי",
    domainVerdictSafe: "הדומיין הראשי נראה בטוח.",
    domainVerdictWarn: "הדומיין הראשי דורש זהירות.",
    linkVerdictSafe: "הקישור הספציפי נראה בטוח.",
    linkVerdictWarn: "הקישור הספציפי דורש זהירות.",
    fullLinksToggle: "הצג קישורים מלאים",
    fullLinksTitle: "קישורים מלאים",
    statusPass: "עבר",
    statusFail: "נכשל",
    statusNa: "לא רלוונטי",
    footer: "מופעל על ידי erlix.net",
    footerTerms: "תנאי שימוש",
    footerContact: "צור קשר",
    footerReport: "דיווח על תקלה",
    termsRequired: "יש לאשר את תנאי השימוש לפני ביצוע בדיקה.",
    contactLine: `צור קשר: ${CONTACT_EMAIL}`,
    reportTitle: "דיווח על תקלה",
    reportContextTitle: "יצורף לדיווח מהעמוד הזה:",
    reportContextEmpty: "לא הוזנו קישור או הודעה בשדות למעלה — רק התיאור למטה יישלח.",
    reportContextUrlLabel: "קישור",
    reportContextMessageLabel: "טקסט ההודעה",
    reportIncludeInReport: "לצרף לדיווח",
    reportExcludedFromReport: "לא יצורף לדיווח הזה.",
    reportIntro: "תאר את הבעיה ושלח את הדיווח מכאן.",
    reportViaEmailOnly: "דיווח ישיר במייל",
    reportViaEmailOnlyHint: "נפתח המייל עם הקשר מהדף — הכול נכתב באפליקציית המייל.",
    reportFormSection: "תיאור הדיווח:",
    reportLabel: "מה לא עבד?",
    reportPlaceholder: "לדוגמה: רמת סיכון שגויה, האתר איטי, הופיעה שגיאה…",
    reportSend: "שליחת דיווח",
    reportSending: "שולח…",
    reportSuccess: "הדיווח נשלח. תודה.",
    reportSuccessViaMail:
      "השליחה מהאתר לא זמינה. לחץ למטה לפתיחת המייל עם הטקסט שכתבת, ואז שלח.",
    reportFail: "לא הצלחנו לשלוח. נסה שוב מאוחר יותר.",
    reportUnavailable: "שליחת דיווח לא זמינה כרגע. פנה למפעיל האתר.",
    reportOpenMail: "פתיחת המייל",
    reportClose: "סגירה",
    liveStatus: "התוצאות מתעדכנות בזמן אמת ככל שנאסף מידע נוסף",
    waitingExternal: "ממתינים לניתוח חיצוני...",
    analysisCompleted: "הבדיקה הושלמה.",
    analysisSteps: "שלבי בדיקה",
    parallelCheckNotice: "הבדיקה מתבצעת במגוון שרתים במקביל, והיא לוקחת כחצי דקה.",
    countdownLabel: "זמן משוער לסיום",
    liveRateLimited: "נשלחו יותר מדי בדיקות בזמן קצר. אנא המתן כמה שניות ונסה שוב.",
    liveNetworkSlow: "החיבור איטי או לא יציב. אנא נסה שוב.",
    liveServerUnavailable: "השירות אינו זמין כרגע. אנא נסה שוב בעוד זמן קצר.",
    partialResultNotice: "הבדיקות החיצוניות עדיין מתעדכנות. מוצגת כרגע התוצאה העדכנית הזמינה.",
    pendingIntelAutoStart: "בדיקות האיומים החיצוניות עדיין מתעדכנות. אנחנו מרעננים את התוצאה אוטומטית כעת.",
    pendingIntelAutoProgress: "מרעננים אוטומטית",
    pendingIntelAutoDone: "הבדיקות החיצוניות עודכנו אוטומטית.",
    pendingIntelAutoStillPending: "חלק מהבדיקות החיצוניות עדיין בעדכון. אפשר להשאיר את הדף פתוח; התוצאה הנוכחית תקפה לעכשיו.",
    forcedDisplayAfterTimeout: "הבדיקות החיצוניות עדיין מתעדכנות. מוצגת עכשיו התוצאה העדכנית הזמינה (לאחר 60 שניות).",
  }
} as const;

/* ═══════════════════════════════════════
   I18N — REASON KEYS
   ═══════════════════════════════════════ */

const reasonI18n = {
  en: {
    invalid_url: "The link format looks invalid.",
    brand: "The link looks like it may be imitating a known brand.",
    brand_mismatch: "Brand appears in the link, but the real domain does not belong to that brand.",
    suspicious_words: "The link contains words often used in scam or phishing messages.",
    lookalike_brand: "The site name looks very similar to a well-known brand or website.",
    at_sign_userinfo: "The link uses a trick to hide the real destination.",
    case_confusable: "Suspicious mixed letter casing in the hostname.",
    mixed_scripts: "The hostname mixes scripts; a non-Latin lookalike character was flagged.",
    unicode_lookalike: "The hostname uses a Unicode letter that resembles Latin (homoglyph).",
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
    ai_subdomain_impersonation_combo: "AI detected social-engineering pressure combined with a potentially misleading subdomain.",
    domain_reputation_warning: "The main domain reputation increased the risk for this link.",
    ai_model_unavailable: "AI message analysis is temporarily unavailable.",
    vt_malicious: "Global virus and threat databases marked this link as malicious.",
    vt_single_vendor_flag: "Only one threat engine flagged this link. This is a weak signal and should be reviewed in context.",
    vt_suspicious: "Global virus and threat databases found suspicious signs for this link.",
    vt_clean: "Global virus and threat databases did not report this link as malicious.",
    vt_pending: "A check in global threat databases has started and is still updating.",
    vt_unavailable: "Global threat database check is unavailable right now.",
    urlscan_malicious: "A global website scanning service marked this link as malicious.",
    urlscan_suspicious: "A global website scanning service found suspicious signs.",
    urlscan_clean: "A global website scanning service did not find malicious signs.",
    urlscan_pending: "A global website scanning service is still checking this link.",
    urlscan_unavailable: "Website scanning service is unavailable right now.",
    gsb_malicious: "Google Safe Browsing flagged this link as unsafe.",
    gsb_suspicious: "Google Safe Browsing found suspicious threat indicators for this link.",
    gsb_clean: "Google Safe Browsing did not report this link as unsafe.",
    gsb_unavailable: "Google Safe Browsing check is unavailable right now.",
    short_link_expanded: "HTTP redirects were followed to the final URL.",
    short_http_to_https_caution:
      "The short link itself is not encrypted, but it redirects to a known secure destination. Prefer opening the full secure link directly.",
    short_https_to_http_downgrade:
      "The short link starts as secure HTTPS but ends at an unsecure page. Avoid entering personal details on the final page.",
    shortlink_use_original_recommended:
      "The final destination appears safe, but the short link itself adds uncertainty. Prefer using the original full link directly.",
    short_link_unresolved: "The full redirect chain could not be followed (error, loop, or blocked hop).",
    short_link_destination_blocked: "Redirects ended on a provider block or interstitial page; analysis uses the link you submitted.",
    hebrew_phishing_page_signals: "The page content in Hebrew includes phishing-style pressure/action terms.",
    hebrew_content_foreign_infra_mismatch: "The page is mainly Hebrew, but the domain infrastructure is atypical for Hebrew-targeted services.",
    tld_country_notice: "Domain suffix points to a specific country.",
    single_page_site: "The website appears to have only a single active page (very limited internal structure).",
    insufficient_trust_signals: "There were not enough trust signals to mark this link as safe.",
    intel_configured: "Advanced security sources are connected.",
    intel_missing: "Some advanced security sources are not connected yet."
  },
  he: {
    invalid_url: "פורמט הקישור לא תקין.",
    brand: "הקישור נראה כמו ניסיון לחקות מותג מוכר.",
    brand_mismatch: "שם מותג מופיע בקישור, אבל הדומיין האמיתי לא שייך למותג הזה.",
    suspicious_words: "בקישור יש מילים שמופיעות הרבה בהונאות ופישינג.",
    lookalike_brand: "שם האתר דומה מאוד למותג או לאתר מוכר.",
    at_sign_userinfo: "הקישור משתמש בטריק שמסתיר את היעד האמיתי.",
    case_confusable: "בשם המארח זוהתה בעיית ערבוב אותיות חשודה.",
    mixed_scripts: "בשם המארח מעורבים אלפביתים שונים; סומן תו שאינו אנגלית פשוטה.",
    unicode_lookalike: "בשם המארח יש אות יוניקוד שנראית כמו אנגלית (הומוגליף).",
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
    ai_subdomain_impersonation_combo: "מנוע ה-AI זיהה לחץ/מניפולציה יחד עם תת-דומיין שעשוי להטעות.",
    domain_reputation_warning: "מוניטין הדומיין הראשי העלה את רמת הסיכון לקישור הזה.",
    ai_model_unavailable: "בדיקת ה-AI של ההודעה אינה זמינה כרגע.",
    vt_malicious: "בדיקה במאגרי וירוסים ואיומים עולמיים סימנה את הקישור כזדוני.",
    vt_single_vendor_flag: "רק מנוע אחד סימן את הקישור כמסוכן.",
    vt_suspicious: "בדיקה במאגרי וירוסים ואיומים עולמיים מצאה סימנים חשודים בקישור.",
    vt_clean: "בדיקה במאגרי וירוסים ואיומים עולמיים לא מצאה שהקישור זדוני.",
    vt_pending: "בדיקה במאגרי וירוסים ואיומים עולמיים התחילה ועדיין מתעדכנת.",
    vt_unavailable: "בדיקה במאגרי האיומים העולמיים אינה זמינה כרגע.",
    urlscan_malicious: "שירות עולמי לסריקת אתרים סימן את הקישור כזדוני.",
    urlscan_suspicious: "שירות עולמי לסריקת אתרים מצא סימנים חשודים בקישור.",
    urlscan_clean: "שירות עולמי לסריקת אתרים לא מצא סימנים זדוניים.",
    urlscan_pending: "שירות עולמי לסריקת אתרים עדיין בודק את הקישור.",
    urlscan_unavailable: "שירות סריקת האתרים אינו זמין כרגע.",
    gsb_malicious: "Google Safe Browsing סימן את הקישור כלא בטוח.",
    gsb_suspicious: "Google Safe Browsing מצא אינדיקציות חשודות לקישור.",
    gsb_clean: "Google Safe Browsing לא סימן את הקישור כלא בטוח.",
    gsb_unavailable: "בדיקת Google Safe Browsing אינה זמינה כרגע.",
    short_link_expanded: "בוצע מעקב אחרי הפניות עד לכתובת היעד הסופית.",
    short_http_to_https_caution:
      "הקישור המקוצר עצמו אינו מוצפן, אך הוא מפנה ליעד מאובטח ומוכר. מומלץ לפתוח ישירות את הקישור המלא והמאובטח.",
    short_https_to_http_downgrade:
      "הקישור המקוצר התחיל כמאובטח, אך יעד הסיום אינו מאובטח. מומלץ לא להזין פרטים אישיים בדף היעד.",
    shortlink_use_original_recommended:
      "היעד הסופי נראה בטוח, אך קישור מקוצר מוסיף אי-ודאות. מומלץ להשתמש ישירות בקישור המלא המקורי.",
    short_link_unresolved: "לא ניתן היה למלא את שרשרת ההפניות (שגיאה, לולאה או צעד חסום).",
    short_link_destination_blocked: "ההפניות הסתיימו בדף חסימה או ביניים של ספק; הניתוח מבוסס על הקישור שהזנת.",
    hebrew_phishing_page_signals: "בתוכן הדף בעברית נמצאו מונחי לחץ או פעולה שמאפיינים פישינג.",
    hebrew_content_foreign_infra_mismatch: "התוכן בדף בעברית, אבל תשתית הדומיין לא אופיינית לשירות שפונה לקהל עברי.",
    tld_country_notice: "סיומת הדומיין מצביעה על מדינה מסוימת.",
    single_page_site: "נראה שלאתר יש דף פעיל יחיד בלבד (מבנה פנימי דל מאוד).",
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
  no_message_warnings: { en: "Suspicious signs in the message itself", he: "סימנים חשודים בהודעה עצמה" },
  vt_clean: { en: "Check in global virus and threat databases", he: "בדיקה במאגרי וירוסים ואיומים עולמיים" },
  urlscan_clean: { en: "Global website behavior scan", he: "סריקה עולמית של התנהגות האתר" },
  gsb_clean: { en: "Check in Google's Safe Browsing threat lists", he: "בדיקה במאגרי הגלישה הבטוחה של Google" },
  dns_resolves: { en: "Website address is active on the internet", he: "כתובת האתר פעילה ברשת" },
  tls_valid: { en: "Secure HTTPS certificate", he: "תעודת HTTPS מאובטחת ותקינה" },
  page_available: { en: "The specific page exists and is reachable", he: "הדף הספציפי קיים ונגיש" },
  short_link_resolved: {
    en: "Redirect chain resolved to final URL",
    he: "מעקב אחרי הפניות עד ליעד הסופי",
  },
};

/* ═══════════════════════════════════════
   HELPERS
   ═══════════════════════════════════════ */

const urlRegex = /^(https?:\/\/)?([^\s/$.?#].[^\s]*)$/i;
const detectedLanguage: Language = navigator.language.toLowerCase().startsWith("en") ? "en" : "he";
const defaultApiBaseUrl =
  typeof window !== "undefined"
    ? "/api"
    : "http://localhost:5000";
const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL || defaultApiBaseUrl).replace(/\/+$/, "");
const LIVE_START_TIMEOUT_MS = 12000;
const LIVE_STATUS_TIMEOUT_MS = 8000;
const FINAL_ANALYZE_TIMEOUT_MS = 35000;
const HARD_RESULT_TIMEOUT_MS = 60000;
const AUTO_INTEL_REFRESH_MAX_ATTEMPTS = 3;
const AUTO_INTEL_REFRESH_DELAY_MS = 4500;
const hasPendingExternalIntel = (data: AnalysisResponse | null): boolean =>
  Boolean(data?.reason_keys?.some((k) => k === "vt_pending" || k === "urlscan_pending"));
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function fetchWithTimeout(
  input: RequestInfo | URL,
  init: RequestInit,
  timeoutMs: number
): Promise<Response> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } finally {
    window.clearTimeout(timer);
  }
}

/* ═══════════════════════════════════════
   APP COMPONENT
   ═══════════════════════════════════════ */

export function App() {
  const [language, setLanguage] = useState<Language>(detectedLanguage);
  const [message, setMessage] = useState("");
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [liveMeta, setLiveMeta] = useState<LiveMeta | null>(null);
  const [countdownSec, setCountdownSec] = useState(40);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [showTermsModal, setShowTermsModal] = useState(false);
  const [showReportModal, setShowReportModal] = useState(false);
  const [lastScanPayload, setLastScanPayload] = useState<ScanPayload | null>(null);
  const [pendingIntelNotice, setPendingIntelNotice] = useState("");
  const [pendingIntelInProgress, setPendingIntelInProgress] = useState(false);
  const [hardDisplayReady, setHardDisplayReady] = useState(false);
  const pollTokenRef = useRef(0);
  const autoIntelRunRef = useRef(0);
  const autoIntelExhaustedTokenRef = useRef<number>(-1);
  const forceDisplayTimerRef = useRef<number | null>(null);
  const t = translations[language];

  useEffect(() => {
    if (!liveMeta || liveMeta.final || countdownSec <= 0) return;
    const timer = window.setTimeout(() => {
      setCountdownSec((prev) => Math.max(0, prev - 1));
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [liveMeta, countdownSec]);

  useEffect(() => {
    return () => {
      if (forceDisplayTimerRef.current != null) {
        window.clearTimeout(forceDisplayTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    // As soon as countdown reaches 00:00 (even before backend marks final),
    // show pending-external-checks notice immediately.
    if (!liveMeta || liveMeta.final || countdownSec > 0) return;
    if (!pendingIntelNotice) {
      setPendingIntelNotice(t.pendingIntelAutoStart);
    }
  }, [liveMeta, countdownSec, pendingIntelNotice, t]);

  useEffect(() => {
    if (!result || loading) return;
    const resultIsFinal = !liveMeta || liveMeta.final;
    if (!resultIsFinal) return;
    if (!lastScanPayload) return;
    if (autoIntelExhaustedTokenRef.current === pollTokenRef.current) return;
    if (!hasPendingExternalIntel(result)) {
      if (!pendingIntelInProgress) {
        setPendingIntelNotice("");
        autoIntelExhaustedTokenRef.current = -1;
      }
      return;
    }
    if (pendingIntelInProgress) return;

    let cancelled = false;
    const runId = autoIntelRunRef.current + 1;
    autoIntelRunRef.current = runId;
    setPendingIntelInProgress(true);
    setPendingIntelNotice(t.pendingIntelAutoStart);

    const refreshPendingIntel = async () => {
      for (let attempt = 1; attempt <= AUTO_INTEL_REFRESH_MAX_ATTEMPTS; attempt += 1) {
        await sleep(AUTO_INTEL_REFRESH_DELAY_MS);
        if (cancelled || runId !== autoIntelRunRef.current) return;
        setPendingIntelNotice(`${t.pendingIntelAutoProgress} ${attempt}/${AUTO_INTEL_REFRESH_MAX_ATTEMPTS}...`);

        try {
          const resp = await fetchWithTimeout(
            `${apiBaseUrl}/analyze`,
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(lastScanPayload),
            },
            FINAL_ANALYZE_TIMEOUT_MS
          );
          if (!resp.ok) continue;
          const refreshed = (await resp.json()) as AnalysisResponse;
          if (cancelled || runId !== autoIntelRunRef.current) return;
          setResult(refreshed);
          if (!hasPendingExternalIntel(refreshed)) {
            setPendingIntelNotice("");
            setPendingIntelInProgress(false);
            return;
          }
        } catch {
          // Keep trying until max attempts.
        }
      }

      if (!cancelled && runId === autoIntelRunRef.current) {
        setPendingIntelNotice(t.pendingIntelAutoStillPending);
        setPendingIntelInProgress(false);
        // Avoid infinite refresh loops on stubborn pending-only responses.
        autoIntelExhaustedTokenRef.current = pollTokenRef.current;
      }
    };

    void refreshPendingIntel();
    return () => {
      cancelled = true;
    };
  }, [result, loading, liveMeta, lastScanPayload, pendingIntelInProgress, t]);

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
    if (check.key === "page_available") {
      const base = checkLabels[check.key]?.[language] ?? check.key;
      return check.value != null ? `${base} (HTTP ${check.value})` : base;
    }
    return checkLabels[check.key]?.[language] ?? check.key;
  };

  const countryNameFromTld = (data: AnalysisResponse): string => {
    const code = (data.tld_country_code || "").trim().toUpperCase();
    if (!code) return "";
    try {
      const locale = language === "he" ? "he" : "en";
      const dn = new Intl.DisplayNames([locale], { type: "region" });
      return dn.of(code) || "";
    } catch {
      return "";
    }
  };

  const getLocalizedReasons = (data: AnalysisResponse): Array<{ key: string; text: string }> => {
    if (data.reason_keys?.length) {
      const filteredKeys = data.reason_keys.filter((key) => {
        if (!data.ai_model_summary) return true;
        return !["ai_model_social_engineering", "ai_model_impersonation", "ai_model_sensitive_action"].includes(key);
      });
      const priorityKeys = ["short_https_to_http_downgrade", "short_http_to_https_caution"];
      const orderedKeys = [
        ...priorityKeys.filter((k) => filteredKeys.includes(k)),
        ...filteredKeys.filter((k) => !priorityKeys.includes(k)),
      ];
      return orderedKeys.map((key) => {
        if (key === "lookalike_brand") {
          const target = (data.lookalike_target || "").trim();
          if (target) {
            if (language === "he") {
              return { key, text: `הקישור אינו ${target} אלא ניסיון חיקוי!` };
            }
            return { key, text: `This is not ${target}. It is likely an imitation attempt!` };
          }
        }
        if (key === "brand" || key === "brand_mismatch") {
          const target = (data.brand_target || "").trim();
          if (target) {
            if (language === "he") {
              return { key, text: `הקישור אינו ${target} אלא ניסיון חיקוי!` };
            }
            return { key, text: `This is not ${target}. It is likely an imitation attempt!` };
          }
        }
        if (key === "tld_country_notice") {
          const country = countryNameFromTld(data);
          if (country) {
            if (language === "he") return { key, text: `האתר ממקום ב: ${country}` };
            return { key, text: `Website is in: ${country}` };
          }
        }
        if (key === "case_confusable") {
          const suspiciousChar = (data.case_confusable_char || "").trim();
          const lowerHost = (data.case_confusable_lower_host || "").trim();
          if (suspiciousChar) {
            if (language === "he") {
              const tail = lowerHost ? ` צורה מנורמלת להשוואה: ${lowerHost}` : "";
              return {
                key,
                text: `בשם המארח מופיע התו «${suspiciousChar}» — אות גדולה באמצע שנועדה להיראות כמו אות קטנה.${tail}`,
              };
            }
            const tail = lowerHost ? ` Normalized form for comparison: ${lowerHost}` : "";
            return {
              key,
              text: `The hostname contains the misleading character «${suspiciousChar}» (mixed capitals).${tail}`,
            };
          }
        }
        if (key === "mixed_scripts") {
          const c = (data.mixed_scripts_char || "").trim();
          if (c) {
            if (language === "he") {
              return {
                key,
                text: `בשם המארח מופיע התו «${c}» — אות שאינה אנגלית ASCII פשוטה (\`a-z\`), והערבוב עם לטינית מעלה חשד להטעיה.`,
              };
            }
            return {
              key,
              text: `The hostname contains «${c}» — a non-plain-Latin letter mixed with Latin, which is a common spoofing trick.`,
            };
          }
        }
        if (key === "unicode_lookalike") {
          const c = (data.unicode_lookalike_char || "").trim();
          if (c) {
            if (language === "he") {
              return {
                key,
                text: `בשם המארח מופיע התו «${c}» — נראה כמו אות לטינית רגילה אך שייך לאלפבית אחר (הומוגליף).`,
              };
            }
            return {
              key,
              text: `The hostname contains «${c}» — a Unicode letter that looks like ordinary Latin but is not (homoglyph).`,
            };
          }
        }
        return { key, text: reasonI18n[language][key as keyof (typeof reasonI18n)["en"]] ?? key };
      });
    }
    return (data.reasons || []).map((text) => ({ key: "", text }));
  };

  const getReasonIcon = (key: string): string => {
    if (key === "short_http_to_https_caution" || key === "short_https_to_http_downgrade")
      return "\u26D4";
    if (
      key.startsWith("vt_clean") ||
      key.startsWith("urlscan_clean") ||
      key.startsWith("gsb_clean") ||
      key === "short_link_expanded"
    )
      return "\u2705";
    if (key === "short_link_destination_blocked") return "\u26A0\uFE0F";
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
    pollTokenRef.current += 1;
    const runToken = pollTokenRef.current;
    const clearForceDisplayTimer = () => {
      if (forceDisplayTimerRef.current != null) {
        window.clearTimeout(forceDisplayTimerRef.current);
        forceDisplayTimerRef.current = null;
      }
    };
    autoIntelRunRef.current += 1;
    autoIntelExhaustedTokenRef.current = -1;
    setError("");
    setResult(null);
    setLiveMeta(null);
    setCountdownSec(40);
    setPendingIntelInProgress(false);
    setPendingIntelNotice("");
    setHardDisplayReady(false);
    setLastScanPayload({ url: trimmed, message: trimmedMessage, language });

    if (!termsAccepted) {
      setError(t.termsRequired);
      return;
    }

    if (!trimmed && !trimmedMessage) {
      setError(t.needInput);
      return;
    }

    if (trimmed && !urlRegex.test(trimmed)) {
      setError(t.invalidUrl);
      return;
    }

    clearForceDisplayTimer();
    forceDisplayTimerRef.current = window.setTimeout(() => {
      if (runToken !== pollTokenRef.current) return;
      setHardDisplayReady(true);
      setPendingIntelInProgress(false);
      setPendingIntelNotice(t.forcedDisplayAfterTimeout);
      setLiveMeta((prev) => {
        if (!prev) return prev;
        if (prev.final) return prev;
        return {
          ...prev,
          final: true,
          stage: 3,
          progress: 100,
          status_text: t.forcedDisplayAfterTimeout,
        };
      });
      setResult((prev) => (
        prev || {
          score: 30,
          risk_level: "Medium",
          reasons: [t.forcedDisplayAfterTimeout],
          reason_keys: ["insufficient_trust_signals"],
        }
      ));
    }, HARD_RESULT_TIMEOUT_MS);

    setLoading(true);
    try {
      let startResponse: Response | null = null;
      let startError: unknown = null;
      for (let attempt = 0; attempt < 2; attempt += 1) {
        try {
          startResponse = await fetchWithTimeout(
            `${apiBaseUrl}/analyze/live/start`,
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ url: trimmed, message: trimmedMessage, language }),
            },
            LIVE_START_TIMEOUT_MS
          );
          if (startResponse.status === 429) {
            clearForceDisplayTimer();
            setError(t.liveRateLimited);
            return;
          }
          if ((startResponse.status >= 500 || startResponse.status === 408) && attempt === 0) {
            await sleep(700);
            continue;
          }
          if (startResponse.status >= 500 || startResponse.status === 408) {
            clearForceDisplayTimer();
            setError(t.liveServerUnavailable);
            return;
          }
          break;
        } catch (err) {
          startError = err;
          if (attempt === 0) {
            await sleep(700);
            continue;
          }
        }
      }

      if (!startResponse) {
        clearForceDisplayTimer();
        setError(startError instanceof Error ? t.liveNetworkSlow : t.liveServerUnavailable);
        return;
      }
      if (startResponse.ok) {
        const startData = await startResponse.json();
        if (runToken !== pollTokenRef.current) return;
        setLiveMeta({
          analysis_id: startData.analysis_id || "",
          final: Boolean(startData.final),
          stage: Number(startData.stage || 1),
          progress: Number(startData.progress || 0),
          risk_level: (startData.risk_level || "Low") as RiskLevel,
          status_text: startData.status_text || t.liveStatus,
          steps: (startData.steps || []) as LiveStep[],
        });
        setResult((startData.result || null) as AnalysisResponse | null);
        setLoading(false);

        if (!startData.final && startData.analysis_id) {
          let gotFinal = false;
          let latestPartial = (startData.result || null) as AnalysisResponse | null;
          const pollStartedAt = Date.now();
          let transientStatusFailures = 0;
          for (let i = 0; i < 30; i += 1) {
            await new Promise((resolve) => setTimeout(resolve, 2300));
            if (runToken !== pollTokenRef.current) return;
            let statusResp: Response;
            try {
              statusResp = await fetchWithTimeout(
                `${apiBaseUrl}/analyze/live/status/${startData.analysis_id}`,
                {},
                LIVE_STATUS_TIMEOUT_MS
              );
            } catch {
              transientStatusFailures += 1;
              if (transientStatusFailures >= 2) break;
              continue;
            }
            if (!statusResp.ok) {
              if (statusResp.status === 429) {
                setError(t.liveRateLimited);
                break;
              }
              transientStatusFailures += 1;
              if (transientStatusFailures >= 2) break;
              continue;
            }
            transientStatusFailures = 0;
            const statusData = await statusResp.json();
            if (runToken !== pollTokenRef.current) return;
            latestPartial = (statusData.result || latestPartial) as AnalysisResponse | null;
            setLiveMeta({
              analysis_id: statusData.analysis_id || "",
              final: Boolean(statusData.final),
              stage: Number(statusData.stage || 1),
              progress: Number(statusData.progress || 0),
              risk_level: (statusData.risk_level || "Low") as RiskLevel,
              status_text: statusData.status_text || (statusData.final ? t.analysisCompleted : t.waitingExternal),
              steps: (statusData.steps || []) as LiveStep[],
            });
            setResult((statusData.result || null) as AnalysisResponse | null);
            if (statusData.final) {
              gotFinal = true;
              clearForceDisplayTimer();
              if (hasPendingExternalIntel((statusData.result || null) as AnalysisResponse | null)) {
                // Show pending-intel panel immediately when countdown reaches 00:00.
                setPendingIntelNotice(t.pendingIntelAutoStart);
              } else {
                setPendingIntelNotice("");
              }
              setCountdownSec(0);
              break;
            }
            if (Date.now() - pollStartedAt > 65000) break;
          }

          // If live polling did not reach final state, force one final pass.
          if (!gotFinal) {
            try {
              const finalResp = await fetchWithTimeout(
                `${apiBaseUrl}/analyze`,
                {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ url: trimmed, message: trimmedMessage, language }),
                },
                FINAL_ANALYZE_TIMEOUT_MS
              );
              if (runToken !== pollTokenRef.current) return;
              if (finalResp.ok) {
                const finalData = (await finalResp.json()) as AnalysisResponse;
                clearForceDisplayTimer();
                // Trust the authoritative /analyze body: inflating risk_level here without
                // updating link_verdict/domain_verdict caused a misleading split UI.
                setResult(finalData);
                setLiveMeta({
                  analysis_id: startData.analysis_id || "",
                  final: true,
                  stage: 3,
                  progress: 100,
                  risk_level: (finalData.risk_level || "Low") as RiskLevel,
                  status_text: t.analysisCompleted,
                  steps: [
                    { key: "stage_1", label: "URL analysis", status: "done" },
                    { key: "stage_2", label: "Redirect check", status: "done" },
                    { key: "stage_3", label: "External checks", status: "done" },
                  ],
                });
                if (hasPendingExternalIntel(finalData)) {
                  setPendingIntelNotice(t.pendingIntelAutoStart);
                } else {
                  setPendingIntelNotice("");
                }
                setCountdownSec(0);
              } else {
                // Do not leave user without output: finalize UI with the latest partial snapshot.
                clearForceDisplayTimer();
                if (latestPartial) {
                  setResult(latestPartial);
                }
                setLiveMeta({
                  analysis_id: startData.analysis_id || "",
                  final: true,
                  stage: 3,
                  progress: 100,
                  risk_level: ((latestPartial?.risk_level || startData.risk_level || "Low") as RiskLevel),
                  status_text: t.partialResultNotice,
                  steps: [
                    { key: "stage_1", label: "URL analysis", status: "done" },
                    { key: "stage_2", label: "Redirect check", status: "done" },
                    { key: "stage_3", label: "External checks", status: "done" },
                  ],
                });
                setError(t.partialResultNotice);
                if (hasPendingExternalIntel(latestPartial)) {
                  setPendingIntelNotice(t.pendingIntelAutoStart);
                } else {
                  setPendingIntelNotice("");
                }
                setCountdownSec(0);
              }
            } catch {
              if (runToken !== pollTokenRef.current) return;
              clearForceDisplayTimer();
              if (latestPartial) {
                setResult(latestPartial);
              }
              setLiveMeta({
                analysis_id: startData.analysis_id || "",
                final: true,
                stage: 3,
                progress: 100,
                risk_level: ((latestPartial?.risk_level || startData.risk_level || "Low") as RiskLevel),
                status_text: t.partialResultNotice,
                steps: [
                  { key: "stage_1", label: "URL analysis", status: "done" },
                  { key: "stage_2", label: "Redirect check", status: "done" },
                  { key: "stage_3", label: "External checks", status: "done" },
                ],
              });
              setError(t.partialResultNotice);
              if (hasPendingExternalIntel(latestPartial)) {
                setPendingIntelNotice(t.pendingIntelAutoStart);
              } else {
                setPendingIntelNotice("");
              }
              setCountdownSec(0);
            }
          }
        }
        return;
      }

      // Backward-compatible fallback to existing single-shot endpoint.
      const response = await fetchWithTimeout(
        `${apiBaseUrl}/analyze`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: trimmed, message: trimmedMessage, language }),
        },
        FINAL_ANALYZE_TIMEOUT_MS
      );
      if (!response.ok) throw new Error(`Status ${response.status}`);
      const legacy = await response.json();
      if (runToken !== pollTokenRef.current) return;
      clearForceDisplayTimer();
      setResult(legacy);
      setLiveMeta({
        analysis_id: "",
        final: true,
        stage: 3,
        progress: 100,
        risk_level: (legacy.risk_level || "Low") as RiskLevel,
        status_text: t.analysisCompleted,
        steps: [
          { key: "stage_1", label: "URL analysis", status: "done" },
          { key: "stage_2", label: "Redirect check", status: "done" },
          { key: "stage_3", label: "External checks", status: "done" },
        ],
      });
      if (hasPendingExternalIntel(legacy as AnalysisResponse)) {
        setPendingIntelNotice(t.pendingIntelAutoStart);
      } else {
        setPendingIntelNotice("");
      }
      setCountdownSec(0);
    } catch (err) {
      const isAbort = err instanceof DOMException && err.name === "AbortError";
      if (isAbort) {
        setError(t.liveNetworkSlow);
      } else {
        setError(err instanceof Error ? err.message : t.liveServerUnavailable);
      }
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
  const knownSiteCountry = result ? countryNameFromTld(result) : "";
  const domainTld = (result?.domain_tld || "").trim().toLowerCase();
  const hideLocationBanner = domainTld === "com";
  const showSiteLocationBanner =
    Boolean(result) && !hideLocationBanner && (Boolean(knownSiteCountry) || result?.is_green_safe === false);
  const siteLocationText = knownSiteCountry || t.locationUnknown;
  const analyzedHostname = (() => {
    try {
      if (!result?.analyzed_url) return "";
      return new URL(result.analyzed_url).hostname.toLowerCase();
    } catch {
      return "";
    }
  })();
  const subdomainPart = (() => {
    const reg = (result?.registrable_domain || "").toLowerCase();
    if (!analyzedHostname || !reg) return "";
    if (!analyzedHostname.endsWith(`.${reg}`)) return "";
    const raw = analyzedHostname.slice(0, -(reg.length + 1));
    const withoutWww = raw
      .split(".")
      .filter((part) => part && !/^www\d*$/i.test(part))
      .join(".");
    return withoutWww;
  })();
  const hasSubdomainFocus = Boolean(result?.has_subdomains && result?.registrable_domain && subdomainPart);
  const hasMisleadingSubdomainAlert = Boolean(
    hasSubdomainFocus &&
      result?.reason_keys?.some((k) => k === "brand_mismatch" || k === "lookalike_brand" || k === "brand")
  );
  // Show verdict/details only after live pipeline reports final (countdown covers the wait).
  const shouldShowResult = Boolean(result) && (!liveMeta || liveMeta.final || hardDisplayReady);
  const hasPendingIntelOnFinal = Boolean(result && shouldShowResult && hasPendingExternalIntel(result));
  const pendingAtCountdownZeroBeforeFinal = Boolean(liveMeta && !liveMeta.final && countdownSec === 0);
  const showPendingIntelPanel = Boolean(
    !hardDisplayReady && (pendingAtCountdownZeroBeforeFinal || (result && shouldShowResult && (hasPendingIntelOnFinal || pendingIntelNotice)))
  );
  // Hide verdict while auto-refresh is actively running; reveal provisional verdict if retries exhausted.
  const blockVerdictWhileRefreshing = Boolean(!hardDisplayReady && hasPendingIntelOnFinal && pendingIntelInProgress);
  const showFinalVerdict = Boolean(result && shouldShowResult && !blockVerdictWhileRefreshing);
  const domainVerdict = result?.domain_verdict;
  const linkVerdict = result?.link_verdict;

  return (
    <main className="page" dir={language === "he" ? "rtl" : "ltr"} lang={language}>
      <TermsModal lang={language} open={showTermsModal} onClose={() => setShowTermsModal(false)} />
      <ReportIssueModal
        open={showReportModal}
        onClose={() => setShowReportModal(false)}
        lang={language}
        url={url}
        message={message}
        apiBaseUrl={apiBaseUrl}
        labels={{
          title: t.reportTitle,
          intro: t.reportIntro,
          contextTitle: t.reportContextTitle,
          contextEmpty: t.reportContextEmpty,
          contextUrlLabel: t.reportContextUrlLabel,
          contextMessageLabel: t.reportContextMessageLabel,
          includeInReport: t.reportIncludeInReport,
          excludedFromReport: t.reportExcludedFromReport,
          viaEmailOnly: t.reportViaEmailOnly,
          viaEmailOnlyHint: t.reportViaEmailOnlyHint,
          formSectionLabel: t.reportFormSection,
          label: t.reportLabel,
          placeholder: t.reportPlaceholder,
          send: t.reportSend,
          sending: t.reportSending,
          success: t.reportSuccess,
          successViaMail: t.reportSuccessViaMail,
          fail: t.reportFail,
          unavailable: t.reportUnavailable,
          openMail: t.reportOpenMail,
          close: t.reportClose,
        }}
      />

      {/* Top rail: Erlix + language */}
      <div className="top-rail">
        <a href="https://erlix.net/" className="top-rail__home-link" aria-label="Erlix home page">
          <img src="/erlix-logo.png" alt="Erlix" className="top-rail__erlix-logo" />
        </a>
        <div className="lang-toggle">
          <button
            type="button"
            className={`lang-toggle__btn ${language === "en" ? "lang-toggle__btn--active" : ""}`}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              setLanguage("en");
            }}
          >
            EN
          </button>
          <button
            type="button"
            className={`lang-toggle__btn ${language === "he" ? "lang-toggle__btn--active" : ""}`}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              setLanguage("he");
            }}
          >
            HE
          </button>
        </div>
      </div>

      {/* Header */}
      <header className="header">
        <a href="https://erlix.net/linkcheck/" className="header__logo-wrap header__logo-link" aria-label="LinkCheck page">
          <div className="header__logo-glow" />
          <img src={linkCheckLogo} alt="LinkCheck" className="header__logo header__logo--linkcheck" />
        </a>
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

        <button type="button" className="scan-btn" onClick={onAnalyze} disabled={loading || !termsAccepted}>
          <span className="scan-btn__icon">{loading ? "" : "\u{1F6E1}\uFE0F"}</span>
          {loading ? t.scanning : t.scan}
        </button>
        {t.scanHint ? <p className="scan-hint">{t.scanHint}</p> : null}

        <TermsInline
          lang={language}
          accepted={termsAccepted}
          onAcceptedChange={setTermsAccepted}
          onOpenFull={() => setShowTermsModal(true)}
        />

        {error && <p className="error-msg">{error}</p>}

        {/* Loading */}
        {loading && (
          <div className="scanner">
            <div className="scanner__ring" />
            <span className="scanner__text">{t.scanning}</span>
          </div>
        )}

        {/* Live progress + countdown only while analysis is still running */}
        {liveMeta && !loading && !liveMeta.final && !hardDisplayReady && (
          <div className="result-section live-progress">
            <div className="result-section__title">{t.analysisSteps}</div>
            <div className="live-progress__status">
              {t.parallelCheckNotice}
            </div>
            <div className="live-countdown" dir="ltr">
              <span className="live-countdown__label">{t.countdownLabel}</span>
              <span className="live-countdown__value">
                00:{String(liveMeta.final ? 0 : countdownSec).padStart(2, "0")}
              </span>
            </div>
            <div className="live-progress__status">
              {liveMeta.status_text || (liveMeta.final ? t.analysisCompleted : t.waitingExternal)}
            </div>
          </div>
        )}

        {/* Pending external checks notice (shown immediately at 00:00, before final verdict) */}
        {showPendingIntelPanel && result && !loading && (
          <div className="result-section">
            <div className="reason-item reason-item--ai-summary">
              <span className="reason-item__icon">{pendingIntelInProgress ? "⏳" : "ℹ️"}</span>
              <span>{pendingIntelNotice || t.pendingIntelAutoStart}</span>
            </div>
          </div>
        )}

        {/* Results */}
        {showFinalVerdict && result && !loading && (
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

            {(domainVerdict?.url || linkVerdict?.url) && (
              <div className="result-section">
                <div className="result-section__title">{t.splitVerdictTitle}</div>
                <div className="reason-item">
                  <span className="reason-item__icon">{domainVerdict?.risk_level === "Low" ? "\u2705" : "\u26A0\uFE0F"}</span>
                  <span>
                    {domainVerdict?.risk_level === "Low" ? t.domainVerdictSafe : t.domainVerdictWarn}
                  </span>
                </div>
                <div className="reason-item">
                  <span className="reason-item__icon">
                    {linkVerdict?.risk_level === "Low" ? "\u2705" : linkVerdict?.risk_level === "High" ? "\u26D4" : "\u26A0\uFE0F"}
                  </span>
                  <span>
                    {linkVerdict?.risk_level === "Low" ? t.linkVerdictSafe : t.linkVerdictWarn}
                  </span>
                </div>
                {(domainVerdict?.url || linkVerdict?.url) && (
                  <details className="redirect-details split-links-details">
                    <summary className="redirect-details__summary">{t.fullLinksToggle}</summary>
                    <div className="redirect-window split-links-window" role="region" aria-label={t.fullLinksTitle}>
                      <div className="redirect-window__title">{t.fullLinksTitle}</div>
                      <div className="redirect-window__content split-links-window__content">
                        {domainVerdict?.url && (
                          <div className="split-links-row">
                            <span className="split-links-row__label">Domain:</span>
                            <span className="split-links-row__url">{domainVerdict.url}</span>
                          </div>
                        )}
                        {linkVerdict?.url && (
                          <div className="split-links-row">
                            <span className="split-links-row__label">Link:</span>
                            <span className="split-links-row__url">{linkVerdict.url}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </details>
                )}
              </div>
            )}

            {/* URL info */}
            {(hasUrlDiff || hasRedirect || !!result?.analyzed_url || !!result?.submitted_url) && (
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
                {!hasUrlDiff && result.analyzed_url && (
                  <div className="url-row">
                    <span className="url-row__label">{t.analyzedUrl}</span>
                    <span className="url-row__value">{result.analyzed_url}</span>
                  </div>
                )}
                {hasSubdomainFocus && (
                  <div
                    className={`main-domain-focus ${hasMisleadingSubdomainAlert ? "main-domain-focus--warn" : ""}`}
                    dir={language === "he" ? "rtl" : "ltr"}
                  >
                    <div className="main-domain-focus__row">
                      {language === "he" ? (
                        <span>
                          הדומיין הראשי הוא: <strong className="main-domain-focus__main">{result.registrable_domain}</strong>
                        </span>
                      ) : (
                        <span>
                          The main domain is: <strong className="main-domain-focus__main">{result.registrable_domain}</strong>
                        </span>
                      )}
                    </div>
                    <div className="main-domain-focus__row">
                      {language === "he" ? (
                        <span>
                          <strong className="main-domain-focus__sub">{subdomainPart}</strong> הינו תת דומיין בלבד.
                        </span>
                      ) : (
                        <span>
                          <strong className="main-domain-focus__sub">{subdomainPart}</strong> is only a subdomain.
                        </span>
                      )}
                    </div>
                  </div>
                )}
                {showSiteLocationBanner && (
                  <div className="site-location-banner" dir={language === "he" ? "rtl" : "ltr"}>
                    <span className="site-location-banner__label">{t.siteLocation}:</span>
                    <span className="site-location-banner__value">{siteLocationText}</span>
                  </div>
                )}

                {hasRedirect && (
                  <details className="redirect-details">
                    <summary className="redirect-details__summary">{t.redirectPathToggle}</summary>
                    <div className="redirect-window" role="region" aria-label={t.redirectChain}>
                      <div className="redirect-window__title">{t.redirectChain}</div>
                      <div className="redirect-window__content">
                        {result.redirect_chain!.map((step, i) => (
                          <div key={i}>
                            {i > 0 && <div className="chain-step__arrow">&#8595;</div>}
                            <div className="chain-step">
                              <span className={`chain-step__dot ${i === result.redirect_chain!.length - 1 ? "chain-step__dot--final" : ""}`} />
                              <span className="chain-step__url">{step}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </details>
                )}
              </div>
            )}

            {/* Reasons */}
            <div className="result-section">
              <div className="result-section__title">{t.reasons}</div>
              {result.ai_model_summary ? (
                <div className="reason-item reason-item--ai-summary">
                  <span className="reason-item__icon">🤖</span>
                  <span>{result.ai_model_summary}</span>
                </div>
              ) : null}
              {getLocalizedReasons(result).map((reason, i) => (
                <div className="reason-item" key={i}>
                  <span className="reason-item__icon">
                    {reason.key ? getReasonIcon(reason.key) : "\u{1F50D}"}
                  </span>
                  <span>{reason.text}</span>
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

      <div className="beta-banner beta-banner--footer" role="status">
        <span className="beta-banner__badge">{t.betaBadge}</span>
        <p className="beta-banner__text">{t.betaNotice}</p>
      </div>

      {/* Footer */}
      <footer className="footer">
        <FooterLegal
          onOpenTerms={() => setShowTermsModal(true)}
          onReport={() => setShowReportModal(true)}
          labels={{ terms: t.footerTerms, contact: t.footerContact, report: t.footerReport }}
        />
        <p className="footer__text">{t.contactLine}</p>
        <p className="footer__text">{t.footer}</p>
      </footer>
    </main>
  );
}
