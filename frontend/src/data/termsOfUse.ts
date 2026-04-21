/**
 * Terms of Use — source strings for in-app display (Hebrew / English).
 * Keep in sync with docs/TERMS_OF_USE.md
 */
export type TermsSection = {
  id: string;
  title: { he: string; en: string };
  body: { he: string[]; en: string[] };
};

export const TERMS_VERSION = "1";

/** Primary contact for legal, privacy, and bug reports */
export const CONTACT_EMAIL = "ierlich@gmail.com";

export const termsSections: TermsSection[] = [
  {
    id: "general",
    title: { he: "1. כללי", en: "1. General" },
    body: {
      he: [
        "ברוכים הבאים לאתר LinkCheck (להלן: \"האתר\"). השימוש באתר כפוף לתנאים המפורטים בתקנון זה.",
        "שימוש באתר מהווה הסכמה מלאה לתנאים אלה. אם אינך מסכים — הימנע משימוש באתר.",
        "מפעיל האתר רשאי לעדכן תקנון זה בכל עת. המשך שימוש לאחר פרסום עדכון מהווה הסכמה לתנאים המעודכנים, אלא אם נאסר על כך לפי דין.",
      ],
      en: [
        'Welcome to the LinkCheck website (the "Site"). Use of the Site is subject to these Terms.',
        "By using the Site you agree to these Terms in full. If you do not agree, do not use the Site.",
        "The operator may update these Terms at any time. Continued use after an update is posted constitutes acceptance of the revised Terms, unless prohibited by law.",
      ],
    },
  },
  {
    id: "service",
    title: { he: "2. תיאור השירות", en: "2. Description of the service" },
    body: {
      he: [
        "האתר מספק כלי לבדיקת קישורים והערכת רמת סיכון (למשל פישינג או הונאה).",
        "השירות מבוסס על ניתוח אוטומטי, מקורות מידע חיצוניים (כאשר מוגדרים) ואלגוריתמים.",
        "תוצאות הבדיקה הן הערכה בלבד ואינן התחייבות לדיוק, שלמות או עדכניות.",
      ],
      en: [
        "The Site provides a tool to assess link risk (for example phishing or fraud).",
        "The service relies on automated analysis, external data sources (when configured), and algorithms.",
        "Results are estimates only and are not a guarantee of accuracy, completeness, or timeliness.",
      ],
    },
  },
  {
    id: "liability",
    title: { he: "3. הגבלת אחריות", en: "3. Limitation of liability" },
    body: {
      he: [
        "השימוש באתר נעשה על אחריות המשתמש בלבד.",
        "האתר אינו מתחייב לזיהוי כל קישור מסוכן או לסיווג נכון של כל קישור בטוח.",
        "מפעיל האתר לא יהיה אחראי לכל נזק, ישיר או עקיף, הנובע משימוש או הסתמכות על האתר.",
        "אין לראות בתוצאות האתר ייעוץ מקצועי, משפטי או אבטחתי.",
      ],
      en: [
        "You use the Site at your own risk.",
        "The Site does not guarantee detection of every harmful link or correct classification of every safe link.",
        "The operator is not liable for any direct or indirect damages arising from use of or reliance on the Site.",
        "Results are not professional, legal, or security advice.",
      ],
    },
  },
  {
    id: "permitted",
    title: { he: "4. שימוש מותר ואסור", en: "4. Permitted and prohibited use" },
    body: {
      he: [
        "המשתמש מתחייב להשתמש באתר בהתאם לדין החל בלבד.",
        "חל איסור על: שימוש לצרכים בלתי חוקיים; ניסיון לעקוף, לשבש או לפגוע במערכת; שימוש אוטומטי מופרז (למשל scraping או בוטים) ללא אישור מראש.",
        "מפעיל האתר רשאי לחסום גישה במקרה של הפרת תנאים אלה.",
      ],
      en: [
        "You agree to use the Site in compliance with applicable law.",
        "You must not: use the Site unlawfully; attempt to bypass, disrupt, or harm the system; or run abusive automated access (for example scraping or bots) without prior permission.",
        "The operator may block access for violations of these Terms.",
      ],
    },
  },
  {
    id: "privacy",
    title: { he: "5. פרטיות והגנת מידע", en: "5. Privacy" },
    body: {
      he: [
        "האתר עשוי לאסוף מידע טכני (למשל כתובת IP, סוג דפדפן/מכשיר, נתוני שימוש) לצורך תפעול, אבטחה ושיפור השירות.",
        "בהתאם ל-GDPR (אירופה), למשתמשים עשויות לעמוד זכויות כגון עיון, תיקון או מחיקה — ניתן לפנות בבקשות פרטיות לכתובת האימייל שלנו.",
        "האתר לא ימכור מידע אישי לצדדים שלישיים ללא בסיס חוקי או הסכמה כנדרש.",
      ],
      en: [
        "The Site may collect technical data (for example IP address, browser/device type, usage data) for operation, security, and improvement.",
        "Where GDPR applies, you may have rights such as access, rectification, or erasure — contact us at the email below for privacy requests.",
        "We will not sell personal information to third parties without a lawful basis or consent as required.",
      ],
    },
  },
  {
    id: "external",
    title: { he: "6. קישורים חיצוניים", en: "6. External links" },
    body: {
      he: [
        "האתר עשוי לבדק או להציג מידע על קישורים חיצוניים.",
        "מפעיל האתר אינו אחראי לתוכן, לאמינות או לזמינות של אתרים חיצוניים.",
        "פתיחת קישורים חיצוניים נעשית באחריות המשתמש בלבד.",
      ],
      en: [
        "The Site may analyze or display information about external links.",
        "The operator is not responsible for third-party content, reliability, or availability.",
        "Opening external links is solely your responsibility.",
      ],
    },
  },
  {
    id: "ip",
    title: { he: "7. קניין רוחני", en: "7. Intellectual property" },
    body: {
      he: [
        "זכויות הקניין הרוחני באתר שייכות למפעיל האתר, אלא אם צוין אחרת.",
        "אין להעתיק, להפיץ או לעשות שימוש מסחרי בתוכן האתר ללא אישור מראש.",
      ],
      en: [
        "Intellectual property rights in the Site belong to the operator unless stated otherwise.",
        "You may not copy, distribute, or commercially exploit Site content without prior permission.",
      ],
    },
  },
  {
    id: "availability",
    title: { he: "8. זמינות השירות", en: "8. Availability" },
    body: {
      he: [
        "מפעיל האתר אינו מתחייב לזמינות רציפה של השירות.",
        "ייתכנו תקלות, הפסקות או שינויים ללא הודעה מוקדמת.",
      ],
      en: [
        "The operator does not guarantee uninterrupted availability.",
        "Outages, maintenance, or changes may occur without advance notice.",
      ],
    },
  },
  {
    id: "law",
    title: { he: "9. דין וסמכות שיפוט", en: "9. Governing law and jurisdiction" },
    body: {
      he: [
        "השימוש באתר כפוף לדין החל במדינת פעילות מפעיל האתר, ככל שלא נקבע אחרת לפי דין חובה.",
        "סכסוכים יידונו בבתי המשפט המוסמכים בהתאם לדין החל.",
        "ככל שנדרש לפי דין האיחוד האירופי, למשתמשים באירופה עומדות זכויות נוספות בהתאם לדין המקומי.",
      ],
      en: [
        "These Terms are governed by the laws applicable in the operator's jurisdiction, unless mandatory law provides otherwise.",
        "Disputes shall be brought before competent courts as required by applicable law.",
        "Where EU law applies, additional rights may apply under local law.",
      ],
    },
  },
  {
    id: "contact",
    title: { he: "10. יצירת קשר", en: "10. Contact" },
    body: {
      he: [
        "לשאלות בנוגע לתנאים או לפרטיות: ierlich@gmail.com",
      ],
      en: [
        "Questions about these Terms or privacy: ierlich@gmail.com",
      ],
    },
  },
  {
    id: "age",
    title: { he: "11. גיל", en: "11. Age" },
    body: {
      he: [
        "השימוש מיועד למשתמשים מגיל 18 ומעלה, או לגיל המינימום הנדרש לפי דין המקומי החל עליך (הגבוה מביניהם).",
      ],
      en: [
        "Use is intended for users aged 18+ or the minimum age required by your local law, whichever is higher.",
      ],
    },
  },
  {
    id: "changes",
    title: { he: "12. שינויים בשירות", en: "12. Changes to the service" },
    body: {
      he: [
        "מפעיל האתר רשאי לשנות, לעדכן או להפסיק את השירות בכל עת, בכפוף לדין.",
      ],
      en: [
        "The operator may change, update, or discontinue the service at any time, subject to applicable law.",
      ],
    },
  },
];
