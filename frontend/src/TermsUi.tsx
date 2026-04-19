import { useEffect, useState } from "react";
import { CONTACT_EMAIL, TERMS_VERSION, termsSections } from "./data/termsOfUse";

export type Lang = "en" | "he";

type TermsCopy = {
  checkbox: string;
  readFull: string;
  modalTitle: string;
  close: string;
  version: string;
};

const copy: Record<Lang, TermsCopy> = {
  he: {
    checkbox: "קראתי והסכמתי לתנאי השימוש (נדרש לביצוע בדיקה)",
    readFull: "תקנון מלא",
    modalTitle: "תקנון שימוש מלא",
    close: "סגירה",
    version: "גרסה",
  },
  en: {
    checkbox: "I have read and agree to the Terms of Use (required to run a check)",
    readFull: "Full terms",
    modalTitle: "Full terms of use",
    close: "Close",
    version: "Version",
  },
};

export function buildReportMailto(lang: Lang, url: string, message: string, description = ""): string {
  const desc =
    description.trim() ||
    (lang === "he"
      ? "(הוסף כאן תיאור — או מחק שורה זו)"
      : "(Add a description here — or delete this line)");
  const body = [
    "LinkCheck — issue report",
    `Language: ${lang}`,
    `URL field: ${url || "(empty)"}`,
    `Message field: ${message || "(empty)"}`,
    "",
    "Description:",
    desc,
    "",
  ].join("\n");
  return `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent("LinkCheck — report")}&body=${encodeURIComponent(body)}`;
}

type TermsInlineProps = {
  lang: Lang;
  accepted: boolean;
  onAcceptedChange: (value: boolean) => void;
  onOpenFull: () => void;
};

/** תנאי שימוש בשורה אחת — מתחת ללחצן הבדיקה */
export function TermsInline({ lang, accepted, onAcceptedChange, onOpenFull }: TermsInlineProps) {
  const t = copy[lang];
  return (
    <div className="terms-inline">
      <label className="terms-inline__check">
        <input
          type="checkbox"
          checked={accepted}
          onChange={(e) => onAcceptedChange(e.target.checked)}
        />
        <span>{t.checkbox}</span>
      </label>
      <button type="button" className="terms-inline__full" onClick={onOpenFull}>
        {t.readFull}
      </button>
    </div>
  );
}

type TermsModalProps = {
  lang: Lang;
  open: boolean;
  onClose: () => void;
};

export function TermsModal({ lang, open, onClose }: TermsModalProps) {
  const t = copy[lang];
  if (!open) return null;
  return (
    <div className="terms-modal" role="dialog" aria-modal="true" aria-labelledby="terms-modal-title">
      <button type="button" className="terms-modal__backdrop" onClick={onClose} aria-label={t.close} />
      <div className="terms-modal__panel">
        <div className="terms-modal__head">
          <h2 id="terms-modal-title" className="terms-modal__title">
            {t.modalTitle}
          </h2>
          <span className="terms-modal__ver">
            {t.version} {TERMS_VERSION}
          </span>
          <button type="button" className="terms-modal__x" onClick={onClose}>
            ×
          </button>
        </div>
        <div className="terms-modal__body">
          {termsSections.map((sec) => (
            <section key={sec.id} className="terms-sec">
              <h3 className="terms-sec__title">{lang === "he" ? sec.title.he : sec.title.en}</h3>
              {(lang === "he" ? sec.body.he : sec.body.en).map((p, i) => (
                <p key={i} className="terms-sec__p">
                  {p}
                </p>
              ))}
            </section>
          ))}
        </div>
        <div className="terms-modal__foot">
          <button type="button" className="terms-gate__btn terms-gate__btn--primary" onClick={onClose}>
            {t.close}
          </button>
        </div>
      </div>
    </div>
  );
}

type FooterLegalProps = {
  onOpenTerms: () => void;
  onReport: () => void;
  labels: { terms: string; contact: string; report: string };
};

export function FooterLegal({ onOpenTerms, onReport, labels }: FooterLegalProps) {
  return (
    <div className="footer-legal">
      <button type="button" className="footer-legal__link" onClick={onOpenTerms}>
        {labels.terms}
      </button>
      <span className="footer-legal__sep" aria-hidden="true">
        ·
      </span>
      <a className="footer-legal__link" href={`mailto:${CONTACT_EMAIL}`}>
        {labels.contact}
      </a>
      <span className="footer-legal__sep" aria-hidden="true">
        ·
      </span>
      <button type="button" className="footer-legal__link" onClick={onReport}>
        {labels.report}
      </button>
    </div>
  );
}

export type ReportModalLabels = {
  title: string;
  intro: string;
  contextTitle: string;
  contextEmpty: string;
  contextUrlLabel: string;
  contextMessageLabel: string;
  includeInReport: string;
  excludedFromReport: string;
  viaEmailOnly: string;
  viaEmailOnlyHint: string;
  formSectionLabel: string;
  label: string;
  placeholder: string;
  send: string;
  sending: string;
  success: string;
  successViaMail: string;
  fail: string;
  unavailable: string;
  openMail: string;
  close: string;
};

type ReportIssueModalProps = {
  open: boolean;
  onClose: () => void;
  lang: Lang;
  url: string;
  message: string;
  apiBaseUrl: string;
  labels: ReportModalLabels;
};

export function ReportIssueModal({
  open,
  onClose,
  lang,
  url,
  message,
  apiBaseUrl,
  labels,
}: ReportIssueModalProps) {
  const [description, setDescription] = useState("");
  const [phase, setPhase] = useState<"idle" | "sending" | "success" | "success_via_mail" | "error">("idle");
  const [showMailto, setShowMailto] = useState(true);
  const [errorHint, setErrorHint] = useState<string | null>(null);
  const [includeUrl, setIncludeUrl] = useState(true);
  const [includeMessage, setIncludeMessage] = useState(true);

  const resetAndClose = () => {
    setDescription("");
    setPhase("idle");
    setErrorHint(null);
    onClose();
  };

  const urlForReport = includeUrl && url.trim() ? url.trim() : "";
  const messageForReport = includeMessage && message.trim() ? message.trim() : "";

  const openClientMailto = () => {
    const mailto = buildReportMailto(lang, urlForReport, messageForReport, description.trim());
    const a = document.createElement("a");
    a.href = mailto;
    a.rel = "noopener noreferrer";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const openQuickMailtoAndClose = () => {
    const mailto = buildReportMailto(lang, urlForReport, messageForReport, "");
    const a = document.createElement("a");
    a.href = mailto;
    a.rel = "noopener noreferrer";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    resetAndClose();
  };

  useEffect(() => {
    if (open) {
      setDescription("");
      setPhase("idle");
      setErrorHint(null);
      setIncludeUrl(true);
      setIncludeMessage(true);
    }
  }, [open]);

  useEffect(() => {
    if (!open) {
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const response = await fetch(`${apiBaseUrl}/report/config`);
        const data = (await response.json().catch(() => ({}))) as { show_mailto?: boolean };
        if (!cancelled && typeof data.show_mailto === "boolean") {
          setShowMailto(data.show_mailto);
        }
      } catch {
        if (!cancelled) {
          setShowMailto(true);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [open, apiBaseUrl]);

  if (!open) {
    return null;
  }

  const submit = async () => {
    const text = description.trim();
    if (text.length < 5) {
      return;
    }
    setPhase("sending");
    setErrorHint(null);
    try {
      const response = await fetch(`${apiBaseUrl}/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          description: text,
          url_field: urlForReport,
          message_field: messageForReport,
          language: lang,
        }),
      });
      const data = (await response.json().catch(() => ({}))) as {
        error?: string;
        mailto_fallback?: boolean;
      };
      if (
        response.status === 503 ||
        data.error === "smtp_not_configured" ||
        data.error === "report_delivery_not_configured"
      ) {
        const mailtoOk = data.mailto_fallback !== false;
        if (!mailtoOk) {
          setErrorHint(labels.unavailable);
          setPhase("error");
          return;
        }
        setPhase("success_via_mail");
        return;
      }
      if (!response.ok) {
        setPhase("error");
        return;
      }
      setPhase("success");
    } catch {
      setPhase("error");
    }
  };

  return (
    <div className="terms-modal report-modal" role="dialog" aria-modal="true" aria-labelledby="report-modal-title">
      <button type="button" className="terms-modal__backdrop" onClick={resetAndClose} aria-label={labels.close} />
      <div className="terms-modal__panel">
        <div className="terms-modal__head terms-modal__head--report">
          <h2 id="report-modal-title" className="terms-modal__title">
            {labels.title}
          </h2>
          <button type="button" className="terms-modal__x" onClick={resetAndClose}>
            ×
          </button>
        </div>
        <div className="terms-modal__body report-modal__body">
          <p className="report-modal__intro">{labels.intro}</p>
          {(phase === "idle" || phase === "sending" || phase === "error") && (
            <div className="report-modal__context" aria-label={labels.contextTitle}>
              <p className="report-modal__context-title">{labels.contextTitle}</p>
              {!url.trim() && !message.trim() ? (
                <p className="report-modal__context-empty">{labels.contextEmpty}</p>
              ) : (
                <div className="report-modal__context-blocks">
                  {url.trim() ? (
                    <div className="report-modal__context-block">
                      <div className="report-modal__context-head">
                        <span className="report-modal__context-k">{labels.contextUrlLabel}</span>
                        <label className="report-modal__context-include">
                          <input
                            type="checkbox"
                            checked={includeUrl}
                            onChange={(e) => setIncludeUrl(e.target.checked)}
                          />
                          <span>{labels.includeInReport}</span>
                        </label>
                      </div>
                      {includeUrl ? (
                        <pre className="report-modal__context-pre report-modal__context-pre--url">{url.trim()}</pre>
                      ) : (
                        <p className="report-modal__context-excluded">{labels.excludedFromReport}</p>
                      )}
                    </div>
                  ) : null}
                  {message.trim() ? (
                    <div className="report-modal__context-block">
                      <div className="report-modal__context-head">
                        <span className="report-modal__context-k">{labels.contextMessageLabel}</span>
                        <label className="report-modal__context-include">
                          <input
                            type="checkbox"
                            checked={includeMessage}
                            onChange={(e) => setIncludeMessage(e.target.checked)}
                          />
                          <span>{labels.includeInReport}</span>
                        </label>
                      </div>
                      {includeMessage ? (
                        <pre
                          className="report-modal__context-pre"
                          dir={lang === "he" ? "rtl" : "ltr"}
                        >
                          {message.trim()}
                        </pre>
                      ) : (
                        <p className="report-modal__context-excluded">{labels.excludedFromReport}</p>
                      )}
                    </div>
                  ) : null}
                </div>
              )}
            </div>
          )}
          {showMailto && (phase === "idle" || phase === "error") ? (
            <div className="report-modal__quick">
              <button
                type="button"
                className="terms-gate__btn terms-gate__btn--ghost report-modal__quick-btn"
                onClick={openQuickMailtoAndClose}
              >
                {labels.viaEmailOnly}
              </button>
              <p className="report-modal__quick-hint">{labels.viaEmailOnlyHint}</p>
            </div>
          ) : null}
          {phase === "success" || phase === "success_via_mail" ? (
            <>
              <p className="report-modal__ok">
                {phase === "success" ? labels.success : labels.successViaMail}
              </p>
              {phase === "success_via_mail" && (
                <button
                  type="button"
                  className="terms-gate__btn terms-gate__btn--ghost report-modal__mail-again"
                  onClick={openClientMailto}
                >
                  {labels.openMail}
                </button>
              )}
            </>
          ) : (
            <>
              <p className="report-modal__form-section">{labels.formSectionLabel}</p>
              <label className="report-modal__label" htmlFor="report-desc">
                {labels.label}
              </label>
              <textarea
                id="report-desc"
                className="report-modal__textarea"
                rows={5}
                dir={lang === "he" ? "rtl" : "ltr"}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder={labels.placeholder}
                disabled={phase === "sending"}
              />
              {phase === "error" && (
                <p className="report-modal__warn">{errorHint ?? labels.fail}</p>
              )}
            </>
          )}
        </div>
        <div className="terms-modal__foot report-modal__foot">
          {phase === "success" || phase === "success_via_mail" ? (
            <button type="button" className="terms-gate__btn terms-gate__btn--primary" onClick={resetAndClose}>
              {labels.close}
            </button>
          ) : (
            <>
              <button
                type="button"
                className="terms-gate__btn terms-gate__btn--primary"
                onClick={submit}
                disabled={description.trim().length < 5 || phase === "sending"}
              >
                {phase === "sending" ? labels.sending : labels.send}
              </button>
              <button type="button" className="terms-gate__btn terms-gate__btn--ghost" onClick={resetAndClose}>
                {labels.close}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
