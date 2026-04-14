# LinkCheck - Development Status

## Current Stage
- MVP web system is running with separated services:
  - `frontend` (React + Vite)
  - `backend` (Flask API)
- Input supports:
  - Full message text (SMS/email)
  - Optional direct URL
  - Automatic URL extraction from message text
- Localization supports:
  - Hebrew and English UI
  - Localized reasons from backend
  - Localized risk labels in frontend

## Detection Logic Implemented
- URL rule-based scoring:
  - Brand pattern in URL
  - Suspicious phishing words
  - Suspicious TLD
  - Long URL
  - Too many hyphens
  - No HTTPS
  - Lookalike-domain detection (digit-substitution and one-letter typo)
  - Mixed alphabet detection (Latin/Cyrillic/Greek/Hebrew in same domain)
  - Unicode homoglyph detection (confusable characters)
  - Punycode (`xn--`) detection for suspicious IDN patterns
- Message text scoring:
  - Urgency/manipulation language
  - Very short message with link
  - Aggressive punctuation

## External Intelligence Status
- Real external calls are not connected yet.
- Ready-to-connect env vars:
  - `VIRUSTOTAL_API_KEY`
  - `URLSCAN_API_KEY`
  - `WHOISXML_API_KEY`
  - `DNS_CHECK_API_KEY`

## Next Steps (Recommended Order)
1. Add real VirusTotal integration (first external source).
2. Add URLScan integration (support async polling flow if needed).
3. Add WHOIS + DNS reputation checks.
4. Merge external-source signals into weighted scoring.
5. Add analysis history (local DB or file) for audit/demo.
6. Add tests for scoring rules and localization.

## Notes
- Keep business logic in backend only.
- Frontend should only send input and display results.
