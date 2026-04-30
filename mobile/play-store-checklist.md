# Google Play Submission Checklist (LinkCheck)

Use this before each production release.

## Technical

- [ ] `versionCode` increased in `mobile/android/app/build.gradle`
- [ ] `versionName` updated if needed
- [ ] `npm run build:android` passed
- [ ] Release built as `.aab` (not debug apk)
- [ ] App opens correctly on Android 10/11/12/13/14+
- [ ] Network calls to production API succeed on Wi-Fi and cellular

## Security and policy

- [ ] Privacy policy URL live and public (`https://...`)
- [ ] Data safety form completed accurately
- [ ] No unnecessary permissions requested
- [ ] Content rating questionnaire completed
- [ ] Target audience and ads declarations completed

## Store listing

- [ ] App name + short description + full description
- [ ] Feature graphic (1024x500)
- [ ] App icon (512x512)
- [ ] Phone screenshots (minimum 2)
- [ ] Localized listing text (Hebrew + optional English)

## Release management

- [ ] Upload to **Internal testing** first
- [ ] Verify critical flow with real testers
- [ ] Roll out to Production gradually (e.g. 10% -> 50% -> 100%)
