# LinkCheck Mobile (Android)

This folder contains a dedicated Android app project for Google Play, separated from the web app code.

## Architecture

- UI/content source: `../frontend` (built with `Vite`)
- Mobile container: `Capacitor` + native Android project in `mobile/android`
- API backend: same production backend used by web (`/api` endpoints from deployed site)
- Mobile build injects `VITE_API_BASE_URL=https://erlix.net/api` so app networking works from `file://` context.
- For mobile packaging speed/stability, the script builds web assets with `vite build`
  (without running `tsc -b` typecheck). Web CI can still keep strict typecheck separately.

## Prerequisites

- Node.js 20+
- Android Studio (latest stable)
- Android SDK + build-tools installed via Android Studio
- Java 21 (recommended with current Android toolchain)

## One-time setup

From `mobile/`:

```bash
npm install
npm run build:android
```

Then open Android Studio:

```bash
npm run open:android
```

## Daily workflow

1. Update web code (in `frontend/`).
2. Build + sync into Android:

```bash
npm run build:android
```

3. Build release in Android Studio (`Build > Generate Signed Bundle / APK`).

## Fastest way to run on phone (without Android Studio)

You can build a ready-to-install Android APK directly from GitHub Actions.

1. Push your branch to GitHub.
2. Open your repository on GitHub.
3. Go to `Actions` tab.
4. Run workflow: `Android Debug APK`.
5. Wait until it finishes (`green check`).
6. Open the run and download artifact: `linkcheck-debug-apk`.
7. Extract and install `app-debug.apk` on your phone.

Notes:
- This is the shortest path for real-device testing.
- `app-debug.apk` is for testing only (not Play Store release).

## Play Store release checklist

### 1) App identity

- Package ID (`applicationId`): `net.erlix.linkcheck`
- App name: `LinkCheck`
- Versioning in `mobile/android/app/build.gradle`:
  - `versionCode` must increase every upload
  - `versionName` is user-facing

### 2) Security baseline (already configured)

- `INTERNET` permission only
- `cleartext` HTTP disabled
- Android backup disabled

### 3) Signing

Generate upload keystore once (keep it safe forever):

```bash
keytool -genkeypair -v -keystore linkcheck-upload.jks -alias linkcheck-upload -keyalg RSA -keysize 2048 -validity 10000
```

In Android Studio:

- `Build > Generate Signed Bundle / APK`
- Choose `Android App Bundle` (`.aab`) for Play
- Use the upload keystore

### 4) Play Console required pages

- Privacy policy URL (public HTTPS page)
- App category (`Tools` or `Productivity`)
- Content rating questionnaire
- Data safety form
- Target audience

### 5) Testing before publish

- Internal testing track upload first
- Validate:
  - app launch
  - scan flow
  - Hebrew/English UI rendering
  - API reachability from mobile networks

## Notes

- This project intentionally keeps full separation between web and mobile layers:
  - Web app remains in `frontend/`
  - Mobile packaging/release logic lives only in `mobile/`
- To support iOS later:

```bash
npx cap add ios
```
