# ZYROX

ZYROX is a Capacitor Android app. This update preserves the existing native Android project and APK pipeline, and adds account authentication to the current HTML/CSS/JavaScript app with a separately deployable Node.js/PostgreSQL API.

## Included

- Username/email registration, email/password sign-in, Google sign-in, sign-out, persistent sessions, password recovery, and password changes.
- A dark gaming-style account dashboard with profile avatar and settings.
- PostgreSQL storage, salted scrypt password hashes, short-lived signed access tokens, rotating hashed refresh credentials in HttpOnly cookies, and server-side Google ID-token verification.
- Rate-limited auth routes, strict CORS allowlisting, request verification, Helmet security headers, bounded JSON bodies, and non-cacheable auth responses.
- Auth API tests and GitHub Actions APK builds.

## Setup

Backend deployment, OAuth configuration, host firewall guidance, and local commands are in server/README.md. Never put database credentials, SMTP passwords, JWT signing keys, or Google client secrets in frontend files. The Google web client ID and API URL are public app configuration, not secrets.

Before account flows work, deploy the API and PostgreSQL database. Password reset additionally needs SMTP. Google sign-in needs a Google web OAuth client ID plus an Android OAuth client configured for the app package and signing certificate. Without those external credentials, the UI keeps Google sign-in disabled and explains that setup is needed.

## Local checks and Android build

From the repo root:

    npm ci
    npm run build:web
    npx cap sync android
    cd android && ./gradlew assembleDebug

Backend tests:

    npm ci --prefix server
    npm test --prefix server

The tests use an in-memory PostgreSQL-compatible database and a stubbed Google verifier; they validate the API's account/session logic, not a live Google account, production database, SMTP delivery, host firewall, or release signing. The GitHub Actions artifact is a debug APK. Configure the optional ANDROID_DEBUG_KEYSTORE_BASE64 Actions secret and register its SHA-1 with Google if you want Google Sign-In to work in the downloaded CI APK.

References: [Capgo native Google sign-in setup](https://capgo.app/docs/plugins/social-login/google/android/) · [Google ID token verification](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token).
