# ZYROX authentication API

This is the backend for the existing ZYROX Capacitor app. It requires Node.js 20+ and PostgreSQL. The API returns 15-minute access tokens to app memory and stores rotating refresh credentials only in Secure/HttpOnly/SameSite=None cookies. Refresh-token hashes, password hashes, reset-code hashes, and account records are stored in PostgreSQL. Passwords use salted scrypt. Google login verifies the signed ID token against Google's published keys and expected audience before using Google's stable subject and verified email to create or link an account.

## Environment

Copy .env.example to .env for local development. In production, add values in the backend host's environment/secrets UI, not source control.

Required for the API:

- DATABASE_URL: PostgreSQL connection string for a dedicated ZYROX database.
- JWT_SECRET: random secret of at least 32 bytes. Generate one locally, for example with openssl rand -base64 48, and store it only in the backend host's secret manager.

Required for Google sign-in:

- GOOGLE_WEB_CLIENT_ID: the public OAuth web client ID. The same ID must be set in the backend environment and the GitHub Actions repository variable. It is the JWT audience, not a client secret.
- In Google Cloud Console configure the OAuth consent screen, create a Web OAuth client, and create an Android OAuth client for package com.etventixdev.zyrox with the SHA-1 fingerprint of the APK's signing certificate. Add test accounts while the consent screen is in testing; submit for verification before public production use. The app uses online sign-in only and does not request a Google refresh token.
- For GitHub Actions debug APKs, register the SHA-1 for the certificate that signs the APK. To make that certificate stable across runners, create a dedicated debug keystore locally with the Android debug defaults (alias androiddebugkey, store/key password android), base64-encode the keystore, and save the encoded value as the GitHub Actions secret ANDROID_DEBUG_KEYSTORE_BASE64. The workflow installs it as the runner's debug keystore; never commit the keystore or print its secret value. Register that keystore's SHA-1 in the Android OAuth client. Without this secret, GitHub's runner-generated debug key may differ and Google Sign-In may fail in the downloaded APK. To create a matching debug key on Linux/macOS, run:

    keytool -genkeypair -v -keystore zyrox-debug.keystore -storepass android -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=ZYROX,C=US"
    keytool -list -v -keystore zyrox-debug.keystore -alias androiddebugkey -storepass android
    base64 -w 0 zyrox-debug.keystore > zyrox-debug-keystore.b64

Register the SHA-1 printed by keytool in the Android OAuth client, then save the base64 file contents as the GitHub Actions secret named ANDROID_DEBUG_KEYSTORE_BASE64. Do not commit either file. This debug key is for test APKs only, not a production release key.

Optional/recommended:

- NODE_ENV=production enables Secure refresh cookies.
- DATABASE_SSL=true when the database provider requires TLS and its certificate is trusted by Node.
- PORT is supplied by many hosts; defaults to 3000.
- ALLOWED_ORIGINS is a comma-separated list of browser origins, such as https://app.example.com. Capacitor's https://localhost and capacitor://localhost origins are allowed by default. Do not use a wildcard.
- TRUST_PROXY should equal the number of trusted reverse proxies in front of the service; many managed app hosts use 1.
- SMTP_HOST, SMTP_PORT, SMTP_SECURE, SMTP_FROM, SMTP_USER, and SMTP_PASSWORD configure transactional email for password resets. The code expires after 10 minutes.

If SMTP is missing, sign-up and sign-in work but password recovery returns a setup message. If GOOGLE_WEB_CLIENT_ID is missing, the Google route is disabled and the Google button stays disabled.

## Database and local run

From this directory:

    cp .env.example .env
    # Edit .env locally with PostgreSQL, a generated JWT_SECRET, and the OAuth audience if used.
    npm ci
    npm run migrate
    npm start

Run the migration against an empty PostgreSQL database before starting the service. It is idempotent and creates users, auth_sessions, and password_resets, plus the Google subject index. Back up the database and keep TLS enabled when supported.

## Hosting and network security

1. Provision managed PostgreSQL and a Node.js 20+ web service. Set the service working directory to server; install with npm ci, run npm run migrate once as a release/pre-deploy command, and start with npm start.
2. Configure DATABASE_URL, JWT_SECRET, NODE_ENV=production, DATABASE_SSL as required, TRUST_PROXY, GOOGLE_WEB_CLIENT_ID, and SMTP settings in the host environment. Keep the JWT signing secret, SMTP credentials, and database URL in the host's secret manager.
3. Publish the API over HTTPS. Allow public inbound traffic only through the provider's HTTPS ingress on port 443; do not expose PostgreSQL publicly. Prefer a private database network, or restrict the database firewall to the backend service's network/egress IPs. Restrict backend egress to the database, the configured SMTP service, and Google's token-signing keys endpoint as required by the host.
4. Add any browser app origin to ALLOWED_ORIGINS. The native Capacitor origins are built in.
5. In GitHub repository settings, add Actions variables named ZYROX_API_URL (public HTTPS API base URL, no trailing slash) and GOOGLE_WEB_CLIENT_ID (public web OAuth client ID). The workflow writes both to www/config.js at build time. They are public configuration, not credentials. For local builds, edit www/config.js yourself.
6. Run Build ZYROX APK and download its ZYROX-APK debug artifact. This is for testing, not a Play Store release-signed build.

Application-level protections are in the API code: Helmet security headers, strict origin allowlisting, a custom request header on mutations, parameterized SQL, password and reset-code hashing, refresh rotation/revocation, bounded request bodies, and rate limits. Rate limits use an in-memory per-process store; before running multiple backend replicas, configure a shared rate-limit store. The network firewall, TLS ingress, database ACLs, egress policy, SMTP provider, and OAuth Console settings must be configured on the deployment platform; this repository cannot change those external controls without a host/project to target.

## Routes

- POST /api/auth/register: username, email, password.
- POST /api/auth/login: email/password.
- POST /api/auth/google: Google ID token; server checks signature, issuer, audience, expiry, and verified email before creating/linking a ZYROX account.
- POST /api/auth/refresh: rotates the HttpOnly refresh cookie and returns a new access token.
- POST /api/auth/logout: revokes the current session and clears its cookie.
- GET /api/auth/me: active profile; requires a bearer access token.
- POST /api/auth/forgot-password and POST /api/auth/reset-password: one-time email recovery.
- POST /api/auth/password: authenticated password change; revokes existing sessions.
- GET /api/health: health check.

## Verification

Run npm test in this directory. Tests cover registration/password hashing, valid and invalid login, session refresh/rotation across app recreation, logout/revocation, email recovery, Google account creation/linking with an injected verifier, and validation/origin checks using an in-memory PostgreSQL-compatible database. Before launch, test with a real PostgreSQL database, an SMTP mailbox, registered Google OAuth client IDs, and an Android build signed with the registered SHA-1 certificate. No live service, OAuth credentials, email provider, or production firewall is configured by this source change.
