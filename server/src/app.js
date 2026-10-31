const crypto = require("node:crypto");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const { hashSecret, verifySecret, digest, signAccessToken, verifyAccessToken } = require("./security");
const { verifyGoogleIdToken } = require("./google-auth");

const SESSION_DAYS = 30;
const RESET_MINUTES = 10;
const REFRESH_COOKIE = "zyrox_refresh";
const EMAIL_RE = /^[A-Za-z0-9.!#$%&'*+?^_~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}
function validUsername(value) {
  return typeof value === "string" && /^[a-zA-Z0-9_]{3,24}$/.test(value);
}
function validPassword(value) {
  return typeof value === "string" && value.length >= 12 && value.length <= 128;
}
function publicUser(row) {
  return { id: row.id, username: row.username, email: row.email };
}
function cookieValue(req, key) {
  const header = req.headers.cookie || "";
  for (const part of header.split(";")) {
    const item = part.trim();
    const at = item.indexOf("=");
    if (at >= 0 && item.slice(0, at) === key) return decodeURIComponent(item.slice(at + 1));
  }
  return "";
}
function writeRefreshCookie(res, value, secure, maxAgeSeconds = SESSION_DAYS * 24 * 60 * 60) {
  const pieces = [REFRESH_COOKIE + "=" + encodeURIComponent(value), "Path=/api/auth", "Max-Age=" + maxAgeSeconds, "HttpOnly", "SameSite=None"];
  if (secure) pieces.push("Secure");
  res.setHeader("Set-Cookie", pieces.join("; "));
}
function clearRefreshCookie(res, secure) {
  writeRefreshCookie(res, "", secure, 0);
}
function createApp({ pool, jwtSecret, allowedOrigins = [], mailer = null, secureCookies = true, trustProxy = false, googleWebClientId = "", googleVerifier = verifyGoogleIdToken }) {
  if (!pool || !jwtSecret) throw new Error("A database pool and JWT secret are required");
  const app = express();
  if (trustProxy) app.set("trust proxy", trustProxy);
  app.disable("x-powered-by");
  app.use(helmet());
  const origins = new Set(allowedOrigins);
  app.use(cors({
    origin(origin, callback) {
      if (!origin || origins.has(origin)) return callback(null, true);
      return callback(new Error("Origin not allowed"));
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Zyrox-Request"],
    maxAge: 600
  }));
  app.use(express.json({ limit: "16kb" }));
  app.use("/api", (req, res, next) => {
    if (req.method === "POST" && req.get("X-Zyrox-Request") !== "1") {
      return res.status(403).json({ error: "Request verification failed. Please reload the app and try again." });
    }
    next();
  });
  app.use("/api/auth", (req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
  });
  const registerLimit = rateLimit({ windowMs: 60 * 60 * 1000, limit: 8, standardHeaders: "draft-8", legacyHeaders: false, message: { error: "Too many account attempts. Try again later." } });
  const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: "draft-8", legacyHeaders: false, message: { error: "Too many sign-in attempts. Wait a few minutes and try again." } });
  const resetLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 3, standardHeaders: "draft-8", legacyHeaders: false, message: { error: "Too many recovery requests. Try again later." } });

  async function issueSession(user, res) {
    const id = crypto.randomUUID();
    const secret = crypto.randomBytes(32).toString("base64url");
    const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
    await pool.query(
      "INSERT INTO auth_sessions (id, user_id, refresh_hash, expires_at) VALUES ($1, $2, $3, $4)",
      [id, user.id, digest(secret), expiresAt]
    );
    writeRefreshCookie(res, id + "." + secret, secureCookies);
    return { accessToken: signAccessToken({ sub: user.id, sid: id }, jwtSecret), user: publicUser(user) };
  }

  async function requireAuth(req, res, next) {
    const header = req.get("Authorization") || "";
    const match = /^Bearer\s+(.+)$/i.exec(header);
    const claims = match && verifyAccessToken(match[1], jwtSecret);
    if (!claims) return res.status(401).json({ error: "Your session expired. Sign in again." });
    try {
      const result = await pool.query(
        "SELECT u.id, u.username, u.email FROM auth_sessions s JOIN users u ON u.id = s.user_id WHERE s.id = $1 AND s.user_id = $2 AND s.revoked_at IS NULL AND s.expires_at > NOW()",
        [claims.sid, claims.sub]
      );
      if (!result.rows[0]) return res.status(401).json({ error: "Your session expired. Sign in again." });
      req.user = result.rows[0];
      req.sessionId = claims.sid;
      next();
    } catch (error) {
      next(error);
    }
  }

  app.get("/api/health", (req, res) => res.json({ status: "ok" }));

  app.post("/api/auth/register", registerLimit, async (req, res, next) => {
    try {
      const username = String(req.body?.username || "").trim();
      const email = normalizeEmail(req.body?.email);
      const password = req.body?.password;
      if (!validUsername(username)) return res.status(400).json({ error: "Username must be 3–24 characters using letters, numbers, or underscores." });
      if (email.length > 254 || !EMAIL_RE.test(email)) return res.status(400).json({ error: "Enter a valid email address." });
      if (!validPassword(password)) return res.status(400).json({ error: "Use a password between 12 and 128 characters." });
      const passwordHash = await hashSecret(password);
      const id = crypto.randomUUID();
      let result;
      try {
        result = await pool.query(
          "INSERT INTO users (id, username, username_key, email, password_hash) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, email",
          [id, username, username.toLowerCase(), email, passwordHash]
        );
      } catch (error) {
        if (error.code === "23505") return res.status(409).json({ error: "That email or username is already registered." });
        throw error;
      }
      return res.status(201).json(await issueSession(result.rows[0], res));
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/auth/login", loginLimit, async (req, res, next) => {
    try {
      const email = normalizeEmail(req.body?.email);
      const password = req.body?.password;
      if (email.length > 254 || !EMAIL_RE.test(email) || typeof password !== "string" || password.length > 128) {
        return res.status(400).json({ error: "Enter your email and password." });
      }
      const result = await pool.query("SELECT id, username, email, password_hash FROM users WHERE email = $1", [email]);
      const user = result.rows[0];
      const matches = user ? await verifySecret(password, user.password_hash) : await (async () => {
        await hashSecret(password);
        return false;
      })();
      if (!user || !matches) return res.status(401).json({ error: "Email or password is incorrect." });
      return res.json(await issueSession(user, res));
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/auth/google", loginLimit, async (req, res, next) => {
    try {
      if (!googleWebClientId) return res.status(503).json({ error: "Google sign-in is not configured yet. Please contact the app owner." });
      const idToken = req.body?.idToken;
      if (typeof idToken !== "string" || idToken.length < 20 || idToken.length > 12000) {
        return res.status(400).json({ error: "Google did not return a valid sign-in token. Try again." });
      }
      let identity;
      try {
        identity = await googleVerifier(idToken, googleWebClientId);
      } catch {
        return res.status(401).json({ error: "Google sign-in could not be verified. Try again." });
      }
      const email = normalizeEmail(identity?.email);
      const subject = String(identity?.sub || "");
      if (!subject || subject.length > 255 || identity?.email_verified !== true || !EMAIL_RE.test(email)) {
        return res.status(401).json({ error: "Google must verify your email before this account can be used." });
      }

      const lookup = async () => pool.query(
        "SELECT id, username, email, google_sub FROM users WHERE google_sub = $1 OR email = $2",
        [subject, email]
      );
      const linkOrFind = async () => {
        const found = await lookup();
        if (found.rows.length > 1) return { conflict: true };
        const existing = found.rows[0];
        if (!existing) return { user: null };
        if (existing.google_sub && existing.google_sub !== subject) return { conflict: true };
        if (!existing.google_sub) {
          const linked = await pool.query(
            "UPDATE users SET google_sub = $1 WHERE id = $2 AND COALESCE(google_sub, $1) = $1 RETURNING id, username, email, google_sub",
            [subject, existing.id]
          );
          if (!linked.rows[0]) return { conflict: true };
          return { user: linked.rows[0] };
        }
        return { user: existing };
      };

      let found = await linkOrFind();
      if (found.conflict) return res.status(409).json({ error: "This Google account is linked to a different ZYROX account." });
      if (found.user) return res.json(await issueSession(found.user, res));

      const passwordHash = await hashSecret(crypto.randomBytes(32).toString("base64url"));
      const prefix = (email.split("@")[0].replace(/[^a-zA-Z0-9_]/g, "").slice(0, 15) || "player");
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const suffix = crypto.createHash("sha256").update(subject + ":" + attempt + ":" + crypto.randomBytes(4).toString("hex")).digest("hex").slice(0, 6);
        const username = (prefix.length >= 3 ? prefix : "player").slice(0, 17) + "_" + suffix;
        try {
          const created = await pool.query(
            "INSERT INTO users (id, username, username_key, email, password_hash, google_sub) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, username, email, google_sub",
            [crypto.randomUUID(), username, username.toLowerCase(), email, passwordHash, subject]
          );
          return res.status(201).json(await issueSession(created.rows[0], res));
        } catch (error) {
          if (error.code !== "23505") throw error;
          found = await linkOrFind();
          if (found.conflict) return res.status(409).json({ error: "This Google account is linked to a different ZYROX account." });
          if (found.user) return res.json(await issueSession(found.user, res));
          if (attempt === 4) return res.status(409).json({ error: "Could not create a ZYROX username. Please try again." });
        }
      }
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/auth/refresh", async (req, res, next) => {
    try {
      const presented = cookieValue(req, REFRESH_COOKIE);
      const [id, secret, ...extra] = presented.split(".");
      if (!id || !secret || extra.length || !/^[0-9a-f-]{36}$/i.test(id)) {
        clearRefreshCookie(res, secureCookies);
        return res.status(401).json({ error: "Please sign in to continue." });
      }
      const result = await pool.query(
        "SELECT s.id, s.user_id, s.refresh_hash, s.expires_at, s.revoked_at, u.username, u.email FROM auth_sessions s JOIN users u ON u.id = s.user_id WHERE s.id = $1",
        [id]
      );
      const row = result.rows[0];
      if (!row || row.revoked_at || new Date(row.expires_at).getTime() <= Date.now() || !safeDigestMatch(digest(secret), row.refresh_hash)) {
        clearRefreshCookie(res, secureCookies);
        return res.status(401).json({ error: "Please sign in to continue." });
      }
      const nextSecret = crypto.randomBytes(32).toString("base64url");
      const nextExpiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
      const rotated = await pool.query(
        "UPDATE auth_sessions SET refresh_hash = $1, expires_at = $2 WHERE id = $3 AND refresh_hash = $4 AND revoked_at IS NULL AND expires_at > NOW() RETURNING user_id",
        [digest(nextSecret), nextExpiresAt, id, row.refresh_hash]
      );
      if (!rotated.rows[0]) {
        clearRefreshCookie(res, secureCookies);
        return res.status(401).json({ error: "Please sign in to continue." });
      }
      writeRefreshCookie(res, id + "." + nextSecret, secureCookies);
      return res.json({ accessToken: signAccessToken({ sub: row.user_id, sid: id }, jwtSecret), user: { id: row.user_id, username: row.username, email: row.email } });
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/auth/logout", async (req, res, next) => {
    try {
      const presented = cookieValue(req, REFRESH_COOKIE);
      const id = presented.split(".")[0];
      if (/^[0-9a-f-]{36}$/i.test(id)) {
        await pool.query("UPDATE auth_sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL", [id]);
      }
      clearRefreshCookie(res, secureCookies);
      return res.json({ message: "Signed out." });
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/auth/me", requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

  app.post("/api/auth/forgot-password", resetLimit, async (req, res, next) => {
    try {
      const email = normalizeEmail(req.body?.email);
      if (email.length > 254 || !EMAIL_RE.test(email)) return res.status(400).json({ error: "Enter a valid email address." });
      if (!mailer || typeof mailer.sendPasswordReset !== "function") {
        return res.status(503).json({ error: "Password recovery is not configured yet. Please contact the app owner." });
      }
      const result = await pool.query("SELECT id, username, email FROM users WHERE email = $1", [email]);
      const user = result.rows[0];
      if (user) {
        const code = String(crypto.randomInt(0, 100000000)).padStart(8, "0");
        const codeHash = await hashSecret(code);
        await pool.query(
          "INSERT INTO password_resets (id, user_id, code_hash, expires_at, attempts) VALUES ($1, $2, $3, $4, 0) ON CONFLICT (user_id) DO UPDATE SET id = EXCLUDED.id, code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at, attempts = 0, created_at = NOW()",
          [crypto.randomUUID(), user.id, codeHash, new Date(Date.now() + RESET_MINUTES * 60 * 1000)]
        );
        try {
          await mailer.sendPasswordReset({ to: user.email, username: user.username, code });
        } catch {
          await pool.query("DELETE FROM password_resets WHERE user_id = $1", [user.id]);
          return res.json({ message: "If that address is registered, a reset code will be emailed." });
        }
      }
      return res.json({ message: "If that address is registered, a reset code will be emailed." });
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/auth/reset-password", resetLimit, async (req, res, next) => {
    try {
      const email = normalizeEmail(req.body?.email);
      const code = String(req.body?.code || "").trim();
      const newPassword = req.body?.newPassword;
      if (!EMAIL_RE.test(email) || !/^\d{8}$/.test(code) || !validPassword(newPassword)) {
        return res.status(400).json({ error: "Check the email, 8-digit code, and new password." });
      }
      const result = await pool.query(
        "SELECT r.id, r.user_id, r.code_hash, r.expires_at, r.attempts FROM password_resets r JOIN users u ON u.id = r.user_id WHERE u.email = $1",
        [email]
      );
      const reset = result.rows[0];
      if (!reset || reset.attempts >= 5 || new Date(reset.expires_at).getTime() <= Date.now()) {
        return res.status(400).json({ error: "That reset code is invalid or expired. Request a new one." });
      }
      if (!await verifySecret(code, reset.code_hash)) {
        await pool.query("UPDATE password_resets SET attempts = attempts + 1 WHERE id = $1", [reset.id]);
        return res.status(400).json({ error: "That reset code is invalid or expired. Request a new one." });
      }
      const passwordHash = await hashSecret(newPassword);
      const consumed = await pool.query(
        "DELETE FROM password_resets WHERE id = $1 AND code_hash = $2 AND attempts < 5 AND expires_at > NOW() RETURNING user_id",
        [reset.id, reset.code_hash]
      );
      if (!consumed.rows[0]) return res.status(400).json({ error: "That reset code is invalid or expired. Request a new one." });
      const userId = consumed.rows[0].user_id;
      await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [passwordHash, userId]);
      await pool.query("UPDATE auth_sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL", [userId]);
      clearRefreshCookie(res, secureCookies);
      return res.json({ message: "Password updated. Sign in with your new password." });
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/auth/password", requireAuth, async (req, res, next) => {
    try {
      const currentPassword = req.body?.currentPassword;
      const newPassword = req.body?.newPassword;
      if (!validPassword(newPassword)) return res.status(400).json({ error: "Use a new password between 12 and 128 characters." });
      const result = await pool.query("SELECT password_hash FROM users WHERE id = $1", [req.user.id]);
      if (!result.rows[0] || !await verifySecret(String(currentPassword || ""), result.rows[0].password_hash)) {
        return res.status(400).json({ error: "Current password is incorrect." });
      }
      const passwordHash = await hashSecret(newPassword);
      await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [passwordHash, req.user.id]);
      await pool.query("UPDATE auth_sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL", [req.user.id]);
      clearRefreshCookie(res, secureCookies);
      return res.json({ message: "Password changed. Sign in again with your new password." });
    } catch (error) {
      next(error);
    }
  });

  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    if (error.message === "Origin not allowed") return res.status(403).json({ error: "This app origin is not allowed." });
    if (error.type === "entity.parse.failed") return res.status(400).json({ error: "Request body must be valid JSON." });
    console.error("ZYROX API request failed:", error.message);
    return res.status(500).json({ error: "Something went wrong. Please try again." });
  });
  return app;
}

function safeDigestMatch(left, right) {
  const a = Buffer.from(String(left || ""));
  const b = Buffer.from(String(right || ""));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

module.exports = { createApp };
