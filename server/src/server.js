require("dotenv").config();
const { Pool } = require("pg");
const nodemailer = require("nodemailer");
const { createApp } = require("./app");

const required = ["DATABASE_URL", "JWT_SECRET"];
const missing = required.filter(key => !process.env[key]);
if (missing.length) {
  console.error("Missing required server configuration:", missing.join(", "));
  process.exit(1);
}
if (Buffer.byteLength(process.env.JWT_SECRET, "utf8") < 32) {
  console.error("JWT_SECRET must contain at least 32 bytes.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: true } : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

let mailer = null;
if (process.env.SMTP_HOST && process.env.SMTP_FROM) {
  const transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === "true",
    requireTLS: process.env.SMTP_SECURE !== "true",
    disableFileAccess: true,
    disableUrlAccess: true,
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD || "" } : undefined
  });
  mailer = {
    async sendPasswordReset({ to, username, code }) {
      await transport.sendMail({
        from: process.env.SMTP_FROM,
        to,
        subject: "Your ZYROX password reset code",
        text: "Hi " + username + ",\n\nYour ZYROX password reset code is " + code + ". It expires in 10 minutes. If you did not request this, you can ignore this email.",
        html: "<p>Hi " + escapeHtml(username) + ",</p><p>Your ZYROX password reset code is <strong>" + code + "</strong>.</p><p>It expires in 10 minutes. If you did not request this, you can ignore this email.</p>"
      });
    }
  };
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[char]));
}

const allowedOrigins = ["https://localhost", "capacitor://localhost", "http://localhost"];
if (process.env.ALLOWED_ORIGINS) {
  allowedOrigins.push(...process.env.ALLOWED_ORIGINS.split(",").map(value => value.trim()).filter(Boolean));
}
const proxySetting = process.env.TRUST_PROXY || "0";
const trustProxy = /^\d+$/.test(proxySetting) ? Number(proxySetting) : false;
const app = createApp({
  pool,
  jwtSecret: process.env.JWT_SECRET,
  allowedOrigins,
  mailer,
  googleWebClientId: process.env.GOOGLE_WEB_CLIENT_ID || "",
  secureCookies: process.env.NODE_ENV === "production",
  trustProxy
});
const port = Number(process.env.PORT || 3000);
const server = app.listen(port, "0.0.0.0", () => console.log("ZYROX auth API listening on port " + port));

async function shutdown() {
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
