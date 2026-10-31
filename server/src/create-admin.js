require("dotenv").config();
const { Pool } = require("pg");
const crypto = require("node:crypto");
const { hashSecret } = require("./security");

async function main() {
  const email = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const username = String(process.env.ADMIN_USERNAME || "").trim();
  const password = process.env.ADMIN_INITIAL_PASSWORD || "";

  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
  if (!email || !username || password.length < 16 || password.length > 128) {
    throw new Error("Set ADMIN_EMAIL, ADMIN_USERNAME and a 16–128 character ADMIN_INITIAL_PASSWORD.");
  }
  if (!/^[A-Za-z0-9_]{3,24}$/.test(username)) {
    throw new Error("ADMIN_USERNAME must be 3–24 letters, numbers or underscores.");
  }

  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  try {
    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1 OR username_key = $2",
      [email, username.toLowerCase()]
    );
    if (existing.rows.length) {
      throw new Error("That email or username already exists. Admin was not created or promoted.");
    }

    const passwordHash = await hashSecret(password);
    await pool.query(
      "INSERT INTO users (id, username, username_key, email, password_hash, role) VALUES ($1, $2, $3, $4, $5, 'admin')",
      [crypto.randomUUID(), username, username.toLowerCase(), email, passwordHash]
    );
    console.log("Initial ZYROX administrator created.");
    console.log("Sign in using the configured admin email and password.");
  } finally {
    await pool.end();
  }
}

main().catch(error => {
  console.error("Admin setup failed:", error.message);
  process.exitCode = 1;
});
