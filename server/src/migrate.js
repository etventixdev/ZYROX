require("dotenv").config();
const fs = require("node:fs");
const path = require("node:path");
const { Pool } = require("pg");

async function main() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: true } : undefined });
  try {
    const sql = fs.readFileSync(path.join(__dirname, "../migrations/001_auth.sql"), "utf8");
    await pool.query(sql);
    console.log("ZYROX authentication schema is ready.");
  } finally {
    await pool.end();
  }
}

main().catch(error => {
  console.error("Database migration failed:", error.message);
  process.exitCode = 1;
});
