const crypto = require("node:crypto");
const { promisify } = require("node:util");

const scrypt = promisify(crypto.scrypt);
const HASH_N = 1 << 15;
const HASH_R = 8;
const HASH_P = 1;
const KEY_LENGTH = 64;
const MAXMEM = 64 * 1024 * 1024;

async function hashSecret(value) {
  const salt = crypto.randomBytes(16);
  const derived = await scrypt(value, salt, KEY_LENGTH, { N: HASH_N, r: HASH_R, p: HASH_P, maxmem: MAXMEM });
  return ["scrypt", HASH_N, HASH_R, HASH_P, salt.toString("base64url"), Buffer.from(derived).toString("base64url")].join("$");
}

async function verifySecret(value, encoded) {
  try {
    const [algorithm, n, r, p, saltText, keyText] = encoded.split("$");
    if (algorithm !== "scrypt") return false;
    const salt = Buffer.from(saltText, "base64url");
    const expected = Buffer.from(keyText, "base64url");
    if (salt.length !== 16 || expected.length !== KEY_LENGTH) return false;
    const actual = Buffer.from(await scrypt(value, salt, expected.length, {
      N: Number(n), r: Number(r), p: Number(p), maxmem: MAXMEM
    }));
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("base64url");
}

function safeEqualText(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function signAccessToken(payload, secret, now = Date.now()) {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify({ ...payload, iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + 900 })).toString("base64url");
  const unsigned = header + "." + body;
  const signature = crypto.createHmac("sha256", secret).update(unsigned).digest("base64url");
  return unsigned + "." + signature;
}

function verifyAccessToken(token, secret, now = Date.now()) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  const unsigned = parts[0] + "." + parts[1];
  const expected = crypto.createHmac("sha256", secret).update(unsigned).digest("base64url");
  if (!safeEqualText(parts[2], expected)) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    if (header.alg !== "HS256" || !payload.sub || !payload.sid || !Number.isFinite(payload.exp) || payload.exp <= Math.floor(now / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

module.exports = { hashSecret, verifySecret, digest, signAccessToken, verifyAccessToken };
