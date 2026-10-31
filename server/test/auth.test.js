const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { newDb } = require("pg-mem");
const { createApp } = require("../src/app");

const jwtSecret = "test-only-secret-value-with-at-least-32-bytes";
const migration = fs.readFileSync(path.join(__dirname, "../migrations/001_auth.sql"), "utf8");

async function makeFixture(options = {}) {
  const db = newDb({ autoCreateForeignKeyIndices: true });
  const { Pool } = db.adapters.createPg();
  const pool = new Pool();
  for (const statement of migration.split(";").map(part => part.trim()).filter(Boolean)) await pool.query(statement);
  const app = createApp({ pool, jwtSecret, allowedOrigins: ["https://localhost"], secureCookies: false, ...options });
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const base = "http://127.0.0.1:" + address.port;
  return { pool, app, server, base, close: () => new Promise(resolve => server.close(resolve)) };
}

function headers(extra = {}) {
  return { "Content-Type": "application/json", "X-Zyrox-Request": "1", ...extra };
}
function firstCookie(response) {
  const value = response.headers.get("set-cookie");
  assert.ok(value, "auth response should set a refresh cookie");
  return value.split(";")[0];
}
async function post(base, path, body, extra = {}) {
  return fetch(base + path, { method: "POST", headers: headers(extra), body: JSON.stringify(body) });
}

const validAccount = { username: "NeonRider", email: "player@example.com", password: "Correct horse battery 2026!" };

test("registration creates a scrypt hash and refresh sessions survive app restart then logout revokes them", async () => {
  const fixture = await makeFixture();
  try {
    const registered = await post(fixture.base, "/api/auth/register", validAccount);
    assert.equal(registered.status, 201);
    const session = await registered.json();
    assert.equal(session.user.username, validAccount.username);
    assert.ok(session.accessToken);
    let cookie = firstCookie(registered);

    const stored = await fixture.pool.query("SELECT password_hash FROM users WHERE email = $1", [validAccount.email]);
    assert.match(stored.rows[0].password_hash, /^scrypt\$/);
    assert.notEqual(stored.rows[0].password_hash, validAccount.password);

    const profileResponse = await fetch(fixture.base + "/api/auth/me", { headers: { Authorization: "Bearer " + session.accessToken } });
    assert.equal(profileResponse.status, 200);
    assert.equal((await profileResponse.json()).user.email, validAccount.email);

    const restarted = await makeFixtureWithPool(fixture.pool);
    try {
      const refreshed = await post(restarted.base, "/api/auth/refresh", {}, { Cookie: cookie });
      assert.equal(refreshed.status, 200);
      const renewed = await refreshed.json();
      assert.equal(renewed.user.id, session.user.id);
      const rotatedCookie = firstCookie(refreshed);

      const replay = await post(restarted.base, "/api/auth/refresh", {}, { Cookie: cookie });
      assert.equal(replay.status, 401, "a rotated refresh cookie must not be reusable");

      const logout = await post(restarted.base, "/api/auth/logout", {}, { Cookie: rotatedCookie });
      assert.equal(logout.status, 200);
      const afterLogout = await post(restarted.base, "/api/auth/refresh", {}, { Cookie: rotatedCookie });
      assert.equal(afterLogout.status, 401);
      const profileAfterLogout = await fetch(restarted.base + "/api/auth/me", { headers: { Authorization: "Bearer " + renewed.accessToken } });
      assert.equal(profileAfterLogout.status, 401);
    } finally {
      await restarted.close();
    }
  } finally {
    await fixture.close();
    await fixture.pool.end();
  }
});

async function makeFixtureWithPool(pool, options = {}) {
  const app = createApp({ pool, jwtSecret, allowedOrigins: ["https://localhost"], secureCookies: false, ...options });
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  return { server, base: "http://127.0.0.1:" + server.address().port, close: () => new Promise(resolve => server.close(resolve)) };
}

test("login validates credentials and issues a persistent session cookie", async () => {
  const fixture = await makeFixture();
  try {
    await post(fixture.base, "/api/auth/register", validAccount);
    const login = await post(fixture.base, "/api/auth/login", { email: validAccount.email, password: validAccount.password });
    assert.equal(login.status, 200);
    assert.ok(firstCookie(login));
    assert.equal((await login.json()).user.username, validAccount.username);

    const wrong = await post(fixture.base, "/api/auth/login", { email: validAccount.email, password: "wrong password" });
    assert.equal(wrong.status, 401);
    assert.match((await wrong.json()).error, /incorrect/i);
  } finally {
    await fixture.close();
    await fixture.pool.end();
  }
});

test("email reset code is one-time, expires through database state, and changes the login password", async () => {
  let sentCode = "";
  const mailer = { async sendPasswordReset(message) { sentCode = message.code; } };
  const fixture = await makeFixture({ mailer });
  try {
    await post(fixture.base, "/api/auth/register", validAccount);
    const requested = await post(fixture.base, "/api/auth/forgot-password", { email: validAccount.email });
    assert.equal(requested.status, 200);
    assert.match((await requested.json()).message, /if that address is registered/i);
    assert.match(sentCode, /^\d{8}$/);

    const reset = await post(fixture.base, "/api/auth/reset-password", {
      email: validAccount.email,
      code: sentCode,
      newPassword: "New secure ZYROX password!"
    });
    assert.equal(reset.status, 200);
    const oldLogin = await post(fixture.base, "/api/auth/login", { email: validAccount.email, password: validAccount.password });
    assert.equal(oldLogin.status, 401);
    const newLogin = await post(fixture.base, "/api/auth/login", { email: validAccount.email, password: "New secure ZYROX password!" });
    assert.equal(newLogin.status, 200);

    const reuse = await post(fixture.base, "/api/auth/reset-password", {
      email: validAccount.email,
      code: sentCode,
      newPassword: "Another secure ZYROX password!"
    });
    assert.equal(reuse.status, 400);
  } finally {
    await fixture.close();
    await fixture.pool.end();
  }
});

test("Google ID tokens create accounts and securely link existing verified-email accounts", async () => {
  let identity = { sub: "google-sub-001", email: "google.player@example.com", email_verified: true };
  const fixture = await makeFixture({
    googleWebClientId: "public-web-client-id.apps.googleusercontent.com",
    googleVerifier: async (token, audience) => {
      assert.equal(token, "verified-google-id-token-for-test");
      assert.equal(audience, "public-web-client-id.apps.googleusercontent.com");
      return identity;
    }
  });
  try {
    const google = await post(fixture.base, "/api/auth/google", { idToken: "verified-google-id-token-for-test" });
    assert.equal(google.status, 201);
    const googleAccount = await google.json();
    assert.equal(googleAccount.user.email, identity.email);
    assert.ok(firstCookie(google));
    assert.ok(googleAccount.accessToken);

    const passwordAccount = await post(fixture.base, "/api/auth/register", {
      username: "LinkedPlayer", email: "linked@example.com", password: "Correct horse battery 2026!"
    });
    const passwordUser = (await passwordAccount.json()).user;
    identity = { sub: "google-sub-002", email: "linked@example.com", email_verified: true };
    const linked = await post(fixture.base, "/api/auth/google", { idToken: "verified-google-id-token-for-test" });
    const linkedBody = await linked.json();
    assert.equal(linked.status, 200, JSON.stringify(linkedBody));
    assert.equal(linkedBody.user.id, passwordUser.id);
    const storedLink = await fixture.pool.query("SELECT google_sub FROM users WHERE id = $1", [passwordUser.id]);
    assert.equal(storedLink.rows[0].google_sub, identity.sub);

    identity = { sub: "google-sub-003", email: "linked@example.com", email_verified: true };
    const conflicting = await post(fixture.base, "/api/auth/google", { idToken: "verified-google-id-token-for-test" });
    assert.equal(conflicting.status, 409);

    identity = { sub: "google-sub-unverified", email: "unverified@example.com", email_verified: false };
    const unverified = await post(fixture.base, "/api/auth/google", { idToken: "verified-google-id-token-for-test" });
    assert.equal(unverified.status, 401);
  } finally {
    await fixture.close();
    await fixture.pool.end();
  }
});

test("Google sign-in is disabled until configured and rejects unverifiable tokens", async () => {
  const disabled = await makeFixture();
  try {
    const response = await post(disabled.base, "/api/auth/google", { idToken: "verified-google-id-token-for-test" });
    assert.equal(response.status, 503);
  } finally {
    await disabled.close();
    await disabled.pool.end();
  }

  const configured = await makeFixture({
    googleWebClientId: "public-web-client-id.apps.googleusercontent.com",
    googleVerifier: async () => { throw new Error("invalid signature"); }
  });
  try {
    const response = await post(configured.base, "/api/auth/google", { idToken: "verified-google-id-token-for-test" });
    assert.equal(response.status, 401);
  } finally {
    await configured.close();
    await configured.pool.end();
  }
});

test("registration enforces username and password rules and refuses unverified cross-origin writes", async () => {
  const fixture = await makeFixture();
  try {
    const bad = await post(fixture.base, "/api/auth/register", { ...validAccount, username: "x", password: "short" });
    assert.equal(bad.status, 400);
    const recipientList = await post(fixture.base, "/api/auth/register", { ...validAccount, email: "player@example.com,attacker@evil.com" });
    assert.equal(recipientList.status, 400, "registration must reject recipient-list syntax");
    const unverified = await fetch(fixture.base + "/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://attacker.example" },
      body: JSON.stringify(validAccount)
    });
    assert.equal(unverified.status, 403);
  } finally {
    await fixture.close();
    await fixture.pool.end();
  }
});
