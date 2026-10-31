let remoteKeys;

async function verifyGoogleIdToken(idToken, audience) {
  if (!audience) throw new Error("Google sign-in is not configured");
  const { createRemoteJWKSet, jwtVerify } = await import("jose");
  if (!remoteKeys) remoteKeys = createRemoteJWKSet(new URL("https://www.googleapis.com/oauth2/v3/certs"));
  const { payload } = await jwtVerify(idToken, remoteKeys, {
    audience,
    issuer: ["https://accounts.google.com", "accounts.google.com"],
    requiredClaims: ["exp", "iat", "sub", "email", "email_verified"],
    maxTokenAge: "1h"
  });
  return payload;
}

module.exports = { verifyGoogleIdToken };
