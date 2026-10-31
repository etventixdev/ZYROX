import { SocialLogin } from "@capgo/capacitor-social-login";

let initializedWith = "";

export async function initializeGoogle(webClientId) {
  if (!webClientId) return false;
  if (initializedWith === webClientId) return true;
  await SocialLogin.initialize({
    google: {
      webClientId,
      mode: "online"
    }
  });
  initializedWith = webClientId;
  return true;
}

export async function signInWithGoogle() {
  if (!initializedWith) throw new Error("Google sign-in is not configured.");
  const response = await SocialLogin.login({
    provider: "google",
    options: { scopes: ["profile", "email"], prompt: "select_account" }
  });
  if (response.provider !== "google" || response.result.responseType !== "online" || !response.result.idToken) {
    throw new Error("Google did not return an ID token. Try again.");
  }
  return response.result.idToken;
}

export async function signOutFromGoogle() {
  if (!initializedWith) return;
  await SocialLogin.logout({ provider: "google" });
}
