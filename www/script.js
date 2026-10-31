(() => {
  const rawApiUrl = window.ZYROX_CONFIG && window.ZYROX_CONFIG.apiBaseUrl;
  const apiBaseUrl = typeof rawApiUrl === "string" ? rawApiUrl.trim().replace(/\/+$/, "") : "";
  const googleWebClientId = window.ZYROX_CONFIG && window.ZYROX_CONFIG.googleWebClientId;
  let googleReady = false;
  let accessToken = "";
  let signedInUser = null;
  let toastTimer;

  const $ = (selector) => document.querySelector(selector);
  const panels = {
    login: $("#login-panel"),
    register: $("#register-panel"),
    forgot: $("#forgot-panel")
  };

  function emailLooksValid(value) {
    return /^[A-Za-z0-9.!#$%&'*+?^_~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/.test(String(value || "").trim());
  }

  function setError(id, message) {
    const element = $("#" + id);
    if (element) element.textContent = message || "";
  }

  function showToast(message) {
    const toast = $("#toast");
    toast.textContent = message;
    toast.classList.add("visible");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("visible"), 3600);
  }

  function openPanel(name) {
    if (!panels[name]) name = "login";
    Object.entries(panels).forEach(([key, panel]) => { panel.hidden = key !== name; });
    ["login-error", "register-error", "forgot-error", "reset-error", "google-error"].forEach(id => setError(id, ""));
    $("#google-entry").hidden = name === "forgot";
    if (name !== "forgot") $("#reset-step").hidden = true;
  }

  function setBusy(button, busy, label) {
    if (!button) return;
    if (busy) {
      button.dataset.originalLabel = button.querySelector("span")?.textContent || "Continue";
      button.disabled = true;
      if (button.querySelector("span")) button.querySelector("span").textContent = label || "Please wait…";
    } else {
      button.disabled = false;
      if (button.querySelector("span") && button.dataset.originalLabel) button.querySelector("span").textContent = button.dataset.originalLabel;
    }
  }

  async function request(path, options = {}) {
    if (!apiBaseUrl) throw new Error("Account services are not configured yet. Set the ZYROX API URL and rebuild the app.");
    let endpoint;
    try {
      endpoint = new URL(apiBaseUrl);
      if (endpoint.protocol !== "https:" && endpoint.hostname !== "localhost" && endpoint.hostname !== "127.0.0.1") {
        throw new Error("The account server must use HTTPS.");
      }
    } catch (error) {
      throw new Error(error.message === "The account server must use HTTPS." ? error.message : "The configured ZYROX API URL is invalid.");
    }
    const headers = { "X-Zyrox-Request": "1" };
    if (options.body !== undefined) headers["Content-Type"] = "application/json";
    if (options.auth && accessToken) headers.Authorization = "Bearer " + accessToken;
    let response;
    try {
      response = await fetch(apiBaseUrl + path, {
        method: options.method || "GET",
        credentials: "include",
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body)
      });
    } catch {
      throw new Error("Could not reach the ZYROX server. Check your connection and try again.");
    }
    let data = {};
    try { data = await response.json(); } catch { /* keep a clear fallback message */ }
    if (!response.ok) throw new Error(data.error || "Request failed. Please try again.");
    return data;
  }

  function showDashboard(user) {
    signedInUser = user;
    accessToken = accessToken || "";
    $("#auth-screen").hidden = true;
    $("#dashboard-screen").hidden = false;
    const username = user.username || "Player";
    $("#dashboard-username").textContent = username;
    $("#dashboard-title").textContent = "Good to have you back, " + username + ".";
    $("#dashboard-email").textContent = user.email || "";
    $("#settings-username").textContent = username;
    $("#settings-email").textContent = user.email || "";
    $("#avatar").textContent = Array.from(username.trim())[0]?.toUpperCase() || "Z";
  }

  function showSignedOut() {
    accessToken = "";
    signedInUser = null;
    $("#dashboard-screen").hidden = true;
    $("#auth-screen").hidden = false;
    openPanel("login");
  }

  function validPassword(value) {
    return typeof value === "string" && value.length >= 12 && value.length <= 128;
  }

  document.querySelectorAll("[data-open]").forEach(button => {
    button.addEventListener("click", () => openPanel(button.dataset.open));
  });

  document.querySelectorAll("[data-toggle-password]").forEach(button => {
    button.addEventListener("click", () => {
      const input = $("#" + button.dataset.togglePassword);
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      button.textContent = show ? "HIDE" : "SHOW";
      button.setAttribute("aria-label", show ? "Hide password" : "Show password");
    });
  });

  async function initializeGoogle() {
    const button = $("#google-login-button");
    const help = $("#google-help");
    if (!googleWebClientId) {
      help.textContent = "Google sign-in is waiting for the public OAuth client ID setup.";
      return;
    }
    if (!window.ZYROXGoogleAuth) {
      help.textContent = "Google sign-in module is missing. Rebuild the web bundle before syncing Android.";
      return;
    }
    try {
      await window.ZYROXGoogleAuth.initializeGoogle(googleWebClientId);
      googleReady = true;
      button.disabled = false;
      help.textContent = "";
    } catch {
      help.textContent = "Google sign-in could not start. Check the Android OAuth package and signing certificate.";
    }
  }

  $("#google-login-button").addEventListener("click", async event => {
    setError("google-error", "");
    if (!googleReady) return setError("google-error", "Google sign-in is not configured yet.");
    const button = event.currentTarget;
    setBusy(button, true, "Opening Google…");
    try {
      const idToken = await window.ZYROXGoogleAuth.signInWithGoogle();
      const result = await request("/api/auth/google", { method: "POST", body: { idToken } });
      accessToken = result.accessToken;
      showDashboard(result.user);
    } catch (error) {
      setError("google-error", error.message || "Google sign-in was cancelled. Try again.");
    } finally { setBusy(button, false); }
  });

  $("#login-form").addEventListener("submit", async event => {
    event.preventDefault();
    setError("login-error", "");
    const email = $("#login-email").value.trim();
    const password = $("#login-password").value;
    if (!emailLooksValid(email)) return setError("login-error", "Enter a valid email address.");
    if (!password) return setError("login-error", "Enter your password.");
    const button = event.currentTarget.querySelector("button[type=submit]");
    setBusy(button, true, "Signing in…");
    try {
      const result = await request("/api/auth/login", { method: "POST", body: { email, password } });
      accessToken = result.accessToken;
      showDashboard(result.user);
    } catch (error) {
      setError("login-error", error.message);
    } finally { setBusy(button, false); }
  });

  $("#register-form").addEventListener("submit", async event => {
    event.preventDefault();
    setError("register-error", "");
    const username = $("#register-username").value.trim();
    const email = $("#register-email").value.trim();
    const password = $("#register-password").value;
    const confirmation = $("#register-confirm").value;
    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) return setError("register-error", "Use 3–24 letters, numbers, or underscores for your username.");
    if (!emailLooksValid(email)) return setError("register-error", "Enter a valid email address.");
    if (!validPassword(password)) return setError("register-error", "Use a password between 12 and 128 characters.");
    if (password !== confirmation) return setError("register-error", "Those passwords don’t match.");
    const button = event.currentTarget.querySelector("button[type=submit]");
    setBusy(button, true, "Creating account…");
    try {
      const result = await request("/api/auth/register", { method: "POST", body: { username, email, password } });
      accessToken = result.accessToken;
      showDashboard(result.user);
    } catch (error) {
      setError("register-error", error.message);
    } finally { setBusy(button, false); }
  });

  $("#forgot-form").addEventListener("submit", async event => {
    event.preventDefault();
    setError("forgot-error", "");
    const email = $("#forgot-email").value.trim();
    if (!emailLooksValid(email)) return setError("forgot-error", "Enter a valid email address.");
    const button = event.currentTarget.querySelector("button[type=submit]");
    setBusy(button, true, "Sending code…");
    try {
      const result = await request("/api/auth/forgot-password", { method: "POST", body: { email } });
      $("#reset-step").hidden = false;
      $("#reset-code").focus();
      showToast(result.message);
    } catch (error) {
      setError("forgot-error", error.message);
    } finally { setBusy(button, false); }
  });

  $("#reset-form").addEventListener("submit", async event => {
    event.preventDefault();
    setError("reset-error", "");
    const email = $("#forgot-email").value.trim();
    const code = $("#reset-code").value.trim();
    const newPassword = $("#reset-password").value;
    if (!/^\d{8}$/.test(code)) return setError("reset-error", "Enter the 8-digit code from your email.");
    if (!validPassword(newPassword)) return setError("reset-error", "Use a password between 12 and 128 characters.");
    const button = event.currentTarget.querySelector("button[type=submit]");
    setBusy(button, true, "Updating…");
    try {
      const result = await request("/api/auth/reset-password", { method: "POST", body: { email, code, newPassword } });
      $("#login-email").value = email;
      $("#login-password").value = "";
      showSignedOut();
      showToast(result.message);
    } catch (error) {
      setError("reset-error", error.message);
    } finally { setBusy(button, false); }
  });

  $("#change-password-form").addEventListener("submit", async event => {
    event.preventDefault();
    setError("change-password-error", "");
    const currentPassword = $("#current-password").value;
    const newPassword = $("#new-password").value;
    if (!validPassword(newPassword)) return setError("change-password-error", "Use a new password between 12 and 128 characters.");
    if (currentPassword === newPassword) return setError("change-password-error", "Choose a password different from your current one.");
    const button = event.currentTarget.querySelector("button[type=submit]");
    setBusy(button, true, "Updating…");
    try {
      const result = await request("/api/auth/password", { method: "POST", body: { currentPassword, newPassword }, auth: true });
      showSignedOut();
      showToast(result.message);
    } catch (error) {
      setError("change-password-error", error.message);
    } finally { setBusy(button, false); }
  });

  $("#logout-button").addEventListener("click", async () => {
    const button = $("#logout-button");
    button.disabled = true;
    try {
      await request("/api/auth/logout", { method: "POST", body: {} });
      if (window.ZYROXGoogleAuth) { try { await window.ZYROXGoogleAuth.signOutFromGoogle(); } catch { /* ZYROX session is already revoked. */ } }
      showSignedOut();
      showToast("You’re signed out.");
    } catch (error) {
      showToast(error.message);
    } finally { button.disabled = false; }
  });

  async function restoreSession() {
    if (!apiBaseUrl) {
      $("#config-notice").hidden = false;
      return;
    }
    try {
      const result = await request("/api/auth/refresh", { method: "POST", body: {} });
      accessToken = result.accessToken;
      showDashboard(result.user);
    } catch (error) {
      if (error.message.includes("Could not reach") || error.message.includes("invalid") || error.message.includes("HTTPS")) showToast(error.message);
    }
  }

  openPanel("login");
  initializeGoogle();
  restoreSession();
})();
