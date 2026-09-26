// Talk — frontend en cours de développement.
// JavaScript vanilla, aucun framework, aucun script inline (CSP stricte).

const apiStatus = document.getElementById("api-status");
const authMessage = document.getElementById("auth-message");
const loggedOut = document.getElementById("auth-logged-out");
const loggedIn = document.getElementById("auth-logged-in");
const authUsername = document.getElementById("auth-username");
const loginForm = document.getElementById("login-form");
const registerForm = document.getElementById("register-form");
const logoutButton = document.getElementById("logout-button");

const CSRF_COOKIE = "talk_csrf";
const CSRF_HEADER = "X-CSRF-Token";

async function checkApi() {
  if (!apiStatus) {
    return;
  }

  try {
    const response = await fetch("/health");
    const data = await response.json();
    apiStatus.textContent = data.status === "ok" ? "en ligne" : "réponse inattendue";
  } catch {
    apiStatus.textContent = "injoignable";
  }
}

function readCookie(name) {
  const prefix = `${name}=`;
  const found = document.cookie.split("; ").find((entry) => entry.startsWith(prefix));
  return found ? decodeURIComponent(found.slice(prefix.length)) : "";
}

// Le cookie talk_csrf n'est pas HttpOnly : le JavaScript doit pouvoir le lire
// pour le renvoyer dans l'en-tête exigé par le serveur sur chaque mutation.
async function ensureCsrfToken() {
  let token = readCookie(CSRF_COOKIE);
  if (token) {
    return token;
  }
  const response = await fetch("/auth/csrf", { credentials: "same-origin" });
  if (!response.ok) {
    return "";
  }
  token = (await response.json()).csrf_token;
  return token;
}

async function postJson(path, body) {
  const csrfToken = await ensureCsrfToken();
  return fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", [CSRF_HEADER]: csrfToken },
    body: JSON.stringify(body),
  });
}

function showMessage(text, isError) {
  if (!authMessage) {
    return;
  }
  authMessage.textContent = text;
  authMessage.hidden = text === "";
  authMessage.classList.toggle("auth-message-error", Boolean(isError));
}

function showSession(user) {
  const connected = Boolean(user);
  if (loggedOut) {
    loggedOut.hidden = connected;
  }
  if (loggedIn) {
    loggedIn.hidden = !connected;
  }
  if (connected && authUsername) {
    authUsername.textContent = user.username;
  }
}

async function refreshSession() {
  const response = await fetch("/auth/me", { credentials: "same-origin" });
  if (response.status === 401) {
    showSession(null);
    return;
  }
  if (response.ok) {
    showSession(await response.json());
  }
}

async function handleSubmit(event, path, form) {
  event.preventDefault();
  showMessage("", false);
  const data = new FormData(form);
  const response = await postJson(path, {
    username: String(data.get("username") || ""),
    password: String(data.get("password") || ""),
  });
  if (response.ok) {
    form.reset();
    showMessage("Connexion réussie.", false);
    await refreshSession();
    return;
  }
  let detail = "La requête a échoué.";
  try {
    const body = await response.json();
    detail = body.detail || detail;
  } catch {
    // Réponse sans corps JSON : on garde le message générique.
  }
  showMessage(detail, true);
}

if (loginForm) {
  loginForm.addEventListener("submit", (event) => handleSubmit(event, "/auth/login", loginForm));
}

if (registerForm) {
  registerForm.addEventListener("submit", (event) =>
    handleSubmit(event, "/auth/register", registerForm),
  );
}

if (logoutButton) {
  logoutButton.addEventListener("click", async () => {
    const response = await postJson("/auth/logout", {});
    showMessage(
      response.ok ? "Déconnecté." : "La déconnexion a échoué.",
      !response.ok,
    );
    showSession(null);
  });
}

checkApi();
refreshSession();
