import { api } from "./api.js";
import { publishPublicKeyIfNeeded } from "./keys.js";

const loginView = document.getElementById("login-view");
const totpView = document.getElementById("totp-view");
const forgotPasswordView = document.getElementById("forgot-password-view");
const resetPasswordView = document.getElementById("reset-password-view");
const authError = document.getElementById("auth-error");
const totpError = document.getElementById("totp-error");

let pendingTotpToken = null;

function hideAllViews() {
  loginView.hidden = true;
  totpView.hidden = true;
  forgotPasswordView.hidden = true;
  resetPasswordView.hidden = true;
}

function showLoginView() {
  hideAllViews();
  loginView.hidden = false;
}

function showTotpView(pendingToken) {
  pendingTotpToken = pendingToken;
  totpError.textContent = "";
  hideAllViews();
  totpView.hidden = false;
}

function showResetPasswordView() {
  hideAllViews();
  resetPasswordView.hidden = false;
  // Pré-rempli si le lien de l'email a été cliqué ; sinon l'utilisateur colle
  // le jeton lui-même (le corps de l'email le donne aussi en texte brut).
  const tokenFromUrl = new URLSearchParams(window.location.search).get("reset_token");
  if (tokenFromUrl) {
    document.querySelector("#reset-password-form [name='token']").value = tokenFromUrl;
  }
}

function goToApp() {
  window.location.href = "/";
}

document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  authError.textContent = "";
  const form = new FormData(event.target);
  try {
    const result = await api.login({
      email: form.get("email"),
      password: form.get("password"),
    });
    if (result.totp_required) {
      showTotpView(result.pending_token);
      return;
    }
    await publishPublicKeyIfNeeded(result.user);
    goToApp();
  } catch (error) {
    authError.textContent = error.message;
  }
});

document.getElementById("totp-login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  totpError.textContent = "";
  const form = new FormData(event.target);
  try {
    const user = await api.verifyTotp(pendingTotpToken, form.get("code"));
    await publishPublicKeyIfNeeded(user);
    goToApp();
  } catch (error) {
    totpError.textContent = error.message;
  }
});

document.getElementById("forgot-password-link").addEventListener("click", () => {
  hideAllViews();
  forgotPasswordView.hidden = false;
});

document.getElementById("forgot-password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  await api.forgotPassword(form.get("email"));
  document.getElementById("forgot-password-message").textContent =
    "Si ce compte existe, un email avec un lien (et un jeton) de réinitialisation vient d'être envoyé.";
});

document.getElementById("have-token-link").addEventListener("click", showResetPasswordView);

document.getElementById("reset-password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  try {
    await api.resetPassword(form.get("token"), form.get("password"));
    document.getElementById("reset-password-message").textContent =
      "Mot de passe changé. Tu peux te reconnecter.";
    window.history.replaceState({}, "", window.location.pathname);
    showLoginView();
  } catch (error) {
    document.getElementById("reset-password-message").textContent = error.message;
  }
});

(async function init() {
  if (new URLSearchParams(window.location.search).get("reset_token")) {
    showResetPasswordView();
    return;
  }
  try {
    await api.me();
    goToApp(); // deja connecte : direction l'application
  } catch {
    showLoginView();
  }
})();
