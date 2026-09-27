// Talk — point d'entrée du frontend.
//
// JavaScript vanilla, modules ES natifs, aucun framework et aucun script inline
// (la CSP refuse `unsafe-inline`). Ce module ne fait que deux choses : gérer
// l'authentification, et deleguer la messagerie à `chat.js` une fois connecté.

import { ensureCsrfToken, getJson, postJson } from "./api.js";
import { initChat } from "./chat.js";

const elements = {};

function cacheElements() {
  for (const id of [
    "api-status",
    "auth-message",
    "auth-logged-out",
    "auth-logged-in",
    "auth-username",
    "login-form",
    "register-form",
    "logout-button",
    "chat-section",
  ]) {
    elements[id] = document.getElementById(id);
  }
}

async function checkApi() {
  const status = elements["api-status"];
  if (!status) {
    return;
  }
  try {
    const data = await (await getJson("/health")).json();
    status.textContent = data.status === "ok" ? "en ligne" : "réponse inattendue";
  } catch {
    status.textContent = "injoignable";
  }
}

function showMessage(text, isError) {
  const message = elements["auth-message"];
  if (!message) {
    return;
  }
  message.textContent = text;
  message.hidden = text === "";
  message.classList.toggle("auth-message-error", Boolean(isError));
}

function showSession(user) {
  const connected = Boolean(user);
  elements["auth-logged-out"].hidden = connected;
  elements["auth-logged-in"].hidden = !connected;
  elements["chat-section"].hidden = !connected;
  if (connected) {
    elements["auth-username"].textContent = user.username;
  }
}

/**
 * Rafraîchit la session, puis démarre la messagerie si l'utilisateur est
 * connecté.
 *
 * L'initialisation du chat est déclenchée à chaque affichage de session, et pas
 * seulement à la connexion : un rechargement de page doit retrouver les canaux
 * et les clés déjà présentes dans le navigateur.
 */
async function refreshSession() {
  const response = await getJson("/auth/me");
  if (response.status === 401) {
    showSession(null);
    return;
  }
  if (!response.ok) {
    return;
  }
  const user = await response.json();
  showSession(user);
  await initChat(user);
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

function wireEvents() {
  elements["login-form"].addEventListener("submit", (event) =>
    handleSubmit(event, "/auth/login", elements["login-form"]),
  );
  elements["register-form"].addEventListener("submit", (event) =>
    handleSubmit(event, "/auth/register", elements["register-form"]),
  );
  elements["logout-button"].addEventListener("click", async () => {
    const response = await postJson("/auth/logout", {});
    showMessage(response.ok ? "Déconnecté." : "La déconnexion a échoué.", !response.ok);
    if (response.ok) {
      // Les clés locales ne sont pas effacées. La clé privée RSA est le seul
      // moyen de lire les enveloppes reçues, et les clés de salon ne peuvent
      // pas être réémises par le serveur : les supprimer rendrait les canaux
      // définitivement illisibles depuis ce navigateur. C'est un choix assumé :
      // quiconque a accès à ce profil peut lire ces canaux, ce qui vaut aussi
      // pour un mot de passe volé.
      showSession(null);
    }
  });
}

cacheElements();
wireEvents();
checkApi();
ensureCsrfToken();
refreshSession();
