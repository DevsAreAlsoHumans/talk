/**
 * auth.js — Inscription / connexion.
 *
 * Inscription : génère la paire de clés RSA dans le navigateur, chiffre la clé
 * privée (JWK) avec une clé dérivée du mot de passe (PBKDF2 + AES-GCM) puis la
 * stocke en localStorage — seul `talk.public_key` est envoyé au serveur.
 *
 * Connexion : déchiffre la clé privée stockée avec le mot de passe saisi, puis
 * s'authentifie auprès du serveur (rotation du jeton CSRF incluse).
 *
 * Cas « verrouillé » (comportement documenté et assumé) : si le stockage local
 * a été vidé, la clé privée est perdue et l'utilisateur doit se réinscrire —
 * ses anciens messages ne sont plus déchiffrables par définition (E2E).
 */

import { api, ApiError } from "./api.js";
import * as crypto from "./crypto.js";
import * as ui from "./ui.js";

/** Clés de localStorage gérées par ce module. */
const LS_PRIVATE_KEY = "talk.private_key";
const LS_USERNAME = "talk.username";
const LS_PUBLIC_KEY = "talk.public_key";
const LS_CSRF = "talk.csrf_token";

/** Utilisateur authentifié en mémoire, ou null. */
let currentUser = null;

/** Callback appelé après une authentification réussie (posé par main.js). */
let onAuthenticated = () => {};

/** Callback de notification (toasts), posé par main.js. */
let onToast = (message, type) => {};

/**
 * Branche l'interface d'authentification (formulaire, bascule login/register)
 * ainsi que la modale de changement de mot de passe.
 * @param {{onAuthenticated: (user: object) => void,
 *          onToast?: (message: string, type?: string) => void}} callbacks
 */
export function initAuth({ onAuthenticated: cb, onToast: toastCallback }) {
  onAuthenticated = cb;
  onToast = toastCallback || onToast;

  const form = document.getElementById("auth-form");
  const usernameInput = document.getElementById("auth-username");
  const passwordInput = document.getElementById("auth-password");
  const password2Input = document.getElementById("auth-password2");
  const errorBox = document.getElementById("auth-error");
  const lockedBox = document.getElementById("auth-locked");

  const toggleModeBtn = document.getElementById("auth-toggle-mode");
  let mode = "login"; // "register" | "login"

  /** Active le mode inscription ou connexion. */
  function setMode(nextMode) {
    mode = nextMode;
    const registering = mode === "register";

    document.getElementById("auth-title").textContent = registering
      ? "Créer un compte"
      : "Connexion";
    document.getElementById("auth-submit").textContent = registering
      ? "Créer le compte"
      : "Se connecter";
    document.getElementById("auth-password2-label").hidden = !registering;
    password2Input.hidden = !registering;
    toggleModeBtn.textContent = registering
      ? "Déjà un compte ? Se connecter"
      : "Pas encore de compte ? S'inscrire";
    document.getElementById("auth-note").textContent = registering
      ? "Votre clé privée est générée dans ce navigateur, chiffrée avec votre mot de passe (PBKDF2) puis stockée uniquement ici."
      : "La clé privée nécessaire au déchiffrement se trouve dans le stockage local de ce navigateur.";

    hideError();
  }

  function hideError() {
    errorBox.hidden = true;
    errorBox.textContent = "";
  }

  function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
  }

  /** Affiche le bloc « compte verrouillé » en lieu et place du formulaire. */
  function showLocked(message) {
    hideError();
    form.hidden = true;
    lockedBox.textContent = message;
    lockedBox.hidden = false;
  }

  function hideLocked() {
    lockedBox.hidden = true;
    lockedBox.textContent = "";
    form.hidden = false;
  }

  toggleModeBtn.addEventListener("click", () => {
    hideLocked();
    setMode(mode === "register" ? "login" : "register");
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    hideError();

    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const password2 = password2Input.value;

    // Validation minimale miroir du backend (Pydantic : 3-32 / 8-128).
    if (username.length < 3 || username.length > 32) {
      showError("Le pseudo doit contenir entre 3 et 32 caractères.");
      return;
    }
    if (password.length < 8 || password.length > 128) {
      showError("Le mot de passe doit contenir entre 8 et 128 caractères.");
      return;
    }
    if (mode === "register" && password !== password2) {
      showError("Les deux mots de passe ne correspondent pas.");
      return;
    }

    const submitBtn = document.getElementById("auth-submit");
    submitBtn.disabled = true;
    try {
      if (mode === "register") {
        await register(username, password);
      } else {
        await login(username, password);
      }
    } catch (error) {
      if (error instanceof LockedAccountError) {
        showLocked(error.message);
      } else {
        showError(error.message || "Erreur inconnue.");
      }
    } finally {
      submitBtn.disabled = false;
    }
  });

  // Connexion préférée : mode login si une clé privée est déjà présente.
  const hasLocalKey =
    localStorage.getItem(LS_PRIVATE_KEY) !== null &&
    localStorage.getItem(LS_PUBLIC_KEY) !== null;

  if (hasLocalKey) {
    setMode("login");
    const storedUser = localStorage.getItem(LS_USERNAME);
    if (storedUser) {
      usernameInput.value = storedUser;
    }
  } else {
    setMode("register");
  }

  /* ------------------------------------------------------------
     Changement de mot de passe.
     Le déclencheur vit désormais dans le menu « Paramètres »
     (voir main.js → openSettingsMenu), qui appelle openPasswordModal().
     Ici on ne branche que la modale elle-même (annulation + soumission).
     ------------------------------------------------------------ */
  document.getElementById("btn-cancel-change-password").addEventListener("click", () => {
    ui.closeModal(document.getElementById("modal-change-password"));
  });

  const passwordForm = document.getElementById("form-change-password");
  passwordForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await submitPasswordChange();
  });
}

/**
 * Ouvre la modale de changement de mot de passe (champs vidés).
 * Exportée pour être déclenchée depuis le menu « Paramètres » (main.js).
 */
export function openPasswordModal() {
  const modal = document.getElementById("modal-change-password");
  document.getElementById("cp-old").value = "";
  document.getElementById("cp-new").value = "";
  document.getElementById("cp-confirm").value = "";
  ui.openModal(modal, "#cp-old");
}

/** Validation client + changement réel (voir export changePassword). */
async function submitPasswordChange() {
  const errorEl = document.getElementById("cp-error");
  const fail = (message) => {
    errorEl.textContent = message;
    errorEl.hidden = false;
  };

  const oldPassword = document.getElementById("cp-old").value;
  const newPassword = document.getElementById("cp-new").value;
  const confirmPassword = document.getElementById("cp-confirm").value;

  if (!oldPassword) {
    fail("Indiquez votre mot de passe actuel.");
    return;
  }
  if (newPassword.length < 8 || newPassword.length > 128) {
    fail("Le nouveau mot de passe doit contenir entre 8 et 128 caractères.");
    return;
  }
  if (newPassword !== confirmPassword) {
    fail("La confirmation ne correspond pas au nouveau mot de passe.");
    return;
  }

  const submitBtn = document.getElementById("btn-change-password-submit");
  submitBtn.disabled = true;
  try {
    await changePassword(oldPassword, newPassword);
    ui.closeModal(document.getElementById("modal-change-password"));
    onToast("Mot de passe mis à jour.", "success");
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      fail("L'ancien mot de passe est incorrect.");
    } else {
      fail(error.message || "Changement de mot de passe impossible.");
    }
  } finally {
    submitBtn.disabled = false;
  }
}

/**
 * Change le mot de passe :
 *   1. déchiffre la clé privée stockée avec l'ancien mot de passe (JWK) ;
 *   2. POST /api/auth/change-password (le serveur vérifie l'ancien) ;
 *   3. ré-chiffre la clé privée avec le nouveau mot de passe puis la stocke.
 * @returns {Promise<void>}
 * @throws {ApiError} ancien mot de passe incorrect (403) ou erreur serveur.
 */
export async function changePassword(oldPassword, newPassword) {
  const storedRaw = localStorage.getItem(LS_PRIVATE_KEY);
  if (!storedRaw) {
    throw new ApiError(
      "Aucune clé privée stockée sur ce navigateur : changement impossible.",
      400,
    );
  }

  let stored;
  try {
    stored = JSON.parse(storedRaw);
  } catch {
    throw new ApiError("Données locales corrompues.", 500);
  }

  // 1. Vérification locale : l'ancien mot de passe déverrouille-t-il la clé ?
  let privateKeyJwk;
  try {
    privateKeyJwk = await crypto.decryptPrivateKeyWithPassword(stored, oldPassword);
  } catch {
    throw new ApiError("L'ancien mot de passe est incorrect.", 403);
  }

  // 2. Autorité serveur (Argon2). En cas d'échec, aucune donnée n'est modifiée.
  await api("/api/auth/change-password", {
    method: "POST",
    body: { old_password: oldPassword, new_password: newPassword },
  });

  // 3. Ré-chiffrement local puis persistance (les clés mémoire sont inchangées).
  const reEncrypted = await crypto.encryptPrivateKeyWithPassword(
    privateKeyJwk,
    newPassword,
  );
  localStorage.setItem(LS_PRIVATE_KEY, JSON.stringify(reEncrypted));
}

/** Erreur spécifique au « verrouillage » (clé privée locale manquante). */
export class LockedAccountError extends Error {
  constructor(message) {
    super(message);
    this.name = "LockedAccountError";
  }
}

/**
 * Inscription E2E : keypair local, stockage chiffré de la clé privée, puis
 * envoi de la clé publique au serveur.
 */
async function register(username, password) {
  // 1. Génération de la paire de clés RSA-OAEP-256 (WebCrypto).
  const { publicKey, privateKey } = await crypto.generateUserKeyPair();

  // 2. Export : publique → SPKI base64 (pour le serveur) ;
  //    privée → JWK (pour le stockage local chiffré).
  const publicKeyBase64 = await crypto.exportPublicKeyBase64(publicKey);
  const privateKeyJwk = await crypto.exportPrivateKeyJwk(privateKey);
  const storedPrivateKey = await crypto.encryptPrivateKeyWithPassword(
    privateKeyJwk,
    password,
  );

  // 3. POST : le serveur ne reçoit que la clé publique (jamais la privée).
  const data = await api("/api/auth/register", {
    method: "POST",
    body: {
      username,
      password,
      public_key: publicKeyBase64,
    },
  });

  // 4. Persistance locale après le succès serveur (ne pollue pas le localStorage
  //    si le pseudo est déjà pris par exemple).
  localStorage.setItem(LS_PRIVATE_KEY, JSON.stringify(storedPrivateKey));
  localStorage.setItem(LS_USERNAME, username);
  localStorage.setItem(LS_PUBLIC_KEY, publicKeyBase64);
  localStorage.setItem(LS_CSRF, data.csrf_token); // rotation de session

  // 5. État mémoire : la clé privée ne quitte jamais le navigateur.
  crypto.setUserPrivateKey(privateKey);
  crypto.setUserPublicKeyBase64(publicKeyBase64);
  currentUser = data.user;
  onAuthenticated(data.user);
}

/**
 * Connexion : déchiffrement de la clé privée locale puis POST /login.
 */
async function login(username, password) {
  // a. Vérifier la présence d'une clé privée locale.
  const storedRaw = localStorage.getItem(LS_PRIVATE_KEY);
  const storedUsername = localStorage.getItem(LS_USERNAME);

  if (!storedRaw || !storedUsername) {
    throw new LockedAccountError(
      "Aucune clé privée stockée sur ce navigateur. Si le stockage local a été vidé, " +
        "la clé privée est perdue et les anciens messages ne peuvent plus être déchiffrés. " +
        "Vous devez vous réinscrire avec un nouveau compte.",
    );
  }
  if (storedUsername !== username) {
    throw new LockedAccountError(
      "La clé privée stockée ici appartient à « " +
        storedUsername +
        " ». Sur ce navigateur, un seul compte est possible : " +
        "connectez-vous avec « " +
        storedUsername +
        " » ou réinscrivez-vous.",
    );
  }

  // b. Déchiffrer la clé privée avec le mot de passe saisi.
  const storedPrivateKey = JSON.parse(storedRaw);
  let privateKeyJwk;
  try {
    privateKeyJwk = await crypto.decryptPrivateKeyWithPassword(
      storedPrivateKey,
      password,
    );
  } catch (error) {
    throw new ApiError(error.message, 401);
  }
  const privateKey = await crypto.importPrivateKeyFromJwk(privateKeyJwk);

  // c. Authentification serveur (vérification Argon2 + rotation session).
  const data = await api("/api/auth/login", {
    method: "POST",
    body: { username, password },
  });
  localStorage.setItem(LS_CSRF, data.csrf_token);

  // d. État mémoire.
  const publicKeyBase64 = localStorage.getItem(LS_PUBLIC_KEY);
  crypto.setUserPrivateKey(privateKey);
  crypto.setUserPublicKeyBase64(publicKeyBase64);
  currentUser = data.user;
  onAuthenticated(data.user);
}

/** @returns {object|null} utilisateur courant. */
export function getCurrentUser() {
  return currentUser;
}

/**
 * Remplace l'utilisateur courant en mémoire (utilisé après un PATCH /api/me
 * du profil : display_name / about mis à jour, identité inchangée).
 * @param {object|null} user {id, username, public_key, created_at, display_name?, about?}
 */
export function setCurrentUser(user) {
  currentUser = user && typeof user === "object" ? user : null;
}

/** @returns {string} pseudo de l'utilisateur courant (ou ""). */
export function getCurrentUsername() {
  return currentUser ? currentUser.username : "";
}

/**
 * Déconnexion : détruit la session serveur puis purge le jeton CSRF local.
 * La clé privée (chiffrée par le mot de passe) est conservée afin de permettre
 * une reconnexion — le serveur ne conserve aucun identifiant la concernant.
 */
export async function logout() {
  try {
    await api("/api/auth/logout", { method: "POST" });
  } catch {
    // Même si le serveur est injoignable, on nettoie la session locale.
  }
  localStorage.removeItem(LS_CSRF);
  currentUser = null;
  crypto.resetCryptoState();
}