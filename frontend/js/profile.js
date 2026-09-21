/**
 * profile.js — Fiche profil « style Discord » : popout de n'importe quel
 * utilisateur (lui-même ou un membre), visualisation du display_name / id /
 * « À propos », et édition du profil de l'utilisateur courant (PATCH /api/me).
 *
 * Règles strictes :
 *   - Construction EN PUR DOM (createElement + textContent), jamais
 *     `innerHTML` avec des données utilisateur ;
 *   - La modale réutilise `ui.openModal`/`ui.closeModal` et le pattern des
 *     modales existantes (fermeture par Échap / clic sur le fond assurée par
 *     `ui.initInteractions`) ;
 *   - L'avatar (lettre + hue) reste déterministe sur le `username` (stabilité),
 *     indépendant du `display_name`.
 *
 * Appels entrant (posés par main.js) :
 *   - clic sur l'avatar d'un message (chat.js → setMemberClickHandler) ;
 *   - clic sur une ligne du panneau membres (rooms.js → setMemberClickHandler) ;
 *   - « Mon profil » depuis le menu Paramètres (main.js).
 */

import { api } from "./api.js";
import * as auth from "./auth.js";
import * as ui from "./ui.js";
import * as rooms from "./rooms.js";
import * as chat from "./chat.js";

/** Longueurs maximales miroir du backend (PATCH /api/me). */
const MAX_DISPLAY_NAME = 32;
const MAX_ABOUT = 500;

/** Callback de notification (toasts), posé par main.js. */
let onToast = () => {};

/** Callback appelé après une mise à jour de profil (posé par main.js). */
let onProfileChanged = () => {};

/** Inverse le message d'un toast (cerise : toujours textContent, aucun HTML). */
export function setToast(fn) {
  onToast = typeof fn === "function" ? fn : onToast;
}

/** Enregistre un callback déclenché après une mise à jour du profil. */
export function setOnProfileChanged(fn) {
  onProfileChanged = typeof fn === "function" ? fn : onProfileChanged;
}

/** Nom affiché : display_name sinon username sinon « Inconnu ». */
function displayNameOf(user) {
  if (!user) {
    return "Inconnu";
  }
  return (
    (user.display_name && String(user.display_name).trim()) ||
    (user.username && String(user.username).trim()) ||
    "Inconnu"
  );
}

/** Normalise un membre/utilisateur en objet profil `{id, username, display_name, about}`. */
function resolveProfile(memberOrUser) {
  const src = memberOrUser && typeof memberOrUser === "object" ? memberOrUser : {};
  return {
    id: src.id != null ? src.id : src.user_id != null ? src.user_id : null,
    username: src.username || src.name || "",
    display_name:
      src.display_name != null && src.display_name !== "" ? String(src.display_name) : null,
    about: src.about != null && src.about !== "" ? String(src.about) : null,
  };
}

/** Vrai si le profil ciblé est celui de l'utilisateur courant. */
function isCurrentUserProfile(profile) {
  const me = auth.getCurrentUser();
  return Boolean(
    me && profile.id != null && me.id != null && String(profile.id) === String(me.id),
  );
}

/* ============================================================
   Point d'entrée
   ============================================================ */

/**
 * Ouvre la fiche profil d'un membre/utilisateur.
 * @param {object} memberOrUser Objet du membre (id, username, display_name,
 *        about) ou de l'utilisateur courant.
 * @param {boolean} [editable] Si vrai, ouvre directement le formulaire
 *        d'édition (utilisé par « Mon profil » si besoin). Par défaut affiche
 *        la fiche ; le bouton « Modifier le profil » n'apparaît que sur le
 *        profil courant.
 */
export function openProfileFor(memberOrUser, editable = false) {
  const profile = resolveProfile(memberOrUser);
  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop";
  backdrop.dataset.modal = "";
  backdrop.hidden = true; // ui.openModal gère l'affichage + le focus

  const modal = document.createElement("div");
  modal.className = "modal modal--profile";
  modal.setAttribute("role", "dialog");
  modal.setAttribute("aria-modal", "true");
  modal.setAttribute("aria-label", "Profil de " + displayNameOf(profile));
  backdrop.appendChild(modal);

  document.body.appendChild(backdrop);
  ui.openModal(backdrop);

  if (editable) {
    renderEditForm(backdrop, modal, profile);
  } else {
    renderProfileView(backdrop, modal, profile);
  }
}

/* ============================================================
   Fiche profil (mode vue)
   ============================================================ */

/**
 * Construit la fiche : grand avatar (hue + initiale du username), display_name
 * en gras, `@username` en secondaire, ID + bouton Copier, section « À propos »,
 * et « Modifier le profil » si c'est la fiche de l'utilisateur courant.
 */
function renderProfileView(backdrop, modal, profile) {
  modal.textContent = "";
  const username = profile.username || "";

  // En-tête : avatar + noms.
  const header = document.createElement("div");
  header.className = "profile-header";

  const avatar = document.createElement("span");
  avatar.className = "avatar avatar--profile " + ui.avatarHueClass(username || "?");
  avatar.textContent = username ? username.charAt(0).toUpperCase() : "?";
  header.appendChild(avatar);

  const names = document.createElement("div");
  names.className = "profile-names";
  const name = document.createElement("div");
  name.className = "profile-name";
  name.textContent = displayNameOf(profile);
  names.appendChild(name);
  const handle = document.createElement("div");
  handle.className = "profile-username";
  handle.textContent = "@" + username;
  names.appendChild(handle);
  header.appendChild(names);
  modal.appendChild(header);

  // Ligne identifiant + bouton Copier (réutilise rooms.copyTextToClipboard).
  const idRow = document.createElement("div");
  idRow.className = "profile-id-row";
  const idText = document.createElement("code");
  idText.className = "profile-id";
  idText.textContent = profile.id != null ? String(profile.id) : "—";
  idRow.appendChild(idText);
  if (profile.id != null) {
    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "btn btn-ghost btn-sm";
    copyBtn.textContent = "Copier";
    copyBtn.addEventListener("click", async () => {
      try {
        await rooms.copyTextToClipboard(String(profile.id));
        onToast("Identifiant copié.", "success");
      } catch {
        onToast("Copie impossible sur ce navigateur.", "error");
      }
    });
    idRow.appendChild(copyBtn);
  }
  modal.appendChild(idRow);

  // Section « À propos » (ou message par défaut en italique).
  const label = document.createElement("div");
  label.className = "profile-section-label";
  label.textContent = "À propos";
  modal.appendChild(label);
  const about = document.createElement("div");
  about.className = "profile-about";
  if (profile.about != null && profile.about.trim() !== "") {
    about.textContent = profile.about;
  } else {
    about.classList.add("profile-about--empty");
    about.textContent = "Aucune bio.";
  }
  modal.appendChild(about);

  // Actions : « Modifier le profil » (profil courant) + « Fermer ».
  const actions = document.createElement("div");
  actions.className = "modal-actions profile-actions";
  if (isCurrentUserProfile(profile)) {
    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "btn btn-primary btn-sm";
    editBtn.textContent = "Modifier le profil";
    editBtn.addEventListener("click", () => renderEditForm(backdrop, modal, profile));
    actions.appendChild(editBtn);
  }
  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "btn btn-ghost";
  closeBtn.textContent = "Fermer";
  closeBtn.addEventListener("click", () => ui.closeModal(backdrop));
  actions.appendChild(closeBtn);
  modal.appendChild(actions);
}

/* ============================================================
   Édition du profil (mode formulaire)
   ============================================================ */

/**
 * Formulaire d'édition dans la même modale : display_name (max 32) et about
 * (max 500, compteur de caractères). Enregistrer → PATCH /api/me → 200 :
 * `auth.setCurrentUser`, rafraîchissement de la sidebar / du fil / des membres,
 * puis fermeture. « Annuler » revient à la fiche (données abandonnées).
 */
function renderEditForm(backdrop, modal, profile) {
  modal.textContent = "";
  const me = auth.getCurrentUser();

  const title = document.createElement("h3");
  title.className = "modal-title";
  title.textContent = "Modifier le profil";
  modal.appendChild(title);

  const form = document.createElement("form");
  form.className = "modal-form profile-form";
  form.setAttribute("novalidate", "");

  // Nom affiché.
  const nameLabel = document.createElement("label");
  nameLabel.className = "field-label";
  nameLabel.htmlFor = "profile-display-name";
  nameLabel.textContent = "Nom affiché";
  form.appendChild(nameLabel);
  const nameInput = document.createElement("input");
  nameInput.type = "text";
  nameInput.id = "profile-display-name";
  nameInput.maxLength = MAX_DISPLAY_NAME;
  nameInput.value = profile.display_name || "";
  nameInput.placeholder = me && me.username ? me.username : "";
  form.appendChild(nameInput);

  // À propos (textarea + compteur).
  const aboutLabel = document.createElement("label");
  aboutLabel.className = "field-label";
  aboutLabel.htmlFor = "profile-about";
  aboutLabel.textContent = "À propos";
  form.appendChild(aboutLabel);
  const aboutInput = document.createElement("textarea");
  aboutInput.id = "profile-about";
  aboutInput.className = "profile-about-input";
  aboutInput.maxLength = MAX_ABOUT;
  aboutInput.placeholder = "Parlez de vous…";
  aboutInput.value = profile.about || "";
  form.appendChild(aboutInput);
  const counter = document.createElement("span");
  counter.className = "profile-counter";
  const updateCounter = () => {
    counter.textContent = `${aboutInput.value.length} / ${MAX_ABOUT}`;
  };
  aboutInput.addEventListener("input", updateCounter);
  updateCounter();
  form.appendChild(counter);

  // Erreur inline.
  const errorEl = document.createElement("p");
  errorEl.className = "form-error";
  errorEl.setAttribute("role", "alert");
  errorEl.hidden = true;
  form.appendChild(errorEl);

  const actions = document.createElement("div");
  actions.className = "modal-actions";

  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.className = "btn btn-ghost";
  cancelBtn.textContent = "Annuler";
  cancelBtn.addEventListener("click", () => renderProfileView(backdrop, modal, profile));
  actions.appendChild(cancelBtn);

  const saveBtn = document.createElement("button");
  saveBtn.type = "button";
  saveBtn.className = "btn btn-primary";
  saveBtn.textContent = "Enregistrer";
  saveBtn.addEventListener("click", async () => {
    const displayName = nameInput.value.trim();
    const about = aboutInput.value.trim();
    errorEl.hidden = true;

    if ([...displayName].length > MAX_DISPLAY_NAME) {
      errorEl.textContent = `Le nom affiché est limité à ${MAX_DISPLAY_NAME} caractères.`;
      errorEl.hidden = false;
      return;
    }
    if ([...about].length > MAX_ABOUT) {
      errorEl.textContent = `La bio est limitée à ${MAX_ABOUT} caractères.`;
      errorEl.hidden = false;
      return;
    }

    saveBtn.disabled = true;
    cancelBtn.disabled = true;
    try {
      // PATCH /api/me — corps {display_name?: str|null, about?: str|null}.
      const data = await api("/api/me", {
        method: "PATCH",
        body: {
          display_name: displayName !== "" ? displayName : null,
          about: about !== "" ? about : null,
        },
      });
      const saved = data && data.user && typeof data.user === "object" ? data.user : null;
      if (saved) {
        auth.setCurrentUser(saved);
      } else {
        // Repli : garde l'objet courant en mémoire (défensif).
        auth.setCurrentUser({
          ...me,
          display_name: displayName !== "" ? displayName : null,
          about: about !== "" ? about : null,
        });
      }
      applyProfileRefresh(auth.getCurrentUser());
      ui.closeModal(backdrop);
      onToast("Profil mis à jour.", "success");
      onProfileChanged(auth.getCurrentUser());
    } catch (error) {
      errorEl.textContent =
        (error && error.message) || "La mise à jour du profil a échoué.";
      errorEl.hidden = false;
    } finally {
      saveBtn.disabled = false;
      cancelBtn.disabled = false;
    }
  });
  actions.appendChild(saveBtn);

  form.appendChild(actions);
  modal.appendChild(form);

  // La modale est déjà visible : on focalise simplement le premier champ.
  const focusTarget = form.querySelector("input, textarea");
  if (focusTarget && typeof focusTarget.focus === "function") {
    focusTarget.focus();
  }
}

/* ============================================================
   Rafraîchissement après mise à jour du profil
   ============================================================ */

/**
 * Met à jour tous les affichages « display_name || username » après un PATCH :
 * sidebar (en-tête du menu Paramètres), panneau membres, fil courant (senders)
 * et base de nom des nouveaux messages. L'avatar reste sur le username.
 */
function applyProfileRefresh(user) {
  if (!user) {
    return;
  }
  const username = user.username || "";

  // Sidebar (en-tête + avatar teinté sur le username).
  const usernameEl = document.getElementById("user-username");
  if (usernameEl) {
    usernameEl.textContent = displayNameOf(user);
  }
  const avatarEl = document.getElementById("user-avatar");
  if (avatarEl) {
    avatarEl.className = "avatar avatar--sm " + ui.avatarHueClass(username || "?");
    avatarEl.textContent = username ? username.charAt(0).toUpperCase() : "?";
  }

  // Fil courant : senders + membersById (pour les futurs messages).
  chat.updateLocalDisplayName(user);

  // Panneau membres (refetch : le serveur renvoie display_name/about).
  if (rooms.getCurrentRoom()) {
    rooms.refreshMembers().catch(() => {
      // affichage non critique ; le prochain refresh corrigera.
    });
  }
}