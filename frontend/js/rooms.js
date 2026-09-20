/**
 * rooms.js — Salons : sidebar, création, adhésion, membres et gestion de la
 * clé de salon (enveloppement / ré-enveloppement vers les membres).
 *
 * Rappel du modèle E2E :
 *   - Création  : on génère la clé de salon (32 octets) et on en pose une copie
 *                 enveloppée (RSA-OAEP) avec SA PROPRE clé publique.
 *   - Ajout     : le membre déjà présent déchiffre sa copie, la ré-enveloppe
 *                 avec la clé publique du nouveau membre puis POST /keys.
 *   - Nouvel adhérent : ne détient rien à l'inscription ; il reçoit sa copie
 *                 enveloppée via l'événement WS `room_key` une fois qu'un membre
 *                 a POSTé la copie à son nom (auto-partage sur `member_joined`
 *                 ou bouton « Actualiser clés »).
 */

import { api } from "./api.js";
import * as crypto from "./crypto.js";
import { getCurrentUser } from "./auth.js";
import * as chat from "./chat.js";

/** Callbacks posés par main.js. */
let onToast = () => {};
let onRoomOpened = () => {};

/** Salon actuellement sélectionné. */
let currentRoom = null;

/** Liste des salons de l'utilisateur (depuis /api/me). */
let roomsList = [];

/** Membres du salon courant : [{id, username, public_key}]. */
let currentMembers = [];

/**
 * Branche l'interface des salons (sidebar, modales, panneau membres).
 * @param {{onToast?: (message: string) => void,
 *          onRoomOpened?: (roomId: string|number) => void}} callbacks
 */
export function initRooms({ onToast: toastCallback, onRoomOpened: openedCallback }) {
  onToast = toastCallback || onToast;
  onRoomOpened = openedCallback || onRoomOpened;

  // ---- Boutons de la sidebar ----
  document.getElementById("btn-new-room").addEventListener("click", () => {
    openModal("modal-new-room", "new-room-name");
  });
  document.getElementById("btn-join-room").addEventListener("click", () => {
    openModal("modal-join-room", "join-room-id");
  });

  // ---- Modale « nouveau salon » ----
  document.getElementById("btn-cancel-new-room").addEventListener("click", () => {
    closeModal("modal-new-room");
  });
  document.getElementById("btn-create-room").addEventListener("click", async () => {
    const input = document.getElementById("new-room-name");
    const name = input.value.trim();
    if (!name) {
      showModalError("modal-new-room", "Donnez un nom au salon.");
      return;
    }
    const createBtn = document.getElementById("btn-create-room");
    createBtn.disabled = true;
    try {
      // createRoom ouvre déjà le salon (selectRoom → onRoomOpened).
      await createRoom(name);
      closeModal("modal-new-room");
      input.value = "";
    } catch (error) {
      showModalError("modal-new-room", error.message || "Création impossible.");
    } finally {
      createBtn.disabled = false;
    }
  });

  // ---- Modale « rejoindre un salon » ----
  document.getElementById("btn-cancel-join-room").addEventListener("click", () => {
    closeModal("modal-join-room");
  });
  document.getElementById("btn-join-room-submit").addEventListener("click", async () => {
    const input = document.getElementById("join-room-id");
    const roomId = input.value.trim();
    if (!/^\d+$/.test(roomId)) {
      showModalError("modal-join-room", "L'identifiant du salon doit être un nombre.");
      return;
    }
    const joinBtn = document.getElementById("btn-join-room-submit");
    joinBtn.disabled = true;
    try {
      // joinRoom ouvre déjà le salon (selectRoom → onRoomOpened).
      await joinRoom(roomId);
      closeModal("modal-join-room");
      input.value = "";
    } catch (error) {
      showModalError("modal-join-room", error.message || "Impossible de rejoindre.");
    } finally {
      joinBtn.disabled = false;
    }
  });

  // ---- Panneau membres / bouton « Actualiser clés » ----
  document.getElementById("btn-refresh-keys").addEventListener("click", () => {
    refreshCurrentRoomKeys();
  });
}

/** Charge /api/me et construit la sidebar. @returns {Promise<Array>} salons. */
export async function loadRooms() {
  const data = await api("/api/me");
  roomsList = Array.isArray(data.rooms) ? data.rooms : [];
  renderSidebar();
  return roomsList;
}

/** @returns {object|null} salon courant. */
export function getCurrentRoom() {
  return currentRoom;
}

/** @returns {Array} tous les salons connus de l'utilisateur (sidebar). */
export function getRooms() {
  return roomsList;
}

/** @returns {Array} membres du salon courant. */
export function getCurrentMembers() {
  return currentMembers;
}

/* ============================================================
   Création / adhésion
   ============================================================ */

/**
 * Crée un salon : POST /api/rooms, génération de la clé de salon et
 * enveloppement de celle-ci pour soi-même (POST /api/rooms/{id}/keys).
 */
async function createRoom(name) {
  const data = await api("/api/rooms", { method: "POST", body: { name } });
  const room = data.room || data;
  const roomId = room.id != null ? room.id : room.room_id;

  // 1. Générer la clé de salon (AES-256-GCM, 32 octets aléatoires).
  const { key, raw } = await crypto.generateRoomKey();
  crypto.storeRoomKey(roomId, { key, raw });

  // 2. Envelopper la clé pour soi-même.
  const me = getCurrentUser();
  const myPublicKey = await crypto.importPublicKeyFromBase64(
    crypto.getUserPublicKeyBase64(),
  );
  const wrapped = await crypto.wrapRoomKeyFor(myPublicKey, raw);
  await api(`/api/rooms/${roomId}/keys`, {
    method: "POST",
    body: { target_user_id: me.id, wrapped_key: wrapped },
  });

  // 3. Rafraîchir la sidebar puis ouvrir le salon.
  await loadRooms();
  await selectRoom(roomId);
  return room;
}

/**
 * Rejoint un salon. L'utilisateur ne détient pas (encore) la clé : un membre
 * présent la partagera à son nom (WS `member_joined` → auto-wrap, ou bouton
 * « Actualiser clés »), et la copie arrivera via l'événement WS `room_key`.
 */
async function joinRoom(roomId) {
  await api(`/api/rooms/${roomId}/join`, { method: "POST" });
  await loadRooms();
  await selectRoom(roomId);
  onToast(
    "Salon rejoint. En attente de la clé de salon partagée par un membre…",
  );
}

/* ============================================================
   Sélection de salon
   ============================================================ */

/** Ouvre un salon : charge membres + historique, met à jour l'UI. */
export async function selectRoom(roomId) {
  const room = roomsList.find((r) => String(r.id) === String(roomId));
  if (!room && currentRoom && String(currentRoom.id) === String(roomId)) {
    // Cas de l'adhésion : le salon peut ne pas être dans roomsList si /api/me
    // n'a pas été rechargé — on conserve l'objet courant.
    showRoomUI();
    return currentRoom;
  }
  if (!room) {
    onToast("Salon introuvable après chargement.");
    return null;
  }

  currentRoom = room;
  renderSidebar(); // surligne le salon actif

  await refreshMembers();

  // Ouvre le fil de discussion (chargement + déchiffrement de l'historique).
  await chat.openRoom(currentRoom.id, currentMembers);

  showRoomUI();
  onRoomOpened(currentRoom.id);
  return currentRoom;
}

/** Affiche les panneaux du salon et masque l'état vide. */
function showRoomUI() {
  document.getElementById("empty-state").hidden = true;
  document.getElementById("room-header").hidden = false;
  document.getElementById("messages").hidden = false;
  document.getElementById("message-form").hidden = false;
  document.getElementById("members-panel").hidden = false;
}

/** Masque les panneaux du salon (aucun salon sélectionné). */
export function hideRoomUI() {
  document.getElementById("empty-state").hidden = false;
  document.getElementById("room-header").hidden = true;
  document.getElementById("messages").hidden = true;
  document.getElementById("message-form").hidden = true;
  document.getElementById("members-panel").hidden = true;
}

/* ============================================================
   Membres
   ============================================================ */

/** Récupère et affiche les membres du salon courant. */
export async function refreshMembers() {
  if (!currentRoom) {
    return;
  }
  const members = await api(`/api/rooms/${currentRoom.id}/members`);
  currentMembers = Array.isArray(members) ? members : [];
  renderMembers();
}

/** Rend la liste des membres (avec la clé publique, utile au wrapping). */
function renderMembers() {
  const me = getCurrentUser();
  const listEl = document.getElementById("members-list");
  listEl.textContent = "";

  currentMembers.forEach((member) => {
    const item = document.createElement("li");
    item.className = "member-item";

    const avatar = document.createElement("span");
    avatar.className = "avatar " + avatarHueClass(member.username || "?");
    avatar.textContent = (member.username || "?").charAt(0);
    item.appendChild(avatar);

    const name = document.createElement("span");
    name.textContent = member.username || "Inconnu";
    item.appendChild(name);

    if (me && String(member.id) === String(me.id)) {
      const you = document.createElement("span");
      you.className = "member-you";
      you.textContent = "(vous)";
      item.appendChild(you);
    }

    listEl.appendChild(item);
  });

  const countEl = document.getElementById("room-members-count");
  const count = currentMembers.length;
  countEl.textContent = count + " membre" + (count > 1 ? "s" : "");
}

/* ============================================================
   Temps réel : member_joined et room_key
   ============================================================ */

/**
 * Événement WS `member_joined` : rafraîchit les membres et, si l'on détient la
 * clé de salon, l'enveloppe automatiquement pour le nouveau membre.
 */
export async function handleMemberJoined(payload) {
  const roomId = payload.room_id != null ? payload.room_id : payload.roomId;
  const member = payload.user || payload.member || null;
  if (roomId == null || !member || member.id == null) {
    return;
  }

  // Rafraîchir la liste des membres si le salon est ouvert.
  if (currentRoom && String(currentRoom.id) === String(roomId)) {
    try {
      await refreshMembers();
    } catch {
      // affichage non critique
    }
  }

  // Partager la clé si on la possède.
  const isOwnRoomKey = crypto.getRoomKeyRaw(roomId);
  if (!isOwnRoomKey) {
    return;
  }

  const sharedMember = currentMembers.find(
    (m) => String(m.id) === String(member.id),
  ) || member;
  const publicKeyB64 = sharedMember.public_key || member.public_key;

  if (!publicKeyB64) {
    // Si le salon est ouvert, on prévient l'utilisateur ; sinon le silence est
    // préférable (l'auto-partage se fera via un autre membre / « Actualiser clés »).
    const isCurrentRoom = currentRoom && String(currentRoom.id) === String(roomId);
    if (isCurrentRoom) {
      onToast(
        "Nouveau membre sans clé publique dans l'événement : " +
          "cliquez sur « Actualiser clés » pour ré-envelopper.",
      );
    }
    return;
  }

  try {
    await wrapAndPostKey(roomId, member.id, publicKeyB64);
    onToast("Clé de salon partagée avec « " + (member.username || "membre") + " ».");
  } catch (error) {
    onToast("Partage de clé impossible : " + (error.message || "erreur"));
  }
}

/**
 * Événement WS `room_key` : une copie enveloppée de la clé de salon nous est
 * destinée (je viens de rejoindre, ou un membre a ré-enveloppé). On la
 * déchiffre avec notre clé privée et on recharge l'historique si besoin.
 */
export async function handleRoomKey(payload) {
  const roomId = payload.room_id != null ? payload.room_id : payload.roomId;
  const wrapped = payload.wrapped_key || payload.key;
  if (roomId == null || !wrapped) {
    return;
  }

  // Déjà en possession de la clé pour ce salon ? Rien à faire.
  if (crypto.getRoomKeyRaw(roomId)) {
    return;
  }

  const privateKey = crypto.getUserPrivateKey();
  if (!privateKey) {
    return;
  }

  try {
    const { key, raw } = await crypto.unwrapRoomKeyFor(wrapped, privateKey);
    crypto.storeRoomKey(roomId, { key, raw });
    onToast("Clé de salon reçue : les messages sont maintenant déchiffrables.");
  } catch (error) {
    onToast("Échec du déchiffrement de la clé de salon : " + (error.message || "erreur"));
    return;
  }

  // Si le salon est ouvert, on recharge l'historique (désormais déchiffrable).
  if (currentRoom && String(currentRoom.id) === String(roomId)) {
    chat.reloadHistory();
  }
}

/* ============================================================
   Bouton « Actualiser clés »
   ============================================================ */

/**
 * Ré-enveloppe la clé de salon pour TOUS les membres actuels.
 * Utile si un auto-partage (`member_joined`) a échoué ou l'a été hors-ligne :
 * chaque membre recevra (ou récupérera) sa copie enveloppée via `room_key`.
 */
export async function refreshCurrentRoomKeys() {
  if (!currentRoom) {
    onToast("Aucun salon sélectionné.");
    return;
  }
  const rawKey = crypto.getRoomKeyRaw(currentRoom.id);
  if (!rawKey) {
    onToast(
      "Vous ne détenez pas la clé de ce salon sur ce navigateur. " +
        "Un autre membre doit cliquer sur « Actualiser clés » pour vous la partager.",
    );
    return;
  }

  let shared = 0;
  for (const member of currentMembers) {
    if (!member.public_key) {
      continue;
    }
    try {
      await wrapAndPostKey(currentRoom.id, member.id, member.public_key);
      shared += 1;
    } catch {
      // on continue pour les autres membres
    }
  }
  onToast(
    "Clé de salon ré-enveloppée pour " + shared + " membre(s) sur " + currentMembers.length + ".",
  );
}

/** Enveloppe la clé de salon pour un membre précis puis l'enregistre. */
async function wrapAndPostKey(roomId, targetUserId, publicKeyBase64) {
  const publicKey = await crypto.importPublicKeyFromBase64(publicKeyBase64);
  const wrapped = await crypto.wrapRoomKeyFor(publicKey, crypto.getRoomKeyRaw(roomId));
  await api(`/api/rooms/${roomId}/keys`, {
    method: "POST",
    body: { target_user_id: targetUserId, wrapped_key: wrapped },
  });
}

/* ============================================================
   Helpers d'interface
   ============================================================ */

/** Construit la sidebar (liste des salons + actif surligné). */
function renderSidebar() {
  const listEl = document.getElementById("room-list");
  listEl.textContent = "";

  roomsList.forEach((room) => {
    const item = document.createElement("div");
    item.className = "room-item" + (currentRoom && String(currentRoom.id) === String(room.id) ? " active" : "");

    const icon = document.createElement("span");
    icon.className = "room-icon";
    icon.textContent = "#";
    item.appendChild(icon);

    const name = document.createElement("span");
    name.className = "room-name";
    name.textContent = room.name;
    item.appendChild(name);

    item.setAttribute("role", "button");
    item.tabIndex = 0;
    item.addEventListener("click", () => {
      selectRoom(room.id);
    });
    item.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectRoom(room.id);
      }
    });

    listEl.appendChild(item);
  });
}

/** Ouvre une modale et donne le focus au champ. */
function openModal(modalId, inputId) {
  document.getElementById(modalId).hidden = false;
  const input = document.getElementById(inputId);
  input.value = "";
  input.focus();
  return input;
}

/** Ferme une modale et efface son erreur éventuelle. */
function closeModal(modalId) {
  document.getElementById(modalId).hidden = true;
  const errorEl = document.querySelector("#" + modalId + " .auth-error");
  if (errorEl) {
    errorEl.hidden = true;
    errorEl.textContent = "";
  }
}

/** Affiche une erreur dans une modale. */
function showModalError(modalId, message) {
  const errorEl = document.querySelector("#" + modalId + " .auth-error");
  errorEl.textContent = message;
  errorEl.hidden = false;
}

/**
 * Classe CSS d'avatar déterministe par pseudo (6 teintes prédéfinies,
 * aucune couleur inline — compatible avec `style-src 'self'`).
 */
function avatarHueClass(username) {
  let hash = 0;
  for (let i = 0; i < username.length; i += 1) {
    hash = (hash * 31 + username.charCodeAt(i)) >>> 0;
  }
  return "avatar-hue-" + (hash % 6);
}