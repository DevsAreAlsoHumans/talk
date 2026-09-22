/**
 * rooms.js — Salons : sidebar (badges de non-lus, menus contextuels), création,
 * adhésion, quitter un salon, panneau membres avec présence en ligne et gestion
 * de la clé de salon (enveloppement / ré-enveloppement vers les membres).
 *
 * Rappel du modèle E2E :
 *   - Création  : on génère la clé de salon (32 octets) et on en pose une copie
 *                 enveloppée (RSA-OAEP) avec SA PROPRE clé publique.
 *   - Ajout     : le membre déjà présent déchiffre sa copie, la ré-enveloppe
 *                 avec la clé publique du nouveau membre puis POST /keys.
 *   - Nouvel adhérent : ne détient rien à l'inscription ; il reçoit sa copie
 *                 enveloppée via l'événement WS `room_key` une fois qu'un membre
 *                 a POSTé la copie à son nom.
 *
 * Présence : choix de conception justifié — on **patche localement** (état
 * mémoire + re-rendu du panneau) plutôt que de refetch les membres à chaque
 * événement `presence`. Les événements portent l'état global d'un utilisateur
 * (`user_id`, `online`) et arrivent sans `room_id` : recharger la liste complète
 * (avec les blobs de clés publiques) à chaque bascule serait du gaspillage
 * réseau inutile, et le patch est idempotent (aucune course possible avec des
 * événements concurrents). Le fetch complet reste fait à l'ouverture du salon
 * et lors des `member_joined`/`member_left`.
 */

import { api } from "./api.js";
import * as crypto from "./crypto.js";
import { getCurrentUser, setCurrentUser } from "./auth.js";
import * as chat from "./chat.js";
import * as ui from "./ui.js";

/** Titre de base (document.title), actualisé avec le total des non-lus. */
const BASE_TITLE = "Caché — chat chiffré de bout en bout";

/** Callbacks posés par main.js. */
let onToast = () => {};
let onRoomOpened = () => {};
let onRoomsChanged = () => {};

/** Gestionnaire de clic sur une ligne du panneau membres (posé par main.js). */
let onMemberClick = () => {};

/**
 * Enregistre le gestionnaire de clic des lignes membres (main.js le branche
 * sur profile.openProfileFor). Évite à rooms.js d'importer profile.js.
 * @param {(member: object) => void} handler
 */
export function setMemberClickHandler(handler) {
  onMemberClick = typeof handler === "function" ? handler : onMemberClick;
}

/** Salon actuellement sélectionné. */
let currentRoom = null;

/** Liste des salons de l'utilisateur (depuis /api/me). */
let roomsList = [];

/** Membres du salon courant : [{id, username, public_key, online}]. */
let currentMembers = [];

/** Non-lus par salon : roomId → nombre de messages reçus hors ouverture. */
const unreadCounts = new Map();

/**
 * Branche l'interface des salons (sidebar, modales, panneau membres, menus).
 * @param {{onToast?: (message: string, type?: string) => void,
 *          onRoomOpened?: (roomId: string|number) => void,
 *          onRoomsChanged?: () => void}} callbacks
 */
export function initRooms({ onToast: toastCallback, onRoomOpened: openedCallback, onRoomsChanged: roomsChanged }) {
  onToast = toastCallback || onToast;
  onRoomOpened = openedCallback || onRoomOpened;
  onRoomsChanged = roomsChanged || onRoomsChanged;

  // ---- Boutons de la sidebar ----
  document.getElementById("btn-new-room").addEventListener("click", () => {
    ui.openModal(document.getElementById("modal-new-room"), "#new-room-name");
  });
  document.getElementById("btn-join-room").addEventListener("click", () => {
    ui.openModal(document.getElementById("modal-join-room"), "#join-room-id");
  });

  // ---- Modale « nouveau salon » ----
  document.getElementById("form-new-room").addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = document.getElementById("new-room-name");
    const name = input.value.trim();
    if (!name) {
      showModalError("new-room-error", "Donnez un nom au salon.");
      return;
    }
    const createBtn = document.getElementById("btn-create-room");
    createBtn.disabled = true;
    try {
      // createRoom ouvre déjà le salon (selectRoom → onRoomOpened).
      await createRoom(name);
      ui.closeModal(document.getElementById("modal-new-room"));
      input.value = "";
    } catch (error) {
      showModalError("new-room-error", error.message || "Création impossible.");
    } finally {
      createBtn.disabled = false;
    }
  });
  document.getElementById("btn-cancel-new-room").addEventListener("click", () => {
    ui.closeModal(document.getElementById("modal-new-room"));
  });

  // ---- Modale « rejoindre un salon » ----
  document.getElementById("form-join-room").addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = document.getElementById("join-room-id");
    // Les identifiants de salon sont des uuid4.hex : 32 caractères hexadécimaux.
    // On normalise en minuscules (uuid4.hex est minuscule — les clés Redis le sont).
    const roomId = input.value.trim().toLowerCase();
    if (!/^[0-9a-f]{32}$/i.test(roomId)) {
      showModalError("join-room-error", "L'identifiant est invalide.");
      return;
    }
    const joinBtn = document.getElementById("btn-join-room-submit");
    joinBtn.disabled = true;
    try {
      // joinRoom ouvre déjà le salon (selectRoom → onRoomOpened).
      await joinRoom(roomId);
      ui.closeModal(document.getElementById("modal-join-room"));
      input.value = "";
    } catch (error) {
      showModalError("join-room-error", error.message || "Impossible de rejoindre.");
    } finally {
      joinBtn.disabled = false;
    }
  });
  document.getElementById("btn-cancel-join-room").addEventListener("click", () => {
    ui.closeModal(document.getElementById("modal-join-room"));
  });

  // ---- Copie de l'identifiant du salon courant (header) ----
  document.getElementById("btn-copy-room-id").addEventListener("click", () => {
    requestCopyRoomId();
  });

  // ---- Panneau membres / bouton « Actualiser clés » ----
  document.getElementById("btn-refresh-keys").addEventListener("click", () => {
    refreshCurrentRoomKeys();
  });

  // ---- Menu "..." de l'en-tête de salon : quitter le salon ----
  document.getElementById("btn-room-menu").addEventListener("click", (event) => {
    event.stopPropagation();
    if (!currentRoom) {
      return;
    }
    const room = currentRoom;
    ui.openMenu(event.currentTarget, [
      {
        label: "Quitter le salon",
        danger: true,
        onClick: () => requestLeaveRoom(room),
      },
    ]);
  });
}

/** Affiche une erreur dans une modale (élément role="alert"). */
function showModalError(errorElementId, message) {
  const errorEl = document.getElementById(errorElementId);
  errorEl.textContent = message;
  errorEl.hidden = false;
}

/* ============================================================
   Listing & sidebar
   ============================================================ */

/** Charge /api/me et construit la sidebar. @returns {Promise<Array>} salons. */
export async function loadRooms() {
  const data = await api("/api/me");
  // Le backend renvoie {user, rooms} : on rafraîchit l'utilisateur courant
  // (display_name / about peuvent avoir changé depuis un autre appareil).
  if (data && data.user && typeof data.user === "object") {
    setCurrentUser(data.user);
  }
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

/** Construit la sidebar (salons, badge de non-lus, menu "..." au survol). */
function renderSidebar() {
  const listEl = document.getElementById("room-list");
  listEl.textContent = "";

  for (const room of roomsList) {
    const item = document.createElement("div");
    item.className =
      "room-item" +
      (currentRoom && String(currentRoom.id) === String(room.id) ? " room-item--active" : "");
    item.dataset.roomId = String(room.id);
    item.setAttribute("role", "button");
    item.tabIndex = 0;

    const icon = document.createElement("span");
    icon.className = "room-icon";
    icon.textContent = "#";
    item.appendChild(icon);

    const name = document.createElement("span");
    name.className = "room-name";
    name.textContent = room.name;
    item.appendChild(name);

    // Badge de messages non lus (pill accent ; masqué si nul).
    const count = unreadCounts.get(String(room.id)) || 0;
    const badge = document.createElement("span");
    badge.className = "room-badge";
    badge.hidden = count <= 0;
    if (count > 0) {
      badge.textContent = formatUnread(count);
    }
    item.appendChild(badge);

    // Menu contextuel "..." (visible au survol) → « Quitter le salon ».
    const menuBtn = document.createElement("button");
    menuBtn.type = "button";
    menuBtn.className = "icon-btn room-menu-btn";
    menuBtn.setAttribute("aria-label", "Options du salon " + room.name);
    menuBtn.appendChild(ui.icon("dots"));
    menuBtn.addEventListener("click", (event) => {
      event.stopPropagation();
      ui.openMenu(menuBtn, [
        {
          label: "Quitter le salon",
          danger: true,
          onClick: () => requestLeaveRoom(room),
        },
      ]);
    });
    item.appendChild(menuBtn);

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
  }
}

/** Formate un compteur de non-lus (plafonné à 99+ pour la lisibilité). */
function formatUnread(count) {
  return count > 99 ? "99+" : String(count);
}

/** Retourne l'élément `.room-item` d'un salon (ou null). */
function roomItemEl(roomId) {
  const key = String(roomId);
  return document.querySelector(`.room-item[data-room-id=${CSS.escape(key)}]`);
}

/* ============================================================
   Non-lus : comptage, badge, titre d'onglet
   ============================================================ */

/**
 * Réception d'un `new_message` (main.js). Si le salon n'est pas celui qui est
 * ouvert : incrément du badge + du total d'onglet. Ouverture → reset (selectRoom).
 */
export function handleRoomMessageUnread(payload) {
  const roomId = payload && (payload.room_id != null ? payload.room_id : payload.roomId);
  if (roomId == null) {
    return;
  }
  const key = String(roomId);

  // Salon ouvert dans cet onglet : pas de non-lu.
  if (currentRoom && String(currentRoom.id) === key) {
    return;
  }

  // Salon inconnu de la sidebar (rejoint depuis un autre onglet) : on rafraîchit
  // /api/me puis on applique le compteur.
  if (!roomsList.some((r) => String(r.id) === key)) {
    loadRooms()
      .then(() => {
        if (roomsList.some((r) => String(r.id) === key)) {
          bumpUnread(key);
        }
      })
      .catch(() => {});
    return;
  }

  bumpUnread(key);
}

/** Incrémente le compteur d'un salon et met à jour badge + titre. */
function bumpUnread(roomKey) {
  unreadCounts.set(roomKey, (unreadCounts.get(roomKey) || 0) + 1);
  updateBadge(roomKey);
  updateTitle();
}

/** Remet à zéro les non-lus d'un salon (appelé à son ouverture). */
export function resetUnread(roomId) {
  const key = String(roomId);
  unreadCounts.delete(key);
  updateBadge(key);
  updateTitle();
}

/** Met à jour le badge d'un salon sans reconstruire toute la sidebar. */
function updateBadge(roomKey) {
  const item = roomItemEl(roomKey);
  if (!item) {
    renderSidebar();
    return;
  }
  const badge = item.querySelector(".room-badge");
  if (!badge) {
    return;
  }
  const count = unreadCounts.get(roomKey) || 0;
  badge.hidden = count <= 0;
  if (count > 0) {
    badge.textContent = formatUnread(count);
  }
}

/** Total des non-lus dans `document.title` (optionnel mais propre). */
function updateTitle() {
  let total = 0;
  for (const count of unreadCounts.values()) {
    total += count;
  }
  document.title = total > 0 ? `(${total}) ${BASE_TITLE}` : BASE_TITLE;
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
 * présent la partagera à son nom, et la copie arrivera via `room_key`.
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

/** Ouvre un salon : charge membres + historique, remet à zéro les non-lus. */
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

  // Restauration opportuniste : si la clé du salon manque (par ex. après un
  // rechargement de page), on tente de la récupérer depuis la copie enveloppée
  // que le serveur conserve à notre nom. Silencieux en cas d'échec.
  // Sans risque de course avec un éventuel `restoreRoomKeys()` en vol :
  // `storeRoomKey` est idempotent et les deux écrivent la même valeur de clé.
  if (!crypto.getRoomKeyRaw(currentRoom.id)) {
    await restoreRoomKey(currentRoom.id);
  }

  // Ouvre le fil de discussion (chargement + déchiffrement de l'historique).
  await chat.openRoom(currentRoom.id, currentMembers);

  resetUnread(roomId);
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
  updateRoomIdBadge();
}

/** Masque les panneaux du salon (aucun salon sélectionné). */
export function hideRoomUI() {
  document.getElementById("empty-state").hidden = false;
  document.getElementById("room-header").hidden = true;
  document.getElementById("messages").hidden = true;
  document.getElementById("message-form").hidden = true;
  document.getElementById("members-panel").hidden = true;
  const idBadge = document.getElementById("room-id-badge");
  if (idBadge) {
    idBadge.hidden = true;
  }
}

/* ============================================================
   Restauration des clés de salon (rechargement de page)
   ============================================================ */

/**
 * Tente de restaurer la clé de salon d'un salon depuis la copie enveloppée que
 * le serveur conserve à notre nom (GET /api/rooms/{id}/keys). Silencieux :
 * tout échec renvoie `false` sans jamais lever d'exception (salon sauté).
 * @param {string|number} roomId
 * @returns {Promise<boolean>} true si une clé a été restaurée.
 */
async function restoreRoomKey(roomId) {
  // Clé déjà présente en mémoire : rien à faire.
  if (crypto.getRoomKeyRaw(roomId)) {
    return false;
  }
  // Clé privée pas encore déchiffrée : la restauration est impossible.
  const privateKey = crypto.getUserPrivateKey();
  if (!privateKey) {
    return false;
  }
  try {
    const data = await api(`/api/rooms/${roomId}/keys`);
    const wrapped = data && data.wrapped_key;
    if (!wrapped) {
      return false; // aucune copie enveloppée à notre nom
    }
    const { key, raw } = await crypto.unwrapRoomKeyFor(wrapped, privateKey);
    crypto.storeRoomKey(roomId, { key, raw });
    return true;
  } catch {
    return false; // erreur isolée : le salon est sauté
  }
}

/**
 * Restaure les clés de salon manquantes (après un F5, les clés ne vivent qu'en
 * mémoire) depuis les copies enveloppées du serveur. Une erreur individuelle ne
 * bloque pas les autres salons.
 * @returns {Promise<number>} nombre de clés restaurées.
 */
export async function restoreRoomKeys() {
  if (!crypto.getUserPrivateKey()) {
    return 0;
  }
  let restored = 0;
  for (const room of roomsList) {
    if (await restoreRoomKey(room.id)) {
      restored += 1;
    }
  }
  return restored;
}

/* ============================================================
   Partage : copie de l'identifiant du salon courant
   ============================================================ */

/**
 * Copie l'identifiant du salon courant dans le presse-papier puis notifie.
 * Le clic déclenche l'action (le presse-papier exige un geste utilisateur).
 */
function requestCopyRoomId() {
  if (!currentRoom || currentRoom.id == null) {
    onToast("Aucun salon sélectionné.", "info");
    return;
  }
  const id = String(currentRoom.id);
  copyTextToClipboard(id)
    .then(() => {
      onToast("Identifiant copié.", "success");
    })
    .catch(() => {
      onToast("Copie impossible sur ce navigateur.", "error");
    });
}

/**
 * Copie du texte dans le presse-papier.
 * - API moderne `navigator.clipboard.writeText` (contexte sécurisé) ;
 * - repli `document.execCommand("copy")` sur un `<textarea>` hors écran
 *   (classe `.clipboard-helper`, aucun style inline — CSP respectée).
 *
 * Exportée pour être réutilisée par le menu « Paramètres » (main.js) pour la
 * copie de l'identifiant utilisateur, sans dupliquer la logique de repli.
 * @param {string} text
 * @returns {Promise<void>} résolue une fois le texte copié.
 */
export async function copyTextToClipboard(text) {
  if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // repli ci-dessous
    }
  }

  const textarea = document.createElement("textarea");
  textarea.className = "clipboard-helper";
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  document.body.appendChild(textarea);
  textarea.select();
  textarea.setSelectionRange(0, text.length);

  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  textarea.remove();

  if (!ok) {
    throw new Error("Presse-papier indisponible.");
  }
}

/**
 * Abrège un identifiant hexadécimal de 32 caractères pour l'étiquette du
 * header (« 9f2c…0b1a ») ; valeur inattendue → affichage complet.
 * @param {string} id
 * @returns {string}
 */
function abbreviateRoomId(id) {
  const text = String(id);
  return /^[0-9a-f]{32}$/i.test(text) ? text.slice(0, 4) + "…" + text.slice(-4) : text;
}

/** Met à jour l'étiquette discrète « ID: … » du header du salon courant. */
function updateRoomIdBadge() {
  const badge = document.getElementById("room-id-badge");
  if (!badge) {
    return;
  }
  if (!currentRoom || currentRoom.id == null) {
    badge.hidden = true;
    return;
  }
  const id = String(currentRoom.id);
  badge.textContent = "ID: " + abbreviateRoomId(id);
  badge.title = id; // identifiant complet au survol
  badge.hidden = false;
}

/* ============================================================
   Quitter un salon
   ============================================================ */

/** Demande de confirmation puis quitte (menu sidebar ou en-tête). */
async function requestLeaveRoom(room) {
  const ok = await ui.confirmDialog({
    title: "Quitter le salon",
    message: `Quitter le salon « ${room.name} » ? Vous pourrez le rejoindre plus tard s'il existe encore.`,
    confirmLabel: "Quitter",
    danger: true,
  });
  if (!ok) {
    return;
  }
  try {
    await leaveRoom(room.id);
  } catch (error) {
    onToast(error.message || "Impossible de quitter le salon.", "error");
  }
}

/**
 * Quitte un salon : POST /api/rooms/{id}/leave → 204, puis retrait local
 * (sidebar, clé de salon locale, non-lus) et état vide si le salon est ouvert.
 */
export async function leaveRoom(roomId) {
  const room = roomsList.find((r) => String(r.id) === String(roomId));
  await api(`/api/rooms/${roomId}/leave`, { method: "POST" });

  // Hygiène locale : la copie de clé enveloppée est purgée côté serveur,
  // on oublie aussi la clé de salon de ce navigateur.
  crypto.removeRoomKey(roomId);
  unreadCounts.delete(String(roomId));

  const wasCurrent = currentRoom && String(currentRoom.id) === String(roomId);
  roomsList = roomsList.filter((r) => String(r.id) !== String(roomId));

  if (wasCurrent) {
    currentRoom = null;
    currentMembers = [];
    chat.closeRoom();
    hideRoomUI();
  }

  renderSidebar();
  updateTitle();
  onRoomsChanged();
  onToast(`Vous avez quitté « ${room ? room.name : roomId} ».`, "success");
}

/* ============================================================
   Membres & présence
   ============================================================ */

/** Récupère et affiche les membres du salon courant (fetch complet). */
export async function refreshMembers() {
  if (!currentRoom) {
    return;
  }
  const members = await api(`/api/rooms/${currentRoom.id}/members`);
  currentMembers = Array.isArray(members) ? members : [];
  renderMembers();
}

/**
 * Rend le panneau membres : deux sections « En ligne — N » puis « Hors ligne »,
 * tri alphabétique à l'intérieur de chaque section, en ligne d'abord.
 * Met aussi à jour l'en-tête : « N membres — M en ligne ».
 */
function renderMembers() {
  const me = getCurrentUser();
  const online = [];
  const offline = [];
  for (const member of currentMembers) {
    (member.online ? online : offline).push(member);
  }
  const byName = (a, b) => String(a.username).localeCompare(String(b.username), "fr");
  online.sort(byName);
  offline.sort(byName);

  document.getElementById("members-online-title").textContent =
    `En ligne — ${online.length}`;
  document.getElementById("members-offline-title").textContent = "Hors ligne";

  // Groupe hors ligne masqué quand vide.
  const offlineGroup = document.getElementById("members-offline-group");
  offlineGroup.hidden = offline.length === 0;

  renderMemberList("members-online", online, me);
  renderMemberList("members-offline", offline, me);

  const total = currentMembers.length;
  const countEl = document.getElementById("room-members-count");
  countEl.textContent =
    `${total} membre${total > 1 ? "s" : ""} — ${online.length} en ligne`;
}

/** Remplit une `<ul>` de membres (avatar + pastille de présence + nom). */
function renderMemberList(listId, members, me) {
  const listEl = document.getElementById(listId);
  listEl.textContent = "";

  for (const member of members) {
    const item = document.createElement("li");
    item.className = "member-item";
    item.setAttribute("role", "button");
    item.tabIndex = 0;
    // Clic/Entrée → fiche profil (display_name || username pour l'affichage).
    const openProfile = (event) => {
      event.stopPropagation();
      onMemberClick({
        id: member.id,
        username: member.username,
        display_name: member.display_name || null,
        about: member.about || null,
      });
    };
    item.addEventListener("click", openProfile);
    item.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openProfile(event);
      }
    });

    const avatarWrap = document.createElement("span");
    avatarWrap.className = "member-avatar-wrap";

    const avatar = document.createElement("span");
    avatar.className = "avatar avatar--member " + ui.avatarHueClass(member.username || "?");
    avatar.textContent = (member.username || "?").charAt(0).toUpperCase();
    avatarWrap.appendChild(avatar);

    const dot = document.createElement("span");
    dot.className = "presence-dot " + (member.online ? "presence-dot--online" : "presence-dot--offline");
    dot.setAttribute("aria-hidden", "true");
    avatarWrap.appendChild(dot);

    item.appendChild(avatarWrap);

    const name = document.createElement("span");
    name.className = "member-name";
    // Le display_name (si présent) prime ; l'avatar reste sur le username.
    name.textContent = member.display_name || member.username || "Inconnu";
    item.appendChild(name);

    if (me && String(member.id) === String(me.id)) {
      const you = document.createElement("span");
      you.className = "member-you";
      you.textContent = "(vous)";
      item.appendChild(you);
    }

    listEl.appendChild(item);
  }
}

/**
 * Événement WS `presence` : patch ciblé de l'état local du membre (idempotent),
 * puis re-rendu du panneau — sans refetch réseau (justifié en tête de module).
 */
export function handlePresence(payload) {
  const userId = payload && (payload.user_id != null ? payload.user_id : payload.userId);
  if (userId == null) {
    return;
  }
  const target = currentMembers.find((m) => String(m.id) === String(userId));
  if (!target) {
    return; // membre d'un autre salon que celui affiché
  }
  const online = Boolean(payload.online);
  if (target.online === online) {
    return; // événement dupliqué (un par salon partagé) : rien à faire
  }
  target.online = online;
  renderMembers();
}

/**
 * Événement WS `member_left` : retrait du membre du panneau + compteurs.
 * Si le membre qui part est nous-même (autre onglet), on recharge la sidebar.
 */
export async function handleMemberLeft(payload) {
  const roomId = payload && (payload.room_id != null ? payload.room_id : payload.roomId);
  const member = payload && payload.member;
  if (roomId == null || !member || member.id == null) {
    return;
  }

  const me = getCurrentUser();

  // Membre du salon actuellement ouvert : suppression ciblée, sans refetch.
  if (currentRoom && String(currentRoom.id) === String(roomId)) {
    const before = currentMembers.length;
    currentMembers = currentMembers.filter((m) => String(m.id) !== String(member.id));
    if (currentMembers.length !== before) {
      renderMembers();
    }
  }

  // Nous-même (autre onglet) : /api/me peut avoir changé (salon supprimé…).
  if (me && String(member.id) === String(me.id)) {
    try {
      await loadRooms();
    } catch {
      // affichage non critique
    }
  }

  // Le salon ouvert n'existe plus côté utilisateur → retour à l'état vide.
  if (currentRoom && !roomsList.some((r) => String(r.id) === String(currentRoom.id))) {
    currentRoom = null;
    currentMembers = [];
    chat.closeRoom();
    hideRoomUI();
    renderSidebar();
    updateTitle();
    onRoomsChanged();
  }
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
  const rawKey = crypto.getRoomKeyRaw(roomId);
  if (!rawKey) {
    return;
  }

  const sharedMember = currentMembers.find(
    (m) => String(m.id) === String(member.id),
  ) || member;
  const publicKeyB64 = sharedMember.public_key || member.public_key;

  if (!publicKeyB64) {
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
    const memberName = member.display_name || member.username || "membre";
    onToast("Clé de salon partagée avec « " + memberName + " ».", "success");
  } catch (error) {
    onToast("Partage de clé impossible : " + (error.message || "erreur"), "error");
  }
}

/**
 * Événement WS `room_key` : une copie enveloppée de la clé de salon nous est
 * destinée. On la déchiffre avec notre clé privée et on recharge l'historique.
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
    onToast("Clé de salon reçue : les messages sont maintenant déchiffrables.", "success");
  } catch (error) {
    onToast(
      "Échec du déchiffrement de la clé de salon : " + (error.message || "erreur"),
      "error",
    );
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
 * Chaque membre recevra sa copie enveloppée via `room_key`.
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
    "success",
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