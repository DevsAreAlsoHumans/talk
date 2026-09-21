/**
 * chat.js — Fil de messages : historique paginé, envoi chiffré, affichage
 * déchiffré, groupement visuel, défilement, suppression, polling de secours.
 *
 * Règles strictes :
 *   - Aucun `innerHTML` avec des données utilisateur : tout le contenu
 *     (messages, pseudos) est injecté via `textContent`.
 *   - Le fil est « à la Discord » : pas de bulles, avatar + pseudo + heure,
 *     regroupement des messages consécutifs d'un même auteur, séparateurs de
 *     dates centrés, bouton de pagination en haut.
 *   - La pagination est gérée par `?limit=50` (ouverture) et
 *     `?before=<seq>&limit=50` (page antérieure), en préservant le scroll.
 */

import { api } from "./api.js";
import * as crypto from "./crypto.js";
import { getCurrentUser } from "./auth.js";
import * as ui from "./ui.js";

/** Taille d'une page d'historique (50 derniers messages à l'ouverture). */
const PAGE_SIZE = 50;

/**
 * Limite client en octets UTF-8 : le ciphertext AES-GCM (+ tag AEAD) puis sa
 * version base64 doivent rester sous la limite serveur (~4096 octets stockés).
 * 3000 octets → ~3016 octets chiffrés → ~4022 caractères base64 : marge sûre.
 */
const MAX_PLAINTEXT_BYTES = 3000;

/**
 * Limite CLIENT pour les pièces jointes : 4 Mo binaires. Le ciphertext base64
 * (~1.34×) reste ainsi bien sous la limite serveur de 6 Mo.
 */
const MAX_ATTACHMENT_BYTES = 4 * 1024 * 1024;

/** Extensions image acceptées en repli quand `file.type` est absent. */
const IMAGE_EXTENSIONS = /\.(gif|png|jpe?g|webp)$/i;

/** Callback de notification (posé par main.js). */
let onToast = () => {};

/** Identifiant du salon actuellement ouvert (null si aucun). */
let currentRoomId = null;

/** @returns {string|null} identifiant du salon ouvert (pour le WS). */
export function getCurrentRoomId() {
  return currentRoomId;
}

/** Plus grand `seq` connu : base du polling `?after=<seq>`. */
let lastMessageId = 0;

/** Plus petit `seq` affiché : borne de la pagination `?before=<seq>`. */
let oldestSeq = null;

/**
 * Séquence d'un message (score Redis, entier) : base du tri et du polling.
 * Le champ `id` est un UUID (non ordonnable) ; seul `seq` est ordonné.
 */
function seqOf(raw) {
  const seq = Number(raw != null ? raw.seq : NaN);
  return Number.isFinite(seq) ? seq : 0;
}

/** Déduplication (anti-doublon entre WS, polling, pagination et envoi local). */
const seenIds = new Set();

/** Pseudo des membres : senderId → username (fourni à l'ouverture du salon). */
let membersById = new Map();

/** Compteur local pour les messages sans id retourné par le serveur. */
let localCounter = 0;

/** Promise de chargement de la première page (évite les lancements concurrents). */
let historyLoading = null;

/** Verrou du chargement « messages précédents ». */
let loadingEarlier = false;

/** Éléments du fil (copies locales, recréées à chaque reset). */
let messagesEl = null;
let loadWrapperEl = null;
let lastMsgEl = null;
let threadHintEl = null;

/* ============================================================
   Branchement initial
   ============================================================ */

/**
 * Branche la zone de saisie et le bouton de pagination.
 * @param {{onToast?: (message: string, type?: string) => void}} callbacks
 */
export function initChat({ onToast: toastCallback }) {
  onToast = toastCallback || onToast;

  const form = document.getElementById("message-form");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = document.getElementById("message-input");
    const text = input.value;
    if (!text.trim()) {
      return;
    }
    input.value = "";
    try {
      const sent = await sendMessage(text);
      if (!sent) {
        input.value = text; // restaure la saisie en cas d'échec
      }
    } catch (error) {
      input.value = text;
      onToast(error.message || "Envoi impossible.", "error");
    }
  });

  // Bouton trombone : ouvre le sélecteur de fichier (images/GIF uniquement).
  const attachBtn = document.getElementById("btn-attach");
  const attachInput = document.getElementById("attach-input");
  if (attachBtn && attachInput) {
    attachBtn.addEventListener("click", () => attachInput.click());
    attachInput.addEventListener("change", async () => {
      const file = attachInput.files && attachInput.files[0];
      // Réinitialise pour autoriser le ré-envoi du même fichier.
      attachInput.value = "";
      if (file) {
        await sendAttachment(file);
      }
    });
  }
}

/* ============================================================
   Ouverture / fermeture de salon
   ============================================================ */

/** Ouvre un salon : réinitialise l'état et charge les 50 derniers messages. */
export async function openRoom(roomId, members) {
  currentRoomId = roomId;
  lastMessageId = 0;
  oldestSeq = null;
  seenIds.clear();
  membersById = new Map((members || []).map((m) => [String(m.id), m.username]));
  resetThread();
  await loadHistory();
}

/** Recharge la première page (utilisé quand une clé de salon arrive). */
export async function reloadHistory() {
  if (!currentRoomId) {
    return;
  }
  lastMessageId = 0;
  oldestSeq = null;
  seenIds.clear();
  resetThread();
  await loadHistory();
}

/** Ferme proprement le fil (salon quitté ou plus aucun salon sélectionné). */
export function closeRoom() {
  currentRoomId = null;
  lastMessageId = 0;
  oldestSeq = null;
  seenIds.clear();
  resetThread();
}

/** Vide le fil et recrée le conteneur de pagination. */
function resetThread() {
  messagesEl = document.getElementById("messages");
  messagesEl.textContent = "";
  lastMsgEl = null;
  threadHintEl = null;

  loadWrapperEl = document.createElement("div");
  loadWrapperEl.className = "message-load";
  loadWrapperEl.hidden = true;

  const button = document.createElement("button");
  button.type = "button";
  button.id = "btn-load-earlier";
  button.className = "btn btn-load-earlier";
  button.textContent = "Charger des messages précédents";
  button.disabled = false;
  button.addEventListener("click", () => {
    loadEarlierMessages();
  });
  loadWrapperEl.appendChild(button);
  messagesEl.appendChild(loadWrapperEl);
}

/** Affiche/masque le bouton de pagination (en tête du fil). */
function showLoadEarlier() {
  if (loadWrapperEl) {
    loadWrapperEl.hidden = false;
  }
}

function hideLoadEarlier() {
  if (loadWrapperEl) {
    loadWrapperEl.hidden = true;
  }
}

/** Recalcule `oldestSeq` depuis le premier message affiché. */
function updateOldestSeq() {
  const first = messagesEl.querySelector(".message");
  const seq = first ? Number(first.dataset.seq) : NaN;
  oldestSeq = Number.isFinite(seq) && seq > 0 ? seq : null;
}

/** Indicateur central « fil vide » (texte non utilisateur). */
function showThreadHint(text) {
  if (!threadHintEl) {
    threadHintEl = document.createElement("div");
    threadHintEl.className = "thread-hint";
    messagesEl.appendChild(threadHintEl);
  }
  threadHintEl.textContent = text;
}

function hideThreadHint() {
  if (threadHintEl) {
    threadHintEl.remove();
    threadHintEl = null;
  }
}

/* ============================================================
   Historique : première page (limit=50)
   ============================================================ */

/** Requête de la première page (protégée contre les lancements concurrents). */
function loadHistory() {
  if (!historyLoading) {
    historyLoading = fetchHistoryAndRender().finally(() => {
      historyLoading = null;
    });
  }
  return historyLoading;
}

async function fetchHistoryAndRender() {
  const roomId = currentRoomId;
  if (!roomId) {
    return;
  }
  const roomKey = crypto.getRoomKey(roomId);

  let items;
  try {
    // GET /api/rooms/{id}/messages?limit=50 → les 50 derniers, croissants.
    const data = await api(`/api/rooms/${roomId}/messages?limit=${PAGE_SIZE}`);
    items = extractMessages(data);
  } catch (error) {
    if (String(roomId) === String(currentRoomId)) {
      showThreadHint("Historique indisponible : " + (error.message || "erreur"));
    }
    return;
  }

  if (String(roomId) !== String(currentRoomId)) {
    return; // le salon a changé pendant la requête
  }

  const ordered = [...items].sort((a, b) => seqOf(a) - seqOf(b));
  for (const raw of ordered) {
    const msg = newMessageFromRaw(raw);
    if (msg && !seenIds.has(msg.id)) {
      await appendMessage(msg, roomKey);
      seenIds.add(msg.id);
      lastMessageId = Math.max(lastMessageId, seqOf(raw));
    }
  }

  if (ordered.length === 0) {
    showThreadHint("Aucun message pour l'instant. Écrivez le premier !");
    hideLoadEarlier();
  } else {
    updateOldestSeq();
    // Page pleine → il peut exister des messages plus anciens.
    if (ordered.length >= PAGE_SIZE) {
      showLoadEarlier();
    } else {
      hideLoadEarlier();
    }
  }
  scrollToBottom();
}

/** Normalise une réponse `{"messages": [...]}` (tolérance tableau nu). */
function extractMessages(data) {
  if (Array.isArray(data)) {
    return data;
  }
  return data && Array.isArray(data.messages) ? data.messages : [];
}

/* ============================================================
   Pagination : page antérieure (before=<seq>)
   ============================================================ */

/**
 * Charge la page précédente et la préfixe dans le DOM, scroll préservé.
 * `?before=<seq du plus ancien message affiché>&limit=50`.
 */
async function loadEarlierMessages() {
  if (!currentRoomId || !oldestSeq || loadingEarlier) {
    return;
  }
  loadingEarlier = true;
  const button = loadWrapperEl && loadWrapperEl.querySelector("button");
  if (button) {
    button.disabled = true;
  }

  const roomId = currentRoomId;
  // Mémorisation pour restaurer la position après l'insertion en tête.
  const prevScrollTop = messagesEl.scrollTop;
  const prevScrollHeight = messagesEl.scrollHeight;

  try {
    const data = await api(
      `/api/rooms/${roomId}/messages?before=${oldestSeq}&limit=${PAGE_SIZE}`,
    );
    if (String(roomId) !== String(currentRoomId)) {
      return;
    }
    let items = extractMessages(data)
      .sort((a, b) => seqOf(a) - seqOf(b))
      .filter((raw) => {
        const msg = newMessageFromRaw(raw);
        return msg && !seenIds.has(msg.id);
      });

    if (items.length === 0) {
      hideLoadEarlier();
      onToast("Début de l'historique.", "info");
      return;
    }

    hideThreadHint();
    const roomKey = crypto.getRoomKey(roomId);
    const fragment = document.createDocumentFragment();
    for (const raw of items) {
      const msg = newMessageFromRaw(raw);
      const node = await buildMessageNode(msg, roomKey);
      seenIds.add(msg.id);
      fragment.appendChild(node);
    }

    // Insertion en tête, dans l'ordre croissant des `seq`.
    const anchor = messagesEl.querySelector(".message");
    messagesEl.insertBefore(fragment, anchor);

    // Regroupement et séparateurs de dates recalculés sur tout le fil
    // (la frontière ancien-nouveau peut changer le premier groupe).
    normalizeGrouping();
    updateOldestSeq();

    if (items.length < PAGE_SIZE) {
      hideLoadEarlier();
    }

    // `lastMessageId` (max) n'est pas affecté : les messages insérés sont
    // antérieurs, donc de `seq` plus petit.
    restoreScroll(prevScrollTop, prevScrollHeight);
  } catch (error) {
    onToast("Chargement impossible : " + (error.message || "erreur"), "error");
  } finally {
    loadingEarlier = false;
    if (button) {
      button.disabled = false;
    }
  }
}

/** Restaure la position de scroll après une insertion en tête. */
function restoreScroll(prevScrollTop, prevScrollHeight) {
  messagesEl.scrollTop = prevScrollTop + (messagesEl.scrollHeight - prevScrollHeight);
}

/* ============================================================
   Temps réel : new_message, message_deleted, polling
   ============================================================ */

/**
 * Applique un nouveau message reçu en temps réel (WebSocket).
 * Les messages d'un autre salon sont ignorés ici (le compteur de non-lus est
 * géré par rooms.js via main.js).
 */
export async function handleNewMessage(payload) {
  const msg = newMessageFromRaw(payload);
  if (!msg) {
    return;
  }
  if (String(msg.room_id) !== String(currentRoomId)) {
    return;
  }
  if (seenIds.has(msg.id)) {
    return; // déjà affiché (polling / envoi local)
  }
  hideThreadHint();
  const roomKey = crypto.getRoomKey(currentRoomId);
  await appendMessage(msg, roomKey);
  seenIds.add(msg.id);
  lastMessageId = Math.max(lastMessageId, seqOf(payload));
  scrollToBottom();
}

/**
 * Événement WS `message_deleted` : retire le message du fil pour tout le monde
 * (ciblé via data-message-id, idempotent).
 */
export function handleMessageDeleted(payload) {
  const roomId = payload && (payload.room_id != null ? payload.room_id : payload.roomId);
  if (roomId == null || String(roomId) !== String(currentRoomId)) {
    return;
  }
  removeMessageNode(payload.id);
}

/** Retire le noeud DOM d'un message (par data-message-id). */
function removeMessageNode(messageId) {
  if (messageId == null) {
    return;
  }
  const node = messagesEl.querySelector(
    `.message[data-message-id=${CSS.escape(String(messageId))}]`,
  );
  if (node) {
    node.remove();
    normalizeGrouping();
    updateOldestSeq();
  }
}

/**
 * Polling de secours : récupère les messages postérieurs à `lastMessageId`.
 * Appelé uniquement quand le WebSocket n'est pas disponible.
 */
export async function pollNewMessages() {
  if (!currentRoomId || !lastMessageId) {
    return;
  }
  // Sans la clé de salon, l'historique n'est pas déchiffrable : inutile de poller.
  if (!crypto.getRoomKey(currentRoomId)) {
    return;
  }

  const roomId = currentRoomId;
  let items;
  try {
    const data = await api(`/api/rooms/${roomId}/messages?after=${lastMessageId}`);
    items = extractMessages(data);
  } catch {
    return; // polling silencieux : on réessaiera au prochain tick
  }

  if (String(roomId) !== String(currentRoomId)) {
    return;
  }
  if (items.length === 0) {
    return;
  }

  const roomKey = crypto.getRoomKey(roomId);
  const ordered = [...items].sort((a, b) => seqOf(a) - seqOf(b));
  for (const raw of ordered) {
    const msg = newMessageFromRaw(raw);
    if (msg && !seenIds.has(msg.id)) {
      hideThreadHint();
      await appendMessage(msg, roomKey);
      seenIds.add(msg.id);
      lastMessageId = Math.max(lastMessageId, seqOf(raw));
    }
  }
  scrollToBottom();
}

/* ============================================================
   Envoi chiffré
   ============================================================ */

/**
 * Envoie un message chiffré : AES-256-GCM avec la clé de salon, puis POST.
 * @returns {Promise<boolean>} true si le message a été envoyé.
 */
export async function sendMessage(text) {
  if (!currentRoomId) {
    onToast("Aucun salon sélectionné.");
    return false;
  }

  const roomKey = crypto.getRoomKey(currentRoomId);
  if (!roomKey) {
    onToast(
      "Clé de salon non disponible sur ce navigateur : " +
        "attendez qu'un membre la partage puis cliquez sur « Actualiser clés ».",
    );
    return false;
  }

  if (crypto.encodeText(text).length > MAX_PLAINTEXT_BYTES) {
    onToast("Message trop long (limite de 3000 octets).");
    return false;
  }

  const user = getCurrentUser();
  const { nonce, ciphertext } = await crypto.encryptMessage(roomKey, text);
  const roomId = currentRoomId;

  const response = await api(`/api/rooms/${roomId}/messages`, {
    method: "POST",
    body: { nonce, ciphertext },
  });

  // Le nouveau message n'est PAS re-broadcasté à l'émetteur : on l'affiche
  // localement après le 201. Le serveur renvoie {"message": {...}}.
  const created = response && typeof response === "object" ? response.message : null;
  let msg;
  if (created && created.id != null) {
    msg = newMessageFromRaw(created);
  } else {
    // Réponse sans métadonnées : on construit un message local.
    localCounter += 1;
    msg = {
      id: "local-" + localCounter,
      room_id: roomId,
      author_id: user ? user.id : null,
      sender: user ? user.username : "",
      nonce,
      ciphertext,
      kind: "text",
      mime: null,
      created_at: new Date().toISOString(),
      encrypted: true,
    };
  }

  // Course possible : le serveur peut broadcaster `new_message` à l'émetteur
  // AVANT que la réponse du POST ne soit traitée → on ne duplique pas l'affichage.
  if (String(roomId) === String(currentRoomId) && !seenIds.has(msg.id)) {
    hideThreadHint();
    await appendMessage(msg, roomKey);
    seenIds.add(msg.id);
  }
  if (created != null && Number.isFinite(seqOf(created))) {
    lastMessageId = Math.max(lastMessageId, seqOf(created));
  }
  scrollToBottom();
  return true;
}

/* ============================================================
   Envoi de pièces jointes (images / GIF) — chiffrement E2E
   ============================================================ */

/**
 * Vrai si le fichier est une image acceptable (type MIME ou extension).
 * Le repli par extension couvre les navigateurs qui ne renseignent pas le type.
 * @param {File} file
 * @returns {boolean}
 */
function isImageFile(file) {
  const type = typeof file.type === "string" ? file.type : "";
  return type.startsWith("image/") || IMAGE_EXTENSIONS.test(String(file.name || ""));
}

/**
 * Lit un fichier en mémoire sous forme d'ArrayBuffer (API FileReader).
 * @param {File} file
 * @returns {Promise<ArrayBuffer>}
 */
function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error || new Error("Lecture impossible."));
    reader.readAsArrayBuffer(file);
  });
}

/**
 * Envoie une image/GIF chiffrée : lecture binaire → `encryptBytes` (AES-256-GCM)
 * → POST /api/rooms/{id}/attachments. Affiche ensuite le message localement avec
 * le même anti-doublon que `sendMessage` (seenIds, course WS, dernier `seq`).
 * @param {File} file Fichier sélectionné (≤ 4 Mo, image).
 * @returns {Promise<boolean>} true si l'image a été envoyée.
 */
export async function sendAttachment(file) {
  if (!file) {
    return false;
  }
  if (!currentRoomId) {
    onToast("Aucun salon sélectionné.");
    return false;
  }

  const roomKey = crypto.getRoomKey(currentRoomId);
  if (!roomKey) {
    onToast(
      "Clé de salon non disponible sur ce navigateur : " +
        "attendez qu'un membre la partage puis cliquez sur « Actualiser clés ».",
    );
    return false;
  }

  if (!isImageFile(file)) {
    onToast("Seules les images et GIFs sont acceptés.", "error");
    return false;
  }
  if (file.size > MAX_ATTACHMENT_BYTES) {
    onToast("Image trop lourde (limite de 4 Mo).", "error");
    return false;
  }

  let bytes;
  try {
    bytes = new Uint8Array(await readFileAsArrayBuffer(file));
  } catch {
    onToast("Lecture du fichier impossible.", "error");
    return false;
  }

  const mime = (file.type || "").startsWith("image/")
    ? file.type
    : sniffImageMime(bytes) || "image/png";

  const user = getCurrentUser();
  const roomId = currentRoomId;
  const { nonce, ciphertext } = await crypto.encryptBytes(roomKey, bytes);

  let response;
  try {
    response = await api(`/api/rooms/${roomId}/attachments`, {
      method: "POST",
      body: { kind: "image", mime, nonce, ciphertext },
    });
  } catch (error) {
    onToast(error.message || "Envoi de l'image impossible.", "error");
    return false;
  }

  // Même logique que sendMessage : métadonnées serveur ou message local de repli.
  const created = response && typeof response === "object" ? response.message : null;
  let msg;
  if (created && created.id != null) {
    msg = newMessageFromRaw(created);
  } else {
    localCounter += 1;
    msg = {
      id: "local-" + localCounter,
      room_id: roomId,
      author_id: user ? user.id : null,
      sender: user ? user.username : "",
      nonce,
      ciphertext,
      kind: "image",
      mime,
      created_at: new Date().toISOString(),
      encrypted: true,
    };
  }

  if (String(roomId) === String(currentRoomId) && !seenIds.has(msg.id)) {
    hideThreadHint();
    await appendMessage(msg, roomKey);
    seenIds.add(msg.id);
  }
  if (created != null && Number.isFinite(seqOf(created))) {
    lastMessageId = Math.max(lastMessageId, seqOf(created));
  }
  scrollToBottom();
  onToast("Image envoyée.", "success");
  return true;
}

/* ============================================================
   Suppression d'un message (auteur uniquement)
   ============================================================ */

/** Menu contextuel → confirmation → DELETE → retrait local. */
async function confirmDeleteMessage(msg, roomId) {
  const ok = await ui.confirmDialog({
    title: "Supprimer le message",
    message:
      "Ce message sera supprimé pour tous les membres du salon. " +
      "Cette action est définitive.",
    confirmLabel: "Supprimer",
    danger: true,
  });
  if (!ok) {
    return;
  }
  try {
    await api(`/api/rooms/${roomId}/messages/${msg.id}`, { method: "DELETE" });
    removeMessageNode(msg.id);
    onToast("Message supprimé.", "success");
  } catch (error) {
    onToast(error.message || "Suppression impossible.", "error");
  }
}

/* ============================================================
   Construction du DOM des messages
   ============================================================ */

/**
 * Normalise un message brut de l'API/WS.
 * Métadonnées serveur : `id` (UUID), `seq` (entier ordonnable), `author_id`.
 * On accepte aussi `roomId`, `sender_id`, `sender`, `username`… (défensif).
 */
function newMessageFromRaw(raw) {
  if (!raw || typeof raw !== "object") {
    return null;
  }
  const id = raw.id != null ? raw.id : raw.seq;
  const roomId = raw.room_id != null ? raw.room_id : raw.roomId;
  const senderId =
    raw.author_id != null
      ? raw.author_id
      : raw.sender_id != null
        ? raw.sender_id
        : raw.sender;
  const senderName =
    raw.sender_username != null
      ? raw.sender_username
      : raw.username != null
        ? raw.username
        : membersById.get(String(senderId)) || "";

  return {
    id: id != null ? id : null,
    room_id: roomId != null ? roomId : currentRoomId,
    sender_id: senderId != null ? senderId : null,
    sender: senderName,
    nonce: raw.nonce || null,
    ciphertext: raw.ciphertext || null,
    // Type de contenu : "text" par défaut, "image" pour une pièce jointe.
    kind: raw.kind != null ? raw.kind : "text",
    mime: raw.mime != null ? raw.mime : null,
    created_at: raw.created_at || raw.createdAt || null,
  };
}

/**
 * Construit le noeud DOM d'un message (avatar, pseudo, heure, texte —
 * déchiffré si possible). Ne l'insère PAS dans le fil.
 * @param {object} msg Message normalisé.
 * @param {CryptoKey|null} roomKey Clé de salon (éventuellement absente).
 * @returns {Promise<HTMLElement>}
 */
async function buildMessageNode(msg, roomKey) {
  const user = getCurrentUser();
  const isOwn = user && msg.sender_id != null && String(msg.sender_id) === String(user.id);

  const item = document.createElement("div");
  item.className = "message";
  item.dataset.messageId = String(msg.id != null ? msg.id : "");
  item.dataset.seq = String(seqOf(msg));
  item.dataset.authorId = msg.sender_id != null ? String(msg.sender_id) : "";
  if (msg.created_at) {
    item.dataset.day = ui.dayKeyOf(msg.created_at);
    item.dataset.dayLabel = ui.dayLabelOf(msg.created_at);
  }

  // Avatar teinté par pseudo (masqué visuellement pour les messages groupés).
  const avatar = document.createElement("span");
  avatar.className = "avatar avatar--message " + ui.avatarHueClass(msg.sender || "?");
  avatar.textContent = (msg.sender || "?").charAt(0).toUpperCase();
  item.appendChild(avatar);

  // Colonne contenu : en-tête (pseudo + heure) puis texte.
  const body = document.createElement("div");
  body.className = "message-body";

  const header = document.createElement("div");
  header.className = "message-header";
  const sender = document.createElement("span");
  sender.className = "message-sender";
  sender.textContent = msg.sender || "Inconnu";
  header.appendChild(sender);
  if (msg.created_at) {
    const timeEl = document.createElement("span");
    timeEl.className = "message-time";
    timeEl.textContent = ui.formatTime(msg.created_at);
    header.appendChild(timeEl);
  }
  body.appendChild(header);

  // Contenu : texte ou image déchiffrés (jamais injecté via innerHTML).
  if (msg.kind === "image") {
    await appendImageContent(item, body, msg, roomKey);
  } else {
    await appendEncryptedText(item, body, msg, roomKey);
  }
  item.appendChild(body);

  // Menu « Supprimer » : auteur uniquement, visible au survol.
  if (isOwn && msg.id != null && String(msg.id).indexOf("local-") !== 0) {
    const roomIdAtBuild = msg.room_id || currentRoomId;
    const actionsBtn = document.createElement("button");
    actionsBtn.type = "button";
    actionsBtn.className = "icon-btn message-actions-btn";
    actionsBtn.setAttribute("aria-label", "Options du message");
    actionsBtn.appendChild(ui.icon("dots"));
    actionsBtn.addEventListener("click", (event) => {
      event.stopPropagation();
      ui.openMenu(actionsBtn, [
        {
          label: "Supprimer",
          danger: true,
          onClick: () => confirmDeleteMessage(msg, roomIdAtBuild),
        },
      ]);
    });
    item.appendChild(actionsBtn);
  }

  return item;
}

/**
 * Déchiffre le texte d'un message et l'ajoute à la colonne de contenu.
 * En cas de clé manquante ou d'échec AEAD, marque le message « verrouillé ».
 * @param {HTMLElement} item Noeud `.message`.
 * @param {HTMLElement} body Colonne `.message-body`.
 * @param {object} msg Message normalisé.
 * @param {CryptoKey|null} roomKey Clé de salon.
 */
async function appendEncryptedText(item, body, msg, roomKey) {
  const textEl = document.createElement("div");
  textEl.className = "message-text";
  let decryptedText = null;
  if (msg.nonce && msg.ciphertext && roomKey) {
    try {
      decryptedText = await crypto.decryptMessage(roomKey, msg.nonce, msg.ciphertext);
    } catch {
      decryptedText = null;
    }
  }
  if (decryptedText !== null) {
    textEl.textContent = decryptedText;
  } else {
    item.classList.add("message--locked");
    textEl.textContent =
      "[Message chiffré — clé de salon non disponible sur ce navigateur]";
  }
  body.appendChild(textEl);
}

/**
 * Déchiffre une image et l'affiche via une balise `<img>` dont la source est
 * posée par propriété (`src`), jamais par `innerHTML`. Le MIME est celui
 * annoncé par le message, sinon deviné depuis les premiers octets, sinon PNG.
 * Repli « verrouillé » si la clé de salon manque ou si le déchiffrement échoue.
 * @param {HTMLElement} item Noeud `.message`.
 * @param {HTMLElement} body Colonne `.message-body`.
 * @param {object} msg Message normalisé (kind === "image").
 * @param {CryptoKey|null} roomKey Clé de salon.
 */
async function appendImageContent(item, body, msg, roomKey) {
  let bytes = null;
  if (msg.nonce && msg.ciphertext && roomKey) {
    try {
      bytes = await crypto.decryptBytes(roomKey, msg.nonce, msg.ciphertext);
    } catch {
      bytes = null;
    }
  }
  if (!bytes) {
    item.classList.add("message--locked");
    const locked = document.createElement("div");
    locked.className = "message-text";
    locked.textContent = "[Image chiffrée — clé de salon non disponible]";
    body.appendChild(locked);
    return;
  }

  // MIME de l'annonce reconnu, sinon deviné depuis les octets, sinon PNG.
  const announced = msg.mime && /^image\//.test(msg.mime) ? msg.mime : null;
  const mime = announced || sniffImageMime(bytes) || "image/png";
  const img = document.createElement("img");
  img.className = "message-image";
  img.src = `data:${mime};base64,${crypto.bytesToBase64(bytes)}`;
  img.alt = "Image partagée";
  img.loading = "lazy";
  body.appendChild(img);
}

/**
 * Devine un MIME d'image courant depuis la signature binaire (magic bytes).
 * Utilisé uniquement quand le serveur n'a pas fourni de `mime`.
 * @param {Uint8Array} bytes
 * @returns {string|null} ex. "image/png", ou null si inconnu.
 */
function sniffImageMime(bytes) {
  if (!bytes || bytes.length < 4) {
    return null;
  }
  // PNG : 89 50 4E 47
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
    return "image/png";
  }
  // JPEG : FF D8
  if (bytes[0] === 0xff && bytes[1] === 0xd8) {
    return "image/jpeg";
  }
  // GIF : 47 49 46 38 ("GIF8")
  if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) {
    return "image/gif";
  }
  // WEBP : "RIFF" .... "WEBP"
  if (
    bytes.length >= 12 &&
    bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
    bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50
  ) {
    return "image/webp";
  }
  return null;
}

/**
 * Ajoute un message en fin de fil, avec regroupement et séparation de date
 * calculés par rapport au dernier message affiché.
 * @param {object} msg Message normalisé.
 * @param {CryptoKey|null} roomKey Clé de salon.
 */
async function appendMessage(msg, roomKey) {
  const node = await buildMessageNode(msg, roomKey);
  const prev = lastMsgEl;

  const isGrouped =
    prev &&
    prev.dataset.authorId &&
    msg.sender_id != null &&
    prev.dataset.authorId === String(msg.sender_id);
  node.classList.add(isGrouped ? "message--grouped" : "message--group-start");

  const prevDay = prev && prev.dataset.day;
  const nodeDay = node.dataset.day;
  if (prev && prevDay && nodeDay && prevDay !== nodeDay) {
    const separator = document.createElement("div");
    separator.className = "date-separator";
    const label = document.createElement("span");
    label.textContent = node.dataset.dayLabel || nodeDay;
    separator.appendChild(label);
    messagesEl.appendChild(separator);
  }

  messagesEl.appendChild(node);
  lastMsgEl = node;
}

/**
 * Recalcule le groupement et les séparateurs de dates sur TOUT le fil.
 * Utilisé après une insertion en tête (pagination) ou une suppression, où la
 * frontière de groupe peut changer.
 */
function normalizeGrouping() {
  for (const sep of messagesEl.querySelectorAll(".date-separator")) {
    sep.remove();
  }
  for (const m of messagesEl.querySelectorAll(".message")) {
    m.classList.remove("message--grouped", "message--group-start");
  }

  let prevAuthor = undefined;
  let prevDay = undefined;
  for (const msgNode of messagesEl.querySelectorAll(".message")) {
    const author = msgNode.dataset.authorId || null;
    const day = msgNode.dataset.day || null;

    if (prevAuthor !== undefined && author !== null && author === prevAuthor) {
      msgNode.classList.add("message--grouped");
    } else {
      msgNode.classList.add("message--group-start");
    }

    // Séparateur avant le premier message du jour suivant.
    if (prevDay !== undefined && day !== null && day !== prevDay) {
      const separator = document.createElement("div");
      separator.className = "date-separator";
      const label = document.createElement("span");
      label.textContent = msgNode.dataset.dayLabel || day;
      separator.appendChild(label);
      msgNode.parentNode.insertBefore(separator, msgNode);
    }

    prevAuthor = author;
    prevDay = day;
  }
}

/** Défilement vers le bas du fil. */
function scrollToBottom() {
  messagesEl.scrollTop = messagesEl.scrollHeight;
}