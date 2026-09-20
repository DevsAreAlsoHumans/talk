/**
 * chat.js — Fil de messages : historique, envoi chiffré, affichage déchiffré,
 * défilement, polling de secours.
 *
 * Aucun `innerHTML` n'est utilisé : tout le contenu utilisateur (messages,
 * pseudos, salons) est injecté via `textContent` (anti-XSS).
 */

import { api } from "./api.js";
import * as crypto from "./crypto.js";
import { getCurrentUser } from "./auth.js";

/**
 * Limite client en octets UTF-8 : le ciphertext AES-GCM (+ tag AEAD) puis sa
 * version base64 doivent rester sous la limite serveur (~4096 octets stockés).
 * 3000 octets → ~3016 octets chiffrés → ~4022 caractères base64 : marge sûre.
 */
const MAX_PLAINTEXT_BYTES = 3000;

/** Callback de notification (posé par main.js). */
let onToast = () => {};

/** Identifiant du salon actuellement ouvert (null si aucun). */
let currentRoomId = null;

/** @returns {string|null} identifiant du salon ouvert (pour le polling WS). */
export function getCurrentRoomId() {
  return currentRoomId;
}

/** Dernier identifiant de message reçu (pour le polling `?after=`). */
let lastMessageId = 0;

/** Déduplication (anti-doublon entre WS, polling et envoi local). */
const seenIds = new Set();

/** Pseudo des membres : senderId → username (fourni à l'ouverture du salon). */
let membersById = new Map();

/** Compteur local pour les messages sans id retourné par le serveur. */
let localCounter = 0;

/** Promise de chargement en cours (évite les lancements concurrents). */
let historyLoading = null;

/**
 * Branche la zone de saisie.
 * @param {{onToast: (message: string) => void}} callbacks
 */
export function initChat({ onToast: toastCallback }) {
  onToast = toastCallback;

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
      onToast(error.message || "Envoi impossible.");
    }
  });
}

/** Ouvre un salon : réinitialise l'état et recharge l'historique. */
export async function openRoom(roomId, members) {
  currentRoomId = roomId;
  lastMessageId = 0;
  seenIds.clear();
  membersById = new Map((members || []).map((m) => [String(m.id), m.username]));
  renderHeaderInfo();

  const messagesEl = document.getElementById("messages");
  messagesEl.textContent = ""; // suppression totale : jamais innerHTML
  await loadHistory();
}

/** Recharge intégralement l'historique (utilisé quand la clé arrive). */
export async function reloadHistory() {
  if (!currentRoomId) {
    return;
  }
  lastMessageId = 0;
  seenIds.clear();
  const messagesEl = document.getElementById("messages");
  messagesEl.textContent = "";
  await loadHistory();
}

/** Requête d'historique (protégée contre les lancements concurrents). */
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
  const roomKey = crypto.getRoomKey(roomId);
  const messagesEl = document.getElementById("messages");

  let messages;
  try {
    messages = await api(`/api/rooms/${roomId}/messages`); // sans `after` : tout l'historique
  } catch (error) {
    appendSystemMessage("Historique indisponible : " + error.message);
    return;
  }

  if (!Array.isArray(messages)) {
    appendSystemMessage("Réponse serveur inattendue pour l'historique.");
    return;
  }

  // Tri croissant par identifiant (séquentiel) pour un affichage chronologique,
  // quel que soit l'ordre renvoyé par le serveur.
  const ordered = [...messages].sort(
    (a, b) => Number(a.id != null ? a.id : a.seq) - Number(b.id != null ? b.id : b.seq),
  );

  for (const raw of ordered) {
    const msg = newMessageFromRaw(raw);
    if (msg && !seenIds.has(msg.id)) {
      await appendMessage(msg, roomKey);
      seenIds.add(msg.id);
      lastMessageId = Math.max(lastMessageId, Number(msg.id) || 0);
    }
  }

  if (ordered.length === 0) {
    appendSystemMessage("Aucun message pour l'instant. Écrivez le premier !");
  }

  scrollToBottom();
}

/**
 * Applique un nouveau message reçu en temps réel (WebSocket).
 * Uniquement si le salon concerné est celui qui est ouvert.
 */
export async function handleNewMessage(payload) {
  const msg = newMessageFromRaw(payload);
  if (!msg) {
    return;
  }
  if (String(msg.room_id) !== String(currentRoomId)) {
    return; // message d'un autre salon : ignoré ici (pas de compteur non lu)
  }
  if (seenIds.has(msg.id)) {
    return; // déjà affiché (polling / envoi local)
  }

  const roomKey = crypto.getRoomKey(currentRoomId);
  await appendMessage(msg, roomKey);
  seenIds.add(msg.id);
  lastMessageId = Math.max(lastMessageId, Number(msg.id) || 0);
  scrollToBottom();
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

  let messages;
  try {
    messages = await api(
      `/api/rooms/${currentRoomId}/messages?after=${lastMessageId}`,
    );
  } catch {
    return; // polling silencieux : on réessaiera au prochain tick
  }

  if (!Array.isArray(messages)) {
    return;
  }

  const roomKey = crypto.getRoomKey(currentRoomId);
  const ordered = [...messages].sort(
    (a, b) => Number(a.id != null ? a.id : a.seq) - Number(b.id != null ? b.id : b.seq),
  );
  for (const raw of ordered) {
    const msg = newMessageFromRaw(raw);
    if (msg && !seenIds.has(msg.id)) {
      await appendMessage(msg, roomKey);
      seenIds.add(msg.id);
      lastMessageId = Math.max(lastMessageId, Number(msg.id) || 0);
    }
  }
  scrollToBottom();
}

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

  const response = await api(`/api/rooms/${currentRoomId}/messages`, {
    method: "POST",
    body: { nonce, ciphertext },
  });

  // Le nouveau message n'est PAS re-broadcasté à l'émetteur : on l'affiche
  // localement après le 201.
  let msg;
  if (response && typeof response === "object" && response.id != null) {
    msg = newMessageFromRaw(response);
  } else {
    // Réponse sans métadonnées : on construit un message local.
    localCounter += 1;
    msg = {
      id: "local-" + localCounter,
      room_id: currentRoomId,
      sender_id: user ? user.id : null,
      sender: user ? user.username : "",
      nonce,
      ciphertext,
      created_at: new Date().toISOString(),
      encrypted: true,
    };
  }

  // Course possible : le serveur peut broadcaster `new_message` à l'émetteur
  // AVANT que la réponse du POST ne soit traitée → on ne duplique pas l'affichage.
  if (!seenIds.has(msg.id)) {
    await appendMessage(msg, roomKey);
    seenIds.add(msg.id);
  }
  scrollToBottom();
  return true;
}

/** Renseigne le nom du salon et le nombre de membres dans l'en-tête. */
function renderHeaderInfo() {
  // Le nom du salon est posé par rooms.js ; ici on met à jour le compteur.
  const countEl = document.getElementById("room-members-count");
  const count = membersById.size;
  countEl.textContent = count + " membre" + (count > 1 ? "s" : "");
}

/**
 * Normalise un message brut de l'API/WS.
 * Le contrat n'impose pas le nom exact des champs de métadonnées : on accepte
 * `id` / `seq`, `sender_id` / `sender`, `username` / `sender_username`, etc.
 */
function newMessageFromRaw(raw) {
  if (!raw || typeof raw !== "object") {
    return null;
  }
  const id = raw.id != null ? raw.id : raw.seq;
  const roomId = raw.room_id != null ? raw.room_id : raw.roomId;
  const senderId = raw.sender_id != null ? raw.sender_id : raw.sender;
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
    created_at: raw.created_at || raw.createdAt || null,
  };
}

/**
 * Ajoute un message au fil (déchiffré si possible).
 * @param {object} msg Message normalisé.
 * @param {CryptoKey|null} roomKey Clé de salon (éventuellement absente).
 */
async function appendMessage(msg, roomKey) {
  const user = getCurrentUser();
  const isOwn = user && msg.sender_id != null && String(msg.sender_id) === String(user.id);

  const messagesEl = document.getElementById("messages");
  const item = document.createElement("div");
  item.className = "message" + (isOwn ? " message--own" : "");

  // Métadonnées : pseudo + heure.
  const meta = document.createElement("div");
  meta.className = "message-meta";

  const senderEl = document.createElement("span");
  senderEl.className = "message-sender";
  senderEl.textContent = isOwn ? "Vous" : msg.sender || "Inconnu";
  meta.appendChild(senderEl);

  if (msg.created_at) {
    const timeEl = document.createElement("span");
    timeEl.className = "message-time";
    timeEl.textContent = formatTime(msg.created_at);
    meta.appendChild(timeEl);
  }

  // Contenu déchiffré (jamais injecté via innerHTML).
  const bubble = document.createElement("div");
  bubble.className = "message-bubble";

  let decryptedText = null;
  if (msg.nonce && msg.ciphertext && roomKey) {
    try {
      decryptedText = await crypto.decryptMessage(roomKey, msg.nonce, msg.ciphertext);
    } catch {
      decryptedText = null;
    }
  }

  const bodyEl = document.createElement("span");
  if (decryptedText !== null) {
    bodyEl.textContent = decryptedText;
  } else {
    bodyEl.textContent =
      "[Message chiffré — clé de salon non disponible sur ce navigateur]";
    item.classList.add("message--locked");
  }
  bubble.appendChild(bodyEl);

  item.appendChild(meta);
  item.appendChild(bubble);
  messagesEl.appendChild(item);
}

/** Ajoute un message système (informations non utilisateur). */
function appendSystemMessage(text) {
  const messagesEl = document.getElementById("messages");
  const item = document.createElement("div");
  item.className = "message message--locked";
  const bubble = document.createElement("div");
  bubble.className = "message-bubble";
  bubble.textContent = text;
  item.appendChild(bubble);
  messagesEl.appendChild(item);
}

/** « Heure d'émission » lisible (ex. : 14:05). */
function formatTime(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return date.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
}

/** Défilement vers le bas du fil. */
function scrollToBottom() {
  const messagesEl = document.getElementById("messages");
  messagesEl.scrollTop = messagesEl.scrollHeight;
}