/**
 * Messages : chiffrement local, envoi, historique, réception temps réel.
 *
 * Le texte en clair n'existe que dans ce fichier et dans la mémoire du
 * navigateur : il n'est jamais mis en cache par le serveur.
 */

import { api } from "../api.js";
import { decryptMessage, encryptMessage } from "../crypto.js";
import { clear, element, formatTime } from "../dom.js";
import { state } from "../state.js";

const listNode = () => document.getElementById("message-list");
const seen = new Set();
let socket = null;
let pollTimer = null;

function messageNode(envelope, plaintext) {
  const mine = envelope.sender_id === state.user?.id;
  const classes = ["message", mine ? "mine" : ""];
  if (plaintext === null) classes.push("unreadable");
  return element(
    "li",
    { class: classes.filter(Boolean).join(" ") },
    element("span", {
      class: "meta",
      text: `${mine ? "vous" : "membre"} · ${formatTime(envelope.sent_at)}`,
    }),
    element("span", {
      class: "body",
      text: plaintext === null ? "⟨message illisible : clé absente⟩" : plaintext,
    }),
  );
}

function append(envelope) {
  if (seen.has(envelope.id)) return;
  seen.add(envelope.id);
  const node = listNode();
  const atBottom = node.scrollHeight - node.scrollTop - node.clientHeight < 60;
  if (state.channelKey) {
    decryptMessage(state.channelKey, envelope).then((plaintext) => {
      node.append(messageNode(envelope, plaintext));
      if (atBottom) node.scrollTop = node.scrollHeight;
    });
  } else {
    node.append(messageNode(envelope, null));
  }
  if (envelope.seq > state.latestSeq) state.latestSeq = envelope.seq;
}

export async function renderHistory() {
  const node = clear(listNode());
  seen.clear();
  const page = await api.history(state.currentChannelId);
  state.latestSeq = page.latest_seq;
  for (const envelope of page.messages) {
    if (state.channelKey) {
      const plaintext = await decryptMessage(state.channelKey, envelope);
      node.append(messageNode(envelope, plaintext));
    } else {
      node.append(messageNode(envelope, null));
    }
    seen.add(envelope.id);
  }
  node.scrollTop = node.scrollHeight;
}

export async function send(text) {
  if (!state.channelKey) throw new Error("Cle de canal indisponible.");
  const sealed = await encryptMessage(state.channelKey, text);
  const envelope = await api.sendMessage(state.currentChannelId, {
    ciphertext: sealed.ciphertext,
    iv: sealed.iv,
    key_version: 1,
  });
  append(envelope);
  return envelope;
}

/* ---------- temps réel ---------- */

function socketUrl(channelId) {
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${window.location.host}/ws/channels/${encodeURIComponent(channelId)}`;
}

/** WebSocket en temps réel, avec repli automatique sur le polling court. */
export function connect(channelId) {
  disconnect();
  if (!channelId) return;
  socket = new WebSocket(socketUrl(channelId));
  socket.addEventListener("open", () => setPresence(true));
  socket.addEventListener("message", (event) => {
    const frame = JSON.parse(event.data);
    if (frame.type === "message") append(frame.message);
  });
  socket.addEventListener("close", () => {
    setPresence(false);
    startPolling();
  });
  socket.addEventListener("error", () => socket?.close());
}

function setPresence(online) {
  const badge = document.getElementById("presence");
  badge.hidden = !online;
}

function startPolling() {
  stopPolling();
  pollTimer = window.setInterval(async () => {
    if (!state.currentChannelId) return;
    try {
      const page = await api.poll(state.currentChannelId, state.latestSeq);
      for (const envelope of page.messages) append(envelope);
    } catch {
      stopPolling();
    }
  }, 3000);
}

function stopPolling() {
  if (pollTimer !== null) window.clearInterval(pollTimer);
  pollTimer = null;
}

export function disconnect() {
  stopPolling();
  if (socket) {
    socket.close();
    socket = null;
  }
}

export function bindComposer(onError) {
  const form = document.getElementById("composer");
  const input = document.getElementById("composer-input");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    try {
      await send(text);
    } catch (error) {
      input.value = text;
      onError(error);
    }
  });
}
