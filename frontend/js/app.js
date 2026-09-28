/* Orchestration : état applicatif, flux login → identité → salon → chat.
   Gestion du panneau des membres (présence), invitation niveau salon, mode
   sombre, indicateurs d'écriture, réactions chiffrées, recherche locale et
   export déchiffré. */

import * as cryptoLib from "./crypto.js";
import { api } from "./api.js";
import { ui } from "./ui.js";
import { ChatSocket } from "./ws.js";

const EMOJIS = ["👍", "❤️", "😂", "🔥", "🎉", "👀"];
const TYPING_TTL_MS = 3000;
const TYPING_THROTTLE_MS = 2000;

const state = {
  me: null,
  identity: null,
  rooms: [],
  current: null,
  members: [],
  online: new Set(),
  friends: [],
  requests: [],
  typing: new Map(),
  lastTypingSent: 0,
  // reactions getters vivent dans state.current.channel via state.reactions
  reactions: new Map(), // channelId -> Map<n, Map<user, emoji>>
};

function setAuthError(err) {
  ui.authError(err && err.message ? err.message : String(err));
}

function init() {
  ui.el("auth-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    doAuth("register");
  });
  ui.el("btn-login").addEventListener("click", () => doAuth("login"));
  ui.el("btn-logout").addEventListener("click", doLogout);
  ui.el("btn-new-room").addEventListener("click", newRoom);
  ui.el("btn-new-channel").addEventListener("click", newChannel);
  ui.el("invite-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    invite();
  });
  ui.el("composer").addEventListener("submit", (ev) => {
    ev.preventDefault();
    send();
  });
  ui.el("composer-input").addEventListener("input", notifyTyping);
  ui.el("btn-theme").addEventListener("click", ui.toggleTheme);
  ui.el("btn-theme-auth").addEventListener("click", ui.toggleTheme);
  ui.el("friend-add").addEventListener("submit", (ev) => {
    ev.preventDefault();
    addFriend();
  });
  ui.el("search-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    search();
  });
  ui.el("btn-export").addEventListener("click", exportChat);
  ui.el("btn-search").addEventListener("click", () => {
    ui.showSearch();
    ui.el("search-input").focus();
  });
  ui.el("btn-leave").addEventListener("click", leaveRoom);
  ui.el("btn-transfer").addEventListener("click", transferOwner);
  ui.el("btn-delete-rm").addEventListener("click", deleteRoomByOwner);
  // Rendu des réactions par délégation sur la liste des messages.
  ui.el("messages").addEventListener("click", onMessagesClick);

  api
    .me()
    .then((me) => {
      state.me = me;
      return enterApp();
    })
    .catch(() => ui.setAuth(true));
}

async function doAuth(mode) {
  const username = ui.el("auth-username").value.trim();
  const password = ui.el("auth-password").value;
  ui.authError("");
  try {
    state.me =
      mode === "register" ? await api.register(username, password) : await api.login(username, password);
    await enterApp();
  } catch (err) {
    setAuthError(err);
  }
}

async function enterApp() {
  ui.setApp(true);
  ui.setMe(state.me.username);
  state.identity = await cryptoLib.ensureIdentity(state.me.username);
  await api.putKey(state.identity.publicRaw);
  refreshFriends();
  await refreshRooms();
}

async function refreshFriends() {
  if (!state.me) return;
  try {
    const [friends, requests] = await Promise.all([api.friends(), api.friendRequests()]);
    state.friends = friends;
    state.requests = requests;
    ui.renderFriends(friends, requests, state.me.username, acceptFriend, dmFriend);
  } catch (err) {
    ui.status(err.message);
  }
}

async function addFriend() {
  const input = ui.el("friend-username");
  const username = input.value.trim();
  if (!username) return;
  input.value = "";
  try {
    await api.sendFriendRequest(username);
    ui.status("demande d'ami envoyée à @" + username);
    refreshFriends();
  } catch (err) {
    ui.status(err.message);
  }
}

async function acceptFriend(username) {
  try {
    await api.acceptFriend(username);
    ui.status("@" + username + " est maintenant un ami");
    refreshFriends();
  } catch (err) {
    ui.status(err.message);
  }
}

async function dmFriend(username) {
  ui.status("création du message privé chiffré…");
  try {
    const room = await api.createDirect(username);
    await ensureDirectKey(room.id);
    await refreshRooms();
    selectRoom(room.id);
  } catch (err) {
    ui.status(err.message);
  }
}

// Message privé fraîchement créé : personne n'a encore de clé de salon.
// Le créateur (propriétaire) en génère une et l'enveloppe pour chaque membre.
async function ensureDirectKey(roomId) {
  const mine = await api.myKey(roomId).catch(() => null);
  if (mine) return;
  const members = await api.members(roomId);
  const keypair = await cryptoLib.generateRoomKey();
  for (const m of members.members) {
    if (!m.public_key) continue;
    const blob = await cryptoLib.wrapRoomKey(state.identity, m.public_key, roomId, keypair.raw);
    await api.shareKey(roomId, m.username, blob);
  }
}

async function refreshRooms() {
  state.rooms = await api.rooms();
  const activeId = state.current ? state.current.id : null;
  ui.renderRooms(state.rooms, activeId, (id) => selectRoom(id));
  if (!activeId && state.rooms.length) selectRoom(state.rooms[0].id);
}

function selectRoom(roomId) {
  closeCurrent();
  ui.clearMessages();
  ui.roomTitle("");
  ui.channelTitle("");
  ui.status("");
  ui.hideSearch();
  ui.showRoomActions(false, false);
  if (!roomId) return;
  const room = state.rooms.find((r) => r.id === roomId);
  ui.roomTitle(room ? room.name : "");
  ui.status("chargement de la clé de salon...");
  loadRoom(roomId).catch((err) => ui.status(err.message));
}

async function loadRoom(roomId) {
  const [members, myKey, channels] = await Promise.all([
    api.members(roomId),
    api.myKey(roomId).catch(() => null),
    api.channels(roomId),
  ]);
  ui.showInvite(members.owner_id === state.me.username);
  ui.showRoomActions(true, members.owner_id === state.me.username);
  state.members = members.members;
  state.online = new Set(members.members.filter((m) => m.online).map((m) => m.username));
  ui.renderMembers(memberSnapshot(), members.owner_id);
  if (!myKey) {
    ui.status("vous n'avez pas encore la clé de ce salon");
    return;
  }
  const owner = members.members.find((m) => m.username === members.owner_id);
  if (!owner || !owner.public_key) {
    ui.status("clé publique du créateur indisponible");
    return;
  }
  const unwrapped = await cryptoLib.unwrapRoomKey(
    state.identity,
    owner.public_key,
    roomId,
    myKey,
  );
  state.current = {
    id: roomId,
    raw: unwrapped.raw,
    key: unwrapped.key,
    channels,
    channel: null,
    ownerId: members.owner_id,
    lastN: 0,
    socket: null,
  };
  const socket = new ChatSocket(
    roomId,
    onMessage,
    onPresence,
    (s) => onSocketState(s),
    onTyping,
    onReaction,
  );
  state.current.socket = socket;
  socket.connect();
  ui.renderChannels(channels, null, (cid) => selectChannel(cid), ownerCanDelete(), (cid) => deleteChannel(cid));
  if (channels.length) selectChannel(channels[0].id);
}

function ownerCanDelete() {
  return !!state.current && state.current.ownerId === state.me.username;
}

function onSocketState(status) {
  ui.status(status);
  if (status === "connecté") refreshMembers(); // resynchronise le statut en ligne
}

async function refreshMembers() {
  if (!state.current) return;
  try {
    const members = await api.members(state.current.id);
    state.members = members.members;
    state.online = new Set(members.members.filter((m) => m.online).map((m) => m.username));
    ui.renderMembers(memberSnapshot(), members.owner_id);
  } catch {
    // page fermée entre-temps
  }
}

// Fusionne l'instantané serveur avec le statut en ligne temps réel.
function memberSnapshot() {
  return state.members.map((m) => ({ ...m, online: state.online.has(m.username) }));
}

function selectChannel(channelId, anchor) {
  const room = state.current;
  if (!room) return;
  const channel = room.channels.find((c) => c.id === channelId);
  if (!channel) return;
  room.channel = channel;
  room.lastN = 0;
  ui.channelTitle(channel.name);
  ui.renderChannels(room.channels, channelId, (cid) => selectChannel(cid), ownerCanDelete(), (cid) => deleteChannel(cid));
  ui.clearMessages();
  loadChannelHistory(channel, anchor);
}

async function loadChannelHistory(channel, anchor) {
  const room = state.current;
  if (!room) return;
  const chId = channel.id;
  const after = anchor != null ? Math.max(0, anchor - 1) : 0;
  try {
    const history = await api.messages(room.id, channel.id, after);
    if (!state.current || state.current.channel.id !== chId) return; // canal changé pendant le fetch
    for (const m of history) {
      const text = await cryptoLib.decryptMessage(room.key, room.id, m.sender, m.payload);
      if (!state.current || state.current.channel.id !== chId) return;
      if (text === null) {
        ui.renderSystem("message illisible (clé de salon différente)");
        continue;
      }
      ui.renderMessage(m.sender, text, m.sender === state.me.username, m.ts, m.n);
      room.lastN = Math.max(room.lastN, m.n);
    }
    if (anchor != null) {
      const wrap = ui.el("messages").querySelector('[data-n="' + anchor + '"]');
      if (wrap) {
        wrap.classList.add("flash");
        wrap.scrollIntoView({ block: "center" });
      }
    }
    await renderChannelReactions(channel.id);
  } catch (err) {
    ui.status(err.message);
  }
}

async function renderChannelReactions(channelId) {
  const room = state.current;
  if (!room) return;
  let rows;
  try {
    rows = await api.reactions(room.id, channelId);
  } catch {
    return;
  }
  const byN = state.reactions.get(channelId) || new Map();
  for (const r of rows) {
    const emoji = await cryptoLib.decryptMessage(room.key, room.id, r.sender, r.payload);
    let byUser = byN.get(r.n);
    if (!byUser) {
      byUser = new Map();
      byN.set(r.n, byUser);
    }
    if (emoji === null) byUser.delete(r.sender);
    else byUser.set(r.sender, emoji);
  }
  state.reactions.set(channelId, byN);
  for (const n of byN.keys()) renderReactionRow(channelId, n);
}

function onMessage(msg) {
  if (!state.current || msg.room_id !== state.current.id) return;
  if (!state.current.channel || msg.channel_id !== state.current.channel.id) return;
  if (msg.n != null && msg.n <= state.current.lastN) return;
  cryptoLib
    .decryptMessage(state.current.key, state.current.id, msg.from, msg.payload)
    .then((text) => {
      if (text === null) return;
      state.current.lastN = Math.max(state.current.lastN, msg.n || 0);
      ui.renderMessage(msg.from, text, msg.from === state.me.username, msg.ts, msg.n);
    });
}

/* Panneau membres : la présence n'affiche plus « a rejoint / a quitté » ;
   elle alimente seulement le statut en ligne. L'invitation, elle, affiche
   une notif unique au moment où elle est émise. */
function onPresence(msg) {
  const room = state.current;
  if (msg.event === "invited") {
    ui.renderSystem("@" + msg.user + " a été invité au salon");
    refreshMembers();
  } else if (msg.event === "member_left") {
    // Un membre a quitté définitivement : plus dans le panneau.
    refreshMembers();
  } else if (msg.event === "ownership_changed") {
    if (room) room.ownerId = msg.owner;
    const isOwner = msg.owner === state.me.username;
    ui.showInvite(isOwner);
    ui.showRoomActions(true, isOwner);
    ui.renderMembers(memberSnapshot(), room && room.ownerId);
  } else if (msg.event === "join") {
    state.online.add(msg.user);
    ui.renderMembers(memberSnapshot(), room && room.ownerId);
  } else if (msg.event === "leave") {
    state.online.delete(msg.user);
    ui.renderMembers(memberSnapshot(), room && room.ownerId);
  }
}

/* Indicateurs d'écriture (transitoires, jamais persistés). */
function onTyping(msg) {
  if (!state.current || msg.user === state.me.username) return;
  state.typing.set(msg.user, Date.now());
  renderTypingHint();
  setTimeout(renderTypingHint, TYPING_TTL_MS + 200);
}

function renderTypingHint() {
  const now = Date.now();
  const active = [];
  for (const [user, ts] of state.typing) {
    if (now - ts > TYPING_TTL_MS) state.typing.delete(user);
    else active.push(user);
  }
  ui.renderTyping(active);
}

function notifyTyping() {
  const room = state.current;
  if (!room || !room.socket) return;
  const now = Date.now();
  if (now - state.lastTypingSent < TYPING_THROTTLE_MS) return;
  state.lastTypingSent = now;
  room.socket.sendTyping();
}

/* Réactions chiffrées : l'emoji voyage en blob AES-GCM, agrégé côté client. */
function onMessagesClick(ev) {
  const btn = ev.target.closest("button.reaction, button.reaction-add");
  if (!btn) return;
  const room = state.current;
  if (!room || !room.channel) return;
  if (btn.classList.contains("reaction-add")) {
    const wrap = btn.closest(".msg");
    const n = Number(wrap && wrap.getAttribute("data-n"));
    if (!wrap || Number.isNaN(n)) return;
    const row = wrap.querySelector(".reactions");
    for (const emoji of EMOJIS) {
      const p = document.createElement("button");
      p.type = "button";
      p.className = "reaction mine";
      p.setAttribute("data-emoji", emoji);
      p.setAttribute("data-n", String(n));
      p.textContent = emoji;
      row.insertBefore(p, btn);
    }
    return;
  }
  const n = Number(btn.getAttribute("data-n"));
  const emoji = btn.getAttribute("data-emoji");
  if (Number.isNaN(n)) return;
  const mine = reactionFor(room.channel.id, n, state.me.username);
  if (mine === emoji) {
    api
      .react(room.id, room.channel.id, n, null)
      .catch((err) => ui.status(err.message));
  } else {
    cryptoLib
      .encryptMessage(room.key, room.id, state.me.username, emoji)
      .then((blobStr) => api.react(room.id, room.channel.id, n, JSON.parse(blobStr)))
      .catch((err) => ui.status(err.message));
  }
}

function onReaction(msg) {
  if (!state.current || msg.channel_id !== state.current.channel.id) return;
  if (!state.current.channel) return;
  const target = state.current.channel;
  updateReactionFromEvent(target.id, msg.n, msg.from, msg.payload);
}

function updateReactionFromEvent(channelId, n, user, payload) {
  const apply = async () => {
    const emoji =
      payload == null
        ? null
        : await cryptoLib.decryptMessage(state.current.key, state.current.id, user, payload);
    let byN = state.reactions.get(channelId);
    if (!byN) {
      byN = new Map();
      state.reactions.set(channelId, byN);
    }
    let byUser = byN.get(n);
    if (!byUser) {
      byUser = new Map();
      byN.set(n, byUser);
    }
    if (emoji === null) byUser.delete(user);
    else byUser.set(user, emoji);
    renderReactionRow(channelId, n);
  };
  apply();
}

function reactionFor(channelId, n, user) {
  const byN = state.reactions.get(channelId);
  if (!byN) return null;
  const byUser = byN.get(n);
  return byUser ? byUser.get(user) || null : null;
}

function renderReactionRow(channelId, n) {
  const byN = state.reactions.get(channelId);
  const counts = new Map();
  const byUser = byN && byN.get(n);
  if (byUser) {
    for (const [user, emoji] of byUser) {
      const info = counts.get(emoji) || { count: 0, mine: false };
      info.count += 1;
      if (user === state.me.username) info.mine = true;
      counts.set(emoji, info);
    }
  }
  ui.renderReactions(n, counts);
}

function send() {
  const input = ui.el("composer-input");
  const text = input.value.trim();
  const room = state.current;
  if (!text || !room || !room.channel) return;
  input.value = "";
  cryptoLib
    .encryptMessage(room.key, room.id, state.me.username, text)
    .then((blob) => {
      const socket = room.socket;
      if (!socket || !socket.connected) {
        ui.status("non connecté : message non envoyé");
        return;
      }
      socket.send(room.channel.id, blob);
      ui.renderMessage(state.me.username, text, true);
    });
}

async function newChannel() {
  const name = window.prompt("Nom du nouveau canal");
  if (name == null) return;
  const trimmed = name.trim();
  const room = state.current;
  if (!trimmed || !room) return;
  try {
    const channel = await api.createChannel(room.id, trimmed);
    room.channels.push(channel);
    selectChannel(channel.id);
  } catch (err) {
    ui.status(err.message);
  }
}

async function newRoom() {
  const name = window.prompt("Nom du nouveau salon");
  if (name == null) return;
  const trimmed = name.trim();
  if (!trimmed) return;
  try {
    const room = await api.createRoom(trimmed);
    const keypair = await cryptoLib.generateRoomKey();
    const self = await cryptoLib.wrapRoomKey(
      state.identity,
      state.identity.publicRaw,
      room.id,
      keypair.raw,
    );
    await api.shareKey(room.id, state.me.username, self);
    await refreshRooms();
    selectRoom(room.id);
  } catch (err) {
    ui.status(err.message);
  }
}

/* Invitation au NIVEAU du salon : le membre accède d'emblée à tous ses
   canaux. Le back-end l'annonce à tout le monde (« a été invité »). */
async function invite() {
  const input = ui.el("invite-username");
  const username = input.value.trim();
  if (!username || !state.current) return;
  try {
    await api.invite(state.current.id, username);
    input.value = "";
    ui.status("membre ajouté, partage de la clé...");
    await shareKeyTo(username);
    refreshMembers();
  } catch (err) {
    ui.status(err.message);
  }
}

async function shareKeyTo(username) {
  const members = await api.members(state.current.id);
  const target = members.members.find((m) => m.username === username);
  if (!target || !target.public_key) {
    ui.status("membre ajouté : clé publique non disponible pour l'instant");
    return;
  }
  const blob = await cryptoLib.wrapRoomKey(
    state.identity,
    target.public_key,
    state.current.id,
    state.current.raw,
  );
  await api.shareKey(state.current.id, username, blob);
  ui.status("clé de salon partagée avec @" + username);
}

/* Recherche locale 100 % côté client : on déchiffre l'historique complet et
   on filtre — aucun texte clair ne transite par le serveur. */
async function loadFullHistory(room, channelId) {
  const all = [];
  let after = 0;
  for (;;) {
    const page = await api.messages(room.id, channelId, after);
    all.push(...page);
    if (!page.length) break;
    after = page[page.length - 1].n;
  }
  return all;
}

async function search() {
  const room = state.current;
  if (!room || !room.channel) return;
  const q = ui.el("search-input").value.trim().toLowerCase();
  if (!q) return;
  ui.status("recherche… (déchiffrement local)");
  const results = [];
  for (const ch of room.channels) {
    const history = await loadFullHistory(room, ch.id);
    for (const m of history) {
      const text = await cryptoLib.decryptMessage(room.key, room.id, m.sender, m.payload);
      if (text && text.toLowerCase().includes(q)) {
        results.push({
          channelId: ch.id,
          channelName: ch.name,
          n: m.n,
          sender: m.sender,
          ts: m.ts,
          text: text.length > 220 ? text.slice(0, 220) + "…" : text,
        });
        if (results.length >= 120) break;
      }
    }
    if (results.length >= 120) break;
  }
  ui.renderSearchResults(results, jumpToResult);
  ui.status(results.length ? results.length + " résultat(s)" : "aucun résultat");
}

function jumpToResult(r) {
  const room = state.current;
  if (!room) return;
  ui.hideSearch();
  selectChannel(r.channelId, r.n);
}

/* Export déchiffré : tout part du navigateur (Blob local), jamais du serveur. */
async function exportChat() {
  const room = state.current;
  if (!room) return;
  ui.status("déchiffrement pour l'export…");
  const out = {
    room: room.id,
    room_name: room.name,
    exported_at: new Date().toISOString(),
    channels: [],
  };
  try {
    for (const ch of room.channels) {
      const history = await loadFullHistory(room, ch.id);
      const messages = [];
      for (const m of history) {
        const text = await cryptoLib.decryptMessage(room.key, room.id, m.sender, m.payload);
        messages.push({
          n: m.n,
          sender: m.sender,
          ts: m.ts,
          text: text === null ? "<illisible>" : text,
        });
      }
      out.channels.push({ id: ch.id, name: ch.name, messages });
    }
    const blob = new Blob([JSON.stringify(out, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "talk-export-" + room.name.replace(/[^\w-]+/g, "_") + ".json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    ui.status("export téléchargé");
  } catch (err) {
    ui.status(err.message);
  }
}

/* Quitter un salon : le serveur purge la clé enveloppée -> perte d'accès
   au contenu chiffré. Le créateur ne peut partir que seul (salon supprimé)
   ou après transfert. */
async function leaveRoom() {
  const room = state.current;
  if (!room) return;
  if (!window.confirm("Quitter ce salon ? Vous perdrez l'accès au contenu chiffré.")) return;
  try {
    await api.leave(room.id);
    leaveOrDeleteCleanup();
  } catch (err) {
    ui.status(err.message);
  }
}

async function transferOwner() {
  const room = state.current;
  if (!room) return;
  const username = window.prompt("Transférer la propriété à (pseudo du membre) :");
  if (username == null) return;
  const to = username.trim();
  if (!to) return;
  try {
    await api.transfer(room.id, to);
    ui.status("propriété transférée à @" + to);
  } catch (err) {
    ui.status(err.message);
  }
}

async function deleteRoomByOwner() {
  const room = state.current;
  if (!room) return;
  if (!window.confirm("Supprimer définitivement ce salon ? Cette action est irréversible.")) return;
  try {
    await api.deleteRoom(room.id);
    leaveOrDeleteCleanup();
  } catch (err) {
    ui.status(err.message);
  }
}

async function deleteChannel(channelId) {
  const room = state.current;
  const channel = room && room.channels.find((c) => c.id === channelId);
  if (!room || !channel) return;
  if (!window.confirm("Supprimer le canal #" + channel.name + " ? (messages chiffrés perdus)")) return;
  try {
    await api.deleteChannel(room.id, channelId);
    room.channels = room.channels.filter((c) => c.id !== channelId);
    if (room.channel && room.channel.id === channelId) {
      const next = room.channels[0];
      if (next) selectChannel(next.id);
    } else {
      ui.renderChannels(
        room.channels,
        room.channel && room.channel.id,
        (cid) => selectChannel(cid),
        ownerCanDelete(),
        (cid) => deleteChannel(cid),
      );
    }
  } catch (err) {
    ui.status(err.message);
  }
}

// Commun à « quitter » et « supprimer » : on se retire proprement et on
// re-sélectionne un autre salon (ou écran vide s'il n'en reste plus).
async function leaveOrDeleteCleanup() {
  closeCurrent();
  ui.showRoomActions(false, false);
  ui.channelTitle("");
  await refreshRooms();
}

function closeCurrent() {
  if (state.current && state.current.socket) state.current.socket.close();
  state.current = null;
  state.reactions.clear();
  state.typing.clear();
  ui.renderTyping([]);
}

async function doLogout() {
  try {
    await api.logout();
  } catch {
    // session déjà expirée : on nettoie quand même la vue
  }
  location.reload();
}

document.addEventListener("DOMContentLoaded", init);