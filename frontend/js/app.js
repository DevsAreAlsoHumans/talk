/* Orchestration : état applicatif, flux login → identité → salon → chat. */

import * as cryptoLib from "./crypto.js";
import { api } from "./api.js";
import { ui } from "./ui.js";
import { ChatSocket } from "./ws.js";

const state = {
  me: null,
  identity: null,
  rooms: [],
  current: null,
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
  await refreshRooms();
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
    lastN: 0,
    socket: null,
  };
  const socket = new ChatSocket(roomId, onMessage, onPresence, (s) => ui.status(s));
  state.current.socket = socket;
  socket.connect();
  ui.renderChannels(channels, null, (cid) => selectChannel(cid));
  if (channels.length) selectChannel(channels[0].id);
}

async function selectChannel(channelId) {
  const room = state.current;
  if (!room) return;
  const channel = room.channels.find((c) => c.id === channelId);
  if (!channel) return;
  room.channel = channel;
  room.lastN = 0;
  ui.channelTitle(channel.name);
  ui.renderChannels(room.channels, channelId, (cid) => selectChannel(cid));
  ui.clearMessages();

  const history = await api.messages(room.id, channelId, 0);
  for (const m of history) {
    const text = await cryptoLib.decryptMessage(room.key, room.id, m.sender, m.payload);
    if (text === null) {
      ui.renderSystem("message illisible (clé de salon différente)");
      continue;
    }
    ui.renderMessage(m.sender, text, m.sender === state.me.username, m.ts);
    room.lastN = Math.max(room.lastN, m.n);
  }
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
      ui.renderMessage(msg.from, text, msg.from === state.me.username, msg.ts);
    });
}

function onPresence(msg) {
  if (msg.event === "join") ui.renderSystem("@" + msg.user + " a rejoint le salon");
  else if (msg.event === "leave") ui.renderSystem("@" + msg.user + " a quitté le salon");
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

async function invite() {
  const input = ui.el("invite-username");
  const username = input.value.trim();
  if (!username || !state.current) return;
  try {
    await api.invite(state.current.id, username);
    input.value = "";
    ui.status("membre ajouté, partage de la clé...");
    await shareKeyTo(username);
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

function closeCurrent() {
  if (state.current && state.current.socket) state.current.socket.close();
  state.current = null;
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