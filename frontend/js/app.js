import { ApiError, apiFetch, jsonBody, refreshCsrf } from "./api.js";
import {
  createRoomKey,
  decryptMessage,
  encryptMessage,
  identityPayload,
  loadOrCreateIdentity,
  unwrapRoomKey,
  wrapRoomKey,
} from "./crypto.js";

const elements = {
  authView: document.querySelector("#auth-view"),
  appView: document.querySelector("#app-view"),
  loginTab: document.querySelector("#login-tab"),
  registerTab: document.querySelector("#register-tab"),
  loginForm: document.querySelector("#login-form"),
  registerForm: document.querySelector("#register-form"),
  userAvatar: document.querySelector("#user-avatar"),
  userDisplayName: document.querySelector("#user-display-name"),
  userUsername: document.querySelector("#user-username"),
  logoutButton: document.querySelector("#logout-button"),
  roomList: document.querySelector("#room-list"),
  channelList: document.querySelector("#channel-list"),
  activeRoomName: document.querySelector("#active-room-name"),
  activeChannelName: document.querySelector("#active-channel-name"),
  activeChannelLabel: document.querySelector("#active-channel-label"),
  emptyChat: document.querySelector("#empty-chat"),
  conversation: document.querySelector("#conversation"),
  messageList: document.querySelector("#message-list"),
  messageForm: document.querySelector("#message-form"),
  messageInput: document.querySelector("#message-input"),
  sendButton: document.querySelector("#send-button"),
  loadMoreButton: document.querySelector("#load-more-button"),
  cryptoWarning: document.querySelector("#crypto-warning"),
  connectionState: document.querySelector("#connection-state"),
  newRoomButton: document.querySelector("#new-room-button"),
  newChannelButton: document.querySelector("#new-channel-button"),
  inviteButton: document.querySelector("#invite-button"),
  shareKeysButton: document.querySelector("#share-keys-button"),
  rotateKeysButton: document.querySelector("#rotate-keys-button"),
  roomActions: document.querySelector("#room-actions"),
  securityInfoButton: document.querySelector("#security-info-button"),
  roomDialog: document.querySelector("#room-dialog"),
  roomForm: document.querySelector("#room-form"),
  channelDialog: document.querySelector("#channel-dialog"),
  channelForm: document.querySelector("#channel-form"),
  memberDialog: document.querySelector("#member-dialog"),
  memberForm: document.querySelector("#member-form"),
  securityDialog: document.querySelector("#security-dialog"),
  toastRegion: document.querySelector("#toast-region"),
};

const state = {
  user: null,
  identity: null,
  rooms: [],
  roomMembers: [],
  activeRoom: null,
  channels: [],
  activeChannel: null,
  messages: [],
  nextCursor: null,
  roomKeyCache: new Map(),
  rawRoomKeys: new Map(),
  socket: null,
  socketEnabled: false,
  pingTimer: null,
  reconnectTimer: null,
  eventRefreshTimer: null,
  sending: false,
};

function initials(name) {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  return (parts.length > 1 ? `${parts[0][0]}${parts.at(-1)[0]}` : name.slice(0, 2)).toUpperCase();
}

function setFormError(form, message = "") {
  const error = form.querySelector(".form-error");
  if (error) {
    error.textContent = message;
  }
}

function setFormBusy(form, busy) {
  const submit = form.querySelector('button[type="submit"]');
  if (submit) {
    submit.disabled = busy;
  }
  form.setAttribute("aria-busy", busy ? "true" : "false");
}

function showToast(message, type = "info") {
  const toast = document.createElement("div");
  toast.className = `toast${type === "error" ? " is-error" : ""}`;
  toast.textContent = message;
  elements.toastRegion.append(toast);
  window.setTimeout(() => toast.remove(), 4800);
}

function errorMessage(error) {
  if (error instanceof ApiError || error instanceof Error) {
    return error.message;
  }
  return "Une erreur inattendue est survenue";
}

function showAuth() {
  elements.appView.hidden = true;
  elements.authView.hidden = false;
  setFormError(elements.loginForm);
  setFormError(elements.registerForm);
  elements.loginForm.reset();
  elements.registerForm.reset();
}

function showApp() {
  elements.authView.hidden = true;
  elements.appView.hidden = false;
}

function switchAuthTab(name) {
  const loginSelected = name === "login";
  elements.loginTab.classList.toggle("is-active", loginSelected);
  elements.registerTab.classList.toggle("is-active", !loginSelected);
  elements.loginTab.setAttribute("aria-selected", String(loginSelected));
  elements.registerTab.setAttribute("aria-selected", String(!loginSelected));
  elements.loginForm.hidden = !loginSelected;
  elements.registerForm.hidden = loginSelected;
  setFormError(elements.loginForm);
  setFormError(elements.registerForm);
}

function deviceName() {
  const platform = globalThis.navigator?.userAgentData?.platform || "Navigateur";
  return `${platform} · appareil personnel`;
}

function openDialog(dialog) {
  const form = dialog.querySelector("form");
  if (form) {
    setFormError(form);
  }
  if (!dialog.open) {
    dialog.showModal();
  }
}

function closeDialog(dialog) {
  if (dialog.open) {
    dialog.close();
  }
}

async function prepareIdentity(username) {
  return loadOrCreateIdentity(username.toLowerCase(), deviceName());
}

async function registerIdentity() {
  if (!state.user || !state.identity) {
    return;
  }
  await apiFetch("/api/identity/keys", {
    method: "POST",
    body: jsonBody(identityPayload(state.identity)),
  });
}

function updateProfile() {
  elements.userDisplayName.textContent = state.user.display_name;
  elements.userUsername.textContent = `@${state.user.username}`;
  elements.userAvatar.textContent = initials(state.user.display_name);
}

async function enterApp(user, preparedIdentity = null) {
  state.user = user;
  state.identity = preparedIdentity || (await prepareIdentity(user.username));
  updateProfile();
  await registerIdentity();
  await loadRooms();
  showApp();
  state.socketEnabled = true;
  connectWebSocket();
}

async function handleLogin(event) {
  event.preventDefault();
  if (!elements.loginForm.reportValidity()) {
    return;
  }
  setFormError(elements.loginForm);
  setFormBusy(elements.loginForm, true);
  try {
    const identity = await prepareIdentity(elements.loginForm.elements.username.value);
    const result = await apiFetch("/api/auth/login", {
      method: "POST",
      body: jsonBody({
        username: elements.loginForm.elements.username.value,
        password: elements.loginForm.elements.password.value,
      }),
    });
    elements.loginForm.reset();
    await enterApp(result.user, identity);
  } catch (error) {
    setFormError(elements.loginForm, errorMessage(error));
  } finally {
    setFormBusy(elements.loginForm, false);
  }
}

async function handleRegister(event) {
  event.preventDefault();
  if (!elements.registerForm.reportValidity()) {
    return;
  }
  setFormError(elements.registerForm);
  setFormBusy(elements.registerForm, true);
  try {
    const identity = await prepareIdentity(elements.registerForm.elements.username.value);
    const result = await apiFetch("/api/auth/register", {
      method: "POST",
      body: jsonBody({
        username: elements.registerForm.elements.username.value,
        display_name: elements.registerForm.elements.display_name.value,
        password: elements.registerForm.elements.password.value,
        identity_key: identityPayload(identity),
      }),
    });
    elements.registerForm.reset();
    await enterApp(result.user, identity);
  } catch (error) {
    setFormError(elements.registerForm, errorMessage(error));
  } finally {
    setFormBusy(elements.registerForm, false);
  }
}

function renderRooms() {
  const fragment = document.createDocumentFragment();
  for (const room of state.rooms) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "room-button";
    button.classList.toggle("is-active", state.activeRoom?.id === room.id);
    button.dataset.roomId = room.id;

    const marker = document.createElement("i");
    marker.textContent = room.name.slice(0, 2);
    const label = document.createElement("span");
    label.textContent = room.name;
    button.append(marker, label);
    button.addEventListener("click", () => selectRoom(room.id));
    fragment.append(button);
  }
  elements.roomList.replaceChildren(fragment);
}

function renderChannels() {
  const fragment = document.createDocumentFragment();
  for (const channel of state.channels) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "channel-button";
    button.classList.toggle("is-active", state.activeChannel?.id === channel.id);
    const label = document.createElement("span");
    label.textContent = channel.name;
    button.append(label);
    button.addEventListener("click", () => selectChannel(channel.id));
    fragment.append(button);
  }
  elements.channelList.replaceChildren(fragment);
}

async function loadRooms(preferredRoomId = null) {
  const result = await apiFetch("/api/rooms");
  state.rooms = result.rooms;
  renderRooms();
  const nextRoomId = preferredRoomId || state.activeRoom?.id || state.rooms[0]?.id;
  if (nextRoomId && state.rooms.some((room) => room.id === nextRoomId)) {
    await selectRoom(nextRoomId);
  } else {
    clearActiveRoom();
  }
}

function clearActiveRoom() {
  state.activeRoom = null;
  state.activeChannel = null;
  state.channels = [];
  state.roomMembers = [];
  state.messages = [];
  state.nextCursor = null;
  elements.activeRoomName.textContent = "Aucun salon";
  elements.activeChannelName.textContent = "Bienvenue sur Talk";
  elements.activeChannelLabel.textContent = "Canal";
  elements.channelList.replaceChildren();
  elements.roomActions.hidden = true;
  elements.newChannelButton.disabled = true;
  elements.emptyChat.hidden = false;
  elements.conversation.hidden = true;
  renderRooms();
}

async function selectRoom(roomId) {
  const [roomResult, channelResult] = await Promise.all([
    apiFetch(`/api/rooms/${roomId}`),
    apiFetch(`/api/rooms/${roomId}/channels`),
  ]);
  state.activeRoom = roomResult.room;
  state.roomMembers = roomResult.members;
  state.channels = channelResult.channels;
  state.activeChannel = null;
  state.messages = [];
  state.nextCursor = null;
  elements.activeRoomName.textContent = state.activeRoom.name;
  elements.newChannelButton.disabled = false;
  elements.emptyChat.hidden = state.channels.length > 0;
  elements.conversation.hidden = state.channels.length === 0;
  elements.roomActions.hidden = state.activeRoom.owner_id !== state.user.id;
  renderRooms();
  renderChannels();
  await loadRoomKeys(state.activeRoom);
  updateComposer();
  const channel = state.channels[0];
  if (channel) {
    await selectChannel(channel.id);
  } else {
    elements.activeChannelName.textContent = "Aucun canal";
    elements.activeChannelLabel.textContent = state.activeRoom.name;
  }
}

async function selectChannel(channelId) {
  const channel = state.channels.find((item) => item.id === channelId);
  if (!channel) {
    return;
  }
  state.activeChannel = channel;
  elements.activeChannelName.textContent = channel.name;
  elements.activeChannelLabel.textContent = state.activeRoom.name;
  elements.emptyChat.hidden = true;
  elements.conversation.hidden = false;
  renderChannels();
  await loadMessages();
}

function cacheRoomKey(roomId, version, roomKey, rawRoomKey) {
  if (!state.roomKeyCache.has(roomId)) {
    state.roomKeyCache.set(roomId, new Map());
  }
  state.roomKeyCache.get(roomId).set(version, roomKey);
  state.rawRoomKeys.set(`${roomId}:${version}`, rawRoomKey);
}

function getRoomKey(roomId, version) {
  return state.roomKeyCache.get(roomId)?.get(version) || null;
}

function getRawRoomKey(roomId, version) {
  return state.rawRoomKeys.get(`${roomId}:${version}`) || null;
}

async function loadRoomKeys(room) {
  const result = await apiFetch(`/api/rooms/${room.id}/keys`);
  for (const envelope of result.key_envelopes) {
    if (
      envelope.recipient_id !== state.user.id ||
      envelope.key_id !== state.identity.keyId
    ) {
      continue;
    }
    const cacheKey = `${room.id}:${envelope.key_version}`;
    if (state.rawRoomKeys.has(cacheKey)) {
      continue;
    }
    try {
      const opened = await unwrapRoomKey(envelope.wrapped_key, state.identity);
      cacheRoomKey(
        room.id,
        envelope.key_version,
        opened.roomKey,
        opened.rawRoomKey,
      );
    } catch (error) {
      console.warn("Impossible d'ouvrir une enveloppe de clé", error);
    }
  }
  const hasCurrentKey = Boolean(getRoomKey(room.id, room.key_version));
  elements.cryptoWarning.hidden = hasCurrentKey;
  updateComposer();
}

function updateComposer() {
  const canWrite = Boolean(
    state.activeRoom &&
      state.activeChannel &&
      getRoomKey(state.activeRoom.id, state.activeRoom.key_version),
  );
  elements.messageInput.disabled = !canWrite;
  elements.sendButton.disabled = !canWrite || !elements.messageInput.value.trim() || state.sending;
  elements.cryptoWarning.hidden = canWrite;
  elements.messageInput.placeholder = canWrite
    ? "Écrivez votre message…"
    : "Clé indisponible sur cet appareil";
}

async function fetchUserKeys(username) {
  const result = await apiFetch(`/api/users/${encodeURIComponent(username)}/keys`);
  if (!result.identity_keys.length) {
    throw new Error(`${result.user.display_name} n’a aucune clé publique disponible`);
  }
  return result;
}

async function makeEnvelopes(rawRoomKey, users, keyVersion) {
  const envelopes = [];
  for (const userResult of users) {
    for (const identityKey of userResult.identity_keys) {
      envelopes.push({
        recipient_id: userResult.user.id,
        key_id: identityKey.key_id,
        algorithm: "RSA-OAEP-256",
        wrapped_key: await wrapRoomKey(rawRoomKey, identityKey.public_key),
        key_version: keyVersion,
      });
    }
  }
  return envelopes;
}

async function createRoom(event) {
  event.preventDefault();
  if (!elements.roomForm.reportValidity()) {
    return;
  }
  setFormError(elements.roomForm);
  setFormBusy(elements.roomForm, true);
  let rawRoomKey = null;
  try {
    const invitedNames = [
      ...new Set(
        elements.roomForm.elements.invites.value
          .split(/[\s,]+/)
          .map((name) => name.trim().toLowerCase())
          .filter(Boolean),
      ),
    ].filter((name) => name !== state.user.username);
    const names = [state.user.username, ...invitedNames];
    const userResults = await Promise.all(names.map(fetchUserKeys));
    rawRoomKey = createRoomKey();
    const keyEnvelopes = await makeEnvelopes(rawRoomKey, userResults, 1);
    const result = await apiFetch("/api/rooms", {
      method: "POST",
      body: jsonBody({
        name: elements.roomForm.elements.name.value,
        channel_name: elements.roomForm.elements.channel_name.value,
        invites: invitedNames.map((username) => ({ username })),
        key_envelopes: keyEnvelopes,
      }),
    });
    closeDialog(elements.roomDialog);
    elements.roomForm.reset();
    elements.roomForm.elements.channel_name.value = "général";
    showToast(`Le salon « ${result.room.name} » est prêt.`);
    await loadRooms(result.room.id);
  } catch (error) {
    setFormError(elements.roomForm, errorMessage(error));
  } finally {
    rawRoomKey?.fill(0);
    setFormBusy(elements.roomForm, false);
  }
}

async function createChannel(event) {
  event.preventDefault();
  if (!state.activeRoom || !elements.channelForm.reportValidity()) {
    return;
  }
  setFormError(elements.channelForm);
  setFormBusy(elements.channelForm, true);
  try {
    const channel = await apiFetch(`/api/rooms/${state.activeRoom.id}/channels`, {
      method: "POST",
      body: jsonBody({ name: elements.channelForm.elements.name.value }),
    });
    closeDialog(elements.channelDialog);
    elements.channelForm.reset();
    state.channels.push(channel);
    state.channels.sort((left, right) => left.created_at - right.created_at);
    await selectChannel(channel.id);
    showToast(`Le canal #${channel.name} a été créé.`);
  } catch (error) {
    setFormError(elements.channelForm, errorMessage(error));
  } finally {
    setFormBusy(elements.channelForm, false);
  }
}

async function addRoomMember(event) {
  event.preventDefault();
  if (!state.activeRoom || !elements.memberForm.reportValidity()) {
    return;
  }
  setFormError(elements.memberForm);
  setFormBusy(elements.memberForm, true);
  try {
    const username = elements.memberForm.elements.username.value.toLowerCase();
    const userResult = await fetchUserKeys(username);
    const rawRoomKey = getRawRoomKey(
      state.activeRoom.id,
      state.activeRoom.key_version,
    );
    if (!rawRoomKey) {
      throw new Error("La clé courante n’est pas disponible sur cet appareil");
    }
    const keyEnvelopes = await makeEnvelopes(rawRoomKey, [userResult], state.activeRoom.key_version);
    await apiFetch(`/api/rooms/${state.activeRoom.id}/members`, {
      method: "POST",
      body: jsonBody({ username, key_envelopes: keyEnvelopes }),
    });
    closeDialog(elements.memberDialog);
    elements.memberForm.reset();
    showToast(`@${username} a été invité avec la clé du salon.`);
    await selectRoom(state.activeRoom.id);
  } catch (error) {
    setFormError(elements.memberForm, errorMessage(error));
  } finally {
    setFormBusy(elements.memberForm, false);
  }
}

async function shareKeysWithDevices() {
  if (!state.activeRoom) {
    return;
  }
  try {
    const rawRoomKey = getRawRoomKey(
      state.activeRoom.id,
      state.activeRoom.key_version,
    );
    if (!rawRoomKey) {
      throw new Error("La clé du salon n’est pas disponible sur cet appareil");
    }
    const [existing, ...userResults] = await Promise.all([
      apiFetch(`/api/rooms/${state.activeRoom.id}/keys`),
      ...state.roomMembers.map((member) => fetchUserKeys(member.username)),
    ]);
    const existingFields = new Set(
      existing.key_envelopes
        .filter((envelope) => envelope.key_version === state.activeRoom.key_version)
        .map(
          (envelope) =>
            `${envelope.key_version}:${envelope.recipient_id}:${envelope.key_id}`,
        ),
    );
    const missingEnvelopes = [];
    for (const userResult of userResults) {
      for (const identityKey of userResult.identity_keys) {
        const field = `${state.activeRoom.key_version}:${userResult.user.id}:${identityKey.key_id}`;
        if (existingFields.has(field)) {
          continue;
        }
        missingEnvelopes.push({
          recipient_id: userResult.user.id,
          key_id: identityKey.key_id,
          algorithm: "RSA-OAEP-256",
          wrapped_key: await wrapRoomKey(rawRoomKey, identityKey.public_key),
          key_version: state.activeRoom.key_version,
        });
      }
    }
    if (!missingEnvelopes.length) {
      showToast("Tous les appareils enregistrés ont déjà cette version de la clé.");
      return;
    }
    await apiFetch(`/api/rooms/${state.activeRoom.id}/keys/share`, {
      method: "POST",
      body: jsonBody({ key_envelopes: missingEnvelopes }),
    });
    showToast("La clé a été partagée avec les nouveaux appareils.");
  } catch (error) {
    showToast(errorMessage(error), "error");
  }
}

async function rotateRoomKey() {
  if (!state.activeRoom) {
    return;
  }
  elements.rotateKeysButton.disabled = true;
  let rawRoomKey = null;
  try {
    const userResults = await Promise.all(
      state.roomMembers.map((member) => fetchUserKeys(member.username)),
    );
    rawRoomKey = createRoomKey();
    const keyEnvelopes = await makeEnvelopes(
      rawRoomKey,
      userResults,
      state.activeRoom.key_version + 1,
    );
    const result = await apiFetch(`/api/rooms/${state.activeRoom.id}/keys/rotate`, {
      method: "POST",
      body: jsonBody({ key_envelopes: keyEnvelopes }),
    });
    state.activeRoom.key_version = result.key_version;
    const currentRoom = state.rooms.find((room) => room.id === state.activeRoom.id);
    if (currentRoom) {
      currentRoom.key_version = result.key_version;
    }
    renderRooms();
    await loadRoomKeys(state.activeRoom);
    showToast("Une nouvelle version de la clé a été distribuée.");
  } catch (error) {
    showToast(errorMessage(error), "error");
  } finally {
    rawRoomKey?.fill(0);
    elements.rotateKeysButton.disabled = false;
  }
}

async function loadMessages({ before = null, append = false } = {}) {
  if (!state.activeChannel) {
    return;
  }
  const query = new URLSearchParams({ limit: "50" });
  if (before) {
    query.set("before", String(before));
  }
  const result = await apiFetch(
    `/api/channels/${state.activeChannel.id}/messages?${query.toString()}`,
  );
  state.messages = append ? [...state.messages, ...result.messages] : result.messages;
  state.nextCursor = result.next_cursor;
  await renderMessages(append);
}

function createMessageElement(message) {
  const item = document.createElement("li");
  const isOwn = message.sender_id === state.user.id;
  item.className = `message-item${isOwn ? " is-own" : ""}`;

  const avatar = document.createElement("span");
  avatar.className = "message-avatar";
  avatar.textContent = initials(message.sender?.display_name || "?");

  const content = document.createElement("div");
  content.className = "message-content";
  const meta = document.createElement("div");
  meta.className = "message-meta";
  const author = document.createElement("strong");
  author.textContent = message.sender?.display_name || "Utilisateur";
  const time = document.createElement("time");
  time.dateTime = new Date(message.created_at).toISOString();
  time.textContent = new Intl.DateTimeFormat("fr-FR", {
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(message.created_at));
  meta.append(author, time);

  const text = document.createElement("p");
  text.className = "message-text";
  text.textContent = "Chargement du déchiffrement…";
  content.append(meta, text);
  item.append(avatar, content);
  return { item, text };
}

async function renderMessages(append = false) {
  if (!append) {
    elements.messageList.replaceChildren();
  }
  const fragment = document.createDocumentFragment();
  for (const message of state.messages) {
    const { item, text } = createMessageElement(message);
    fragment.append(item);
    const roomKey = getRoomKey(
      message.room_id,
      message.key_version,
    );
    if (!roomKey) {
      text.textContent = "Message chiffré — clé de cette version indisponible.";
      text.classList.add("is-error");
      continue;
    }
    try {
      text.textContent = await decryptMessage(message, roomKey);
    } catch (error) {
      text.textContent = errorMessage(error);
      text.classList.add("is-error");
    }
  }
  elements.messageList.append(fragment);
  elements.loadMoreButton.hidden = state.nextCursor === null;
  if (!append) {
    window.requestAnimationFrame(() => {
      elements.messageList.scrollTop = elements.messageList.scrollHeight;
    });
  }
}

async function sendMessage(event) {
  event.preventDefault();
  if (!state.activeRoom || !state.activeChannel || state.sending) {
    return;
  }
  const plaintext = elements.messageInput.value.trim();
  const roomKey = getRoomKey(state.activeRoom.id, state.activeRoom.key_version);
  if (!plaintext || !roomKey) {
    return;
  }
  state.sending = true;
  updateComposer();
  try {
    const clientId = crypto.randomUUID();
    const message = {
      client_id: clientId,
      algorithm: "AES-GCM-256",
      key_version: state.activeRoom.key_version,
      room_id: state.activeRoom.id,
      channel_id: state.activeChannel.id,
      sender_id: state.user.id,
    };
    const encrypted = await encryptMessage(plaintext, roomKey, message);
    await apiFetch(`/api/channels/${state.activeChannel.id}/messages`, {
      method: "POST",
      body: jsonBody({
        client_id: clientId,
        algorithm: message.algorithm,
        key_version: message.key_version,
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
      }),
    });
    elements.messageInput.value = "";
    elements.messageInput.style.height = "auto";
    await loadMessages();
  } catch (error) {
    showToast(errorMessage(error), "error");
  } finally {
    state.sending = false;
    updateComposer();
  }
}

function setConnection(status, label) {
  elements.connectionState.classList.toggle("is-offline", status !== "online");
  elements.connectionState.querySelector("span").textContent = label;
}

function clearSocketTimers() {
  window.clearInterval(state.pingTimer);
  window.clearTimeout(state.reconnectTimer);
  state.pingTimer = null;
  state.reconnectTimer = null;
}

function connectWebSocket() {
  if (!state.socketEnabled) {
    return;
  }
  clearSocketTimers();
  state.socket?.close();
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${protocol}//${window.location.host}/api/ws`);
  state.socket = socket;
  setConnection("connecting", "Connexion…");

  socket.addEventListener("open", () => {
    state.pingTimer = window.setInterval(() => {
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "ping", nonce: crypto.randomUUID() }));
      }
    }, 25000);
  });
  socket.addEventListener("message", (event) => {
    try {
      void handleRealtimeEvent(JSON.parse(event.data));
    } catch (error) {
      console.warn("Événement temps réel ignoré", error);
    }
  });
  socket.addEventListener("close", () => {
    window.clearInterval(state.pingTimer);
    if (state.socketEnabled && state.user) {
      setConnection("offline", "Hors ligne");
      state.reconnectTimer = window.setTimeout(connectWebSocket, 2500);
    }
  });
}

async function handleRealtimeEvent(event) {
  if (event.type === "connection.ready") {
    setConnection("online", "En direct");
    return;
  }
  if (event.type === "message.created") {
    const message = event.message;
    if (
      state.activeChannel?.id === message.channel_id &&
      state.activeRoom?.id === message.room_id
    ) {
      scheduleMessageRefresh();
    } else {
      showToast(`Nouveau message dans #${message.channel_id.slice(0, 6)}…`);
    }
    return;
  }
  if (event.type === "channel.created" && state.activeRoom?.id === event.room_id) {
    if (!state.channels.some((channel) => channel.id === event.channel.id)) {
      state.channels.push(event.channel);
      renderChannels();
    }
    return;
  }
  if (event.type?.startsWith("room.")) {
    const preferred = state.activeRoom?.id;
    await loadRooms(preferred);
    if (state.activeRoom && ["room.keys_shared", "room.keys_rotated"].includes(event.type)) {
      await loadRoomKeys(state.activeRoom);
    }
  }
}

function scheduleMessageRefresh() {
  window.clearTimeout(state.eventRefreshTimer);
  state.eventRefreshTimer = window.setTimeout(() => {
    if (state.user) {
      void loadMessages().catch((error) => showToast(errorMessage(error), "error"));
    }
  }, 120);
}

async function logout() {
  state.socketEnabled = false;
  clearSocketTimers();
  state.socket?.close();
  state.socket = null;
  try {
    await apiFetch("/api/auth/logout", { method: "POST" });
  } catch (error) {
    console.warn("Déconnexion locale après une erreur réseau", error);
  } finally {
    for (const rawKey of state.rawRoomKeys.values()) {
      rawKey.fill(0);
    }
    state.user = null;
    state.identity = null;
    state.rooms = [];
    state.roomMembers = [];
    state.channels = [];
    state.messages = [];
    state.roomKeyCache.clear();
    state.rawRoomKeys.clear();
    clearActiveRoom();
    setConnection("offline", "Hors ligne");
    showAuth();
  }
}

function bindEvents() {
  elements.loginTab.addEventListener("click", () => switchAuthTab("login"));
  elements.registerTab.addEventListener("click", () => switchAuthTab("register"));
  elements.loginForm.addEventListener("submit", handleLogin);
  elements.registerForm.addEventListener("submit", handleRegister);
  elements.logoutButton.addEventListener("click", logout);
  elements.newRoomButton.addEventListener("click", () => openDialog(elements.roomDialog));
  elements.newChannelButton.addEventListener("click", () => openDialog(elements.channelDialog));
  elements.inviteButton.addEventListener("click", () => openDialog(elements.memberDialog));
  elements.shareKeysButton.addEventListener("click", shareKeysWithDevices);
  elements.rotateKeysButton.addEventListener("click", rotateRoomKey);
  elements.securityInfoButton.addEventListener("click", () => openDialog(elements.securityDialog));
  elements.roomForm.addEventListener("submit", createRoom);
  elements.channelForm.addEventListener("submit", createChannel);
  elements.memberForm.addEventListener("submit", addRoomMember);
  elements.messageForm.addEventListener("submit", sendMessage);
  elements.loadMoreButton.addEventListener("click", async () => {
    if (!state.nextCursor) {
      return;
    }
    try {
      await loadMessages({ before: state.nextCursor, append: true });
    } catch (error) {
      showToast(errorMessage(error), "error");
    }
  });
  elements.messageInput.addEventListener("input", () => {
    elements.messageInput.style.height = "auto";
    elements.messageInput.style.height = `${Math.min(elements.messageInput.scrollHeight, 140)}px`;
    updateComposer();
  });
  elements.messageInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      elements.messageForm.requestSubmit();
    }
  });

  document.querySelectorAll(".password-toggle").forEach((button) => {
    button.addEventListener("click", () => {
      const input = button.parentElement.querySelector("input");
      const visible = input.type === "text";
      input.type = visible ? "password" : "text";
      button.textContent = visible ? "Afficher" : "Masquer";
      button.setAttribute("aria-label", visible ? "Afficher le mot de passe" : "Masquer le mot de passe");
    });
  });
  document.querySelectorAll(".dialog-close").forEach((button) => {
    button.addEventListener("click", () => closeDialog(button.closest("dialog")));
  });
  document.querySelectorAll("dialog").forEach((dialog) => {
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) {
        closeDialog(dialog);
      }
    });
  });
  document.querySelector(".dialog-done").addEventListener("click", () => closeDialog(elements.securityDialog));
}

async function bootstrap() {
  bindEvents();
  try {
    await refreshCsrf();
    const result = await apiFetch("/api/auth/me");
    await enterApp(result.user);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      showAuth();
      return;
    }
    showAuth();
    showToast(errorMessage(error), "error");
  }
}

void bootstrap();
