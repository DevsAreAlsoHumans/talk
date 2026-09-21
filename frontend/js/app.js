/*
 * Interface de talk. Toute la cryptographie passe par crypto.js : ici on ne fait qu'orchestrer
 * (connexion, salons, messages, temps réel) et afficher. Le contenu affiché est toujours inséré
 * comme texte (voir dom.js), jamais comme HTML.
 */
import * as api from './api.js';
import * as e2e from './crypto.js';
import { $, clear, h } from './dom.js';

const USERNAME_PATTERN = /^[a-z0-9_]{3,32}$/;
const MIN_PASSWORD_LENGTH = 10;
const MAX_MESSAGE_CHARS = 2000;
const HISTORY_PAGE_SIZE = 50;
const RECONNECT_DELAYS_MS = [1000, 2000, 5000, 10000];
const GROUP_WINDOW_MS = 5 * 60 * 1000;
const NEAR_BOTTOM_PX = 96;
const REVEAL_GLYPHS = '▒░▓#%&*+=?';
const REVEAL_FRAMES = 12;
const ALLOWED_IMAGE_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif']);
const ALLOWED_VOICE_TYPES = new Set(['audio/webm', 'audio/ogg', 'audio/mp4', 'audio/mpeg']);
const MAX_MEDIA_BYTES = 2 * 1024 * 1024; // limite serveur identique côté navigateur
const MAX_IMAGE_BYTES = 8 * 1024 * 1024; // avant ré-encodage si hors limites
const AVATAR_SIZE = 512;
const MAX_VOICE_MS = 60_000;
const MIN_VOICE_MS = 300;
const RTC_CONFIG = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };
const ROLE_OWNER = 'owner';
const ROLE_CO = 'co';
const ROLE_MEMBER = 'member';

const timeFormat = new Intl.DateTimeFormat('fr-FR', { hour: '2-digit', minute: '2-digit' });
const dayFormat = new Intl.DateTimeFormat('fr-FR', { weekday: 'long', day: 'numeric', month: 'long' });
const prefersReducedMotion = () => globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;

const el = {
  authScreen: $('#auth-screen'),
  authForm: $('#auth-form'),
  authUsername: $('#auth-username'),
  authPassword: $('#auth-password'),
  authConfirm: $('#auth-confirm'),
  confirmField: $('#confirm-field'),
  registerWarning: $('#register-warning'),
  authError: $('#auth-error'),
  authSubmit: $('#auth-submit'),
  tabLogin: $('#tab-login'),
  tabRegister: $('#tab-register'),
  app: $('#app'),
  roomList: $('#room-list'),
  roomEmpty: $('#room-empty'),
  createRoomForm: $('#create-room-form'),
  newRoomName: $('#new-room-name'),
  convList: $('#conv-list'),
  convEmpty: $('#conv-empty'),
  addFriendForm: $('#add-friend-form'),
  addFriendName: $('#add-friend-name'),
  friendList: $('#friend-list'),
  friendRequests: $('#friend-requests'),
  friendRequestsGroup: $('#friend-requests-group'),
  friendEmpty: $('#friend-empty'),
  tabSessions: $('#tab-sessions'),
  tabFriends: $('#tab-friends'),
  sessionsPanel: $('#sessions-panel'),
  friendsPanel: $('#friends-panel'),
  meName: $('#me-name'),
  logout: $('#logout'),
  toggleRail: $('#toggle-rail'),
  toggleMembers: $('#toggle-members'),
  roomTitle: $('#room-title'),
  e2eBadge: $('#e2e-badge'),
  connStatus: $('#conn-status'),
  messages: $('#messages'),
  composer: $('#composer'),
  composerInput: $('#composer-input'),
  composerSend: $('#composer-send'),
  memberCount: $('#member-count'),
  memberList: $('#member-list'),
  addMemberForm: $('#add-member-form'),
  addMemberName: $('#add-member-name'),
  btnProfile: $('#btn-profile'),
  meAvatar: $('#me-avatar'),
  fileImage: $('#file-image'),
  btnVoice: $('#btn-voice'),
  voiceStatus: $('#voice-status'),
  profileDialog: $('#profile-dialog'),
  profileForm: $('#profile-form'),
  profilePreview: $('#profile-preview'),
  profileAvatar: $('#profile-avatar'),
  profileName: $('#profile-name'),
  profileBio: $('#profile-bio'),
  profileError: $('#profile-error'),
  profileSave: $('#profile-save'),
  profileCancel: $('#profile-cancel'),
  callView: $('#call-view'),
  callState: $('#call-state'),
  callPeer: $('#call-peer'),
  callAccept: $('#call-accept'),
  callDecline: $('#call-decline'),
  callMute: $('#call-mute'),
  callEnd: $('#call-end'),
  callRemote: $('#call-remote'),
  toast: $('#toast'),
  announcer: $('#announcer'),
};

const state = {
  loggedIn: false,
  me: null, // { id, username, publicKey, displayName, bio }
  privateKey: null, // CryptoKey non extractable : ne quitte jamais la mémoire du navigateur
  rooms: [],
  currentRoomId: null,
  roomDetails: new Map(), // id → { members, owner_id, wrapped_key, avatars, online, ... }
  roomKeys: new Map(), // id → CryptoKey AES-GCM
  timelines: new Map(), // id → Map(seq → { message, text | media })
  hasMore: new Map(), // id → reste-t-il des messages plus anciens ?
  convs: [],
  currentConvId: null,
  convDetails: new Map(), // id → { peer, wrapped_key, ... }
  convKeys: new Map(), // id → CryptoKey AES-GCM
  convTimelines: new Map(), // id → Map(seq → { message, text | media })
  convHasMore: new Map(), // id → reste-t-il des messages plus anciens ?
  convOnline: new Map(), // id du correspondant → en ligne ?
  friends: [], // amis confirmés (MemberSummary)
  friendRequests: [], // demandes d'ami reçues, en attente
  avatars: new Map(), // id du salon → Map(id du membre → URL de l'avatar déchiffré)
  unread: new Set(),
  fingerprints: new Map(),
  socket: null,
  everConnected: false,
  reconnectAttempt: 0,
  reconnectTimer: null,
  toastTimer: null,
  authMode: 'login',
  call: null, // { peerId, peerName, pc, localStream, remoteStream, state, muted }
  incoming: null, // { id, name, offer } appels entrants en attente
  recorder: null, // enregistrement vocal en cours
  recordingStartedAt: 0,
};

// ---------- Retours à l'utilisateur ----------

function notify(message, kind = 'info') {
  el.toast.textContent = message;
  el.toast.dataset.kind = kind;
  el.toast.hidden = false;
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => {
    el.toast.hidden = true;
  }, 5000);
}

function announce(text) {
  el.announcer.textContent = '';
  setTimeout(() => {
    el.announcer.textContent = text;
  }, 50);
}

function reportError(error, fallback = 'Une erreur est survenue. Réessayez.') {
  console.error(error);
  if (error instanceof api.ApiError && error.status === 401) return; // déjà géré : retour à la connexion
  if (error instanceof api.ApiError && error.status === 429) notify('Trop de requêtes : ralentissez un instant.', 'error');
  else notify(fallback, 'error');
}

// ---------- Écran de connexion ----------

function showAuthError(message) {
  el.authError.textContent = message ?? '';
  el.authError.hidden = !message;
}

function setAuthMode(mode) {
  state.authMode = mode;
  const registering = mode === 'register';
  el.tabLogin.setAttribute('aria-selected', String(!registering));
  el.tabRegister.setAttribute('aria-selected', String(registering));
  el.confirmField.hidden = !registering;
  el.registerWarning.hidden = !registering;
  el.authPassword.autocomplete = registering ? 'new-password' : 'current-password';
  showAuthError(null);
  setAuthBusy(false);
}

function setAuthBusy(busy) {
  const registering = state.authMode === 'register';
  el.authSubmit.disabled = busy;
  if (busy) el.authSubmit.textContent = registering ? 'Création du compte…' : 'Connexion…';
  else el.authSubmit.textContent = registering ? 'Créer mon compte' : 'Se connecter';
}

function validateCredentials(username, password, confirmation) {
  if (!USERNAME_PATTERN.test(username)) {
    return "Nom d'utilisateur invalide : 3 à 32 caractères, lettres minuscules, chiffres ou _.";
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Mot de passe trop court : ${MIN_PASSWORD_LENGTH} caractères minimum.`;
  }
  if (state.authMode === 'register' && password !== confirmation) {
    return 'Les deux mots de passe ne correspondent pas.';
  }
  return null;
}

function describeAuthError(error) {
  if (error instanceof api.ApiError) {
    if (error.status === 401) return "Nom d'utilisateur ou mot de passe incorrect.";
    if (error.status === 409) return "Ce nom d'utilisateur est déjà pris.";
    if (error.status === 429) return 'Trop de tentatives. Patientez une minute avant de réessayer.';
    if (error.status === 422) return 'Informations invalides. Vérifiez les champs saisis.';
  }
  if (error instanceof TypeError) return 'Impossible de joindre le serveur.';
  return 'Une erreur est survenue. Réessayez.';
}

async function register(username, password) {
  const { wrapKey, authSecret } = await e2e.deriveKeys(password, username);
  const identity = await e2e.generateIdentity();
  await api.register({
    username,
    auth_secret: authSecret,
    public_key: identity.publicKey,
    encrypted_private_key: await e2e.encryptPrivateKey(identity.pkcs8, wrapKey),
  });
  await completeLogin(username, wrapKey, authSecret);
}

async function login(username, password) {
  const { wrapKey, authSecret } = await e2e.deriveKeys(password, username);
  await completeLogin(username, wrapKey, authSecret);
}

async function completeLogin(username, wrapKey, authSecret) {
  const { user, csrf_token: csrfToken } = await api.login({ username, auth_secret: authSecret });
  api.setCsrfToken(csrfToken);
  try {
    state.privateKey = await e2e.decryptPrivateKey(user.encrypted_private_key, wrapKey);
  } catch (error) {
    await api.logout().catch(() => {});
    throw error;
  }
  state.me = {
    id: user.id,
    username: user.username,
    publicKey: user.public_key,
    displayName: user.display_name,
    bio: user.bio,
  };
  el.authPassword.value = '';
  el.authConfirm.value = '';
  await enterApp();
}

el.authForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const username = el.authUsername.value.trim().toLowerCase();
  const problem = validateCredentials(username, el.authPassword.value, el.authConfirm.value);
  if (problem) {
    showAuthError(problem);
    return;
  }
  showAuthError(null);
  setAuthBusy(true);
  try {
    if (state.authMode === 'register') await register(username, el.authPassword.value);
    else await login(username, el.authPassword.value);
  } catch (error) {
    console.error(error);
    showAuthError(describeAuthError(error));
  } finally {
    setAuthBusy(false);
  }
});

el.tabLogin.addEventListener('click', () => setAuthMode('login'));
el.tabRegister.addEventListener('click', () => setAuthMode('register'));

// ---------- Entrée / sortie de l'application ----------

async function enterApp() {
  state.loggedIn = true;
  el.authScreen.hidden = true;
  el.app.hidden = false;
  setRailTab('sessions');
  el.meName.textContent = state.me.displayName || state.me.username;
  updateOwnAvatar(null);
  connectSocket();
  await Promise.all([refreshRooms(), refreshConversations(), refreshFriends()]);
  if (state.rooms.length > 0) await selectRoom(state.rooms[0].id);
  else if (state.convs.length > 0) await selectConversation(state.convs[0].id);
  else renderChat();
}

function resetSession() {
  state.loggedIn = false;
  clearTimeout(state.reconnectTimer);
  const socket = state.socket;
  state.socket = null;
  socket?.close(1000);
  teardownCall({
    silent: true,
    sendSignal: false,
  });
  stopRecording(true);
  Object.assign(state, {
    me: null,
    privateKey: null,
    rooms: [],
    currentRoomId: null,
    convs: [],
    currentConvId: null,
    friends: [],
    friendRequests: [],
    everConnected: false,
    reconnectAttempt: 0,
    incoming: null,
    call: null,
    recorder: null,
  });
  for (const collection of [
    state.roomDetails,
    state.roomKeys,
    state.timelines,
    state.hasMore,
    state.convDetails,
    state.convKeys,
    state.convTimelines,
    state.convHasMore,
    state.convOnline,
    state.fingerprints,
  ]) {
    collection.clear();
  }
  revokeAllMedia(state.timelines, state.convTimelines, state.avatars);
  state.unread.clear();
  api.setCsrfToken(null);
  clear(el.roomList);
  clear(el.convList);
  clear(el.memberList);
  clear(el.messages);
  clear(el.friendList);
  clear(el.friendRequests);
  el.app.classList.remove('thread-dm');
  el.app.hidden = true;
  el.authScreen.hidden = false;
}

async function logout() {
  try {
    await api.logout();
  } catch (error) {
    console.error(error);
  }
  resetSession();
  setAuthMode('login');
  el.authUsername.focus();
}

api.onUnauthorized(() => {
  if (!state.loggedIn) return;
  resetSession();
  setAuthMode('login');
  showAuthError('Votre session a expiré. Reconnectez-vous.');
});

el.logout.addEventListener('click', logout);

// ---------- Salons ----------

/** Clé d'unicité d'un fil (salon ou conversation) : préfixe « c: » pour les conversations directes. */
function threadKey({ kind, id }) {
  return kind === 'conv' ? `c:${id}` : id;
}

/** Fil actuellement affiché, ou null si rien n'est sélectionné. */
function currentThread() {
  if (state.currentConvId) return { kind: 'conv', id: state.currentConvId };
  if (state.currentRoomId) return { kind: 'room', id: state.currentRoomId };
  return null;
}

async function refreshRooms() {
  state.rooms = await api.listRooms();
  renderRoomList();
}

function renderRoomList() {
  clear(el.roomList);
  el.roomEmpty.hidden = state.rooms.length > 0;
  for (const room of state.rooms) {
    const active = room.id === state.currentRoomId;
    el.roomList.append(
      h(
        'li',
        {},
        h(
          'button',
          {
            type: 'button',
            class: `room${active ? ' active' : ''}`,
            'aria-current': active ? 'true' : null,
            onclick: () => selectRoom(room.id),
          },
          h('span', { class: 'room-name' }, room.name),
          state.unread.has(room.id) ? h('span', { class: 'unread', title: 'Nouveaux messages' }) : null,
          state.unread.has(room.id) ? h('span', { class: 'sr-only' }, ' (nouveaux messages)') : null,
          h('span', { class: 'room-count', title: 'Membres' }, String(room.member_count)),
        ),
      ),
    );
  }
}

/** Charge le détail du salon et déballe sa clé avec notre clé privée (jamais envoyée au serveur). */
async function ensureRoom(roomId) {
  let detail = state.roomDetails.get(roomId);
  if (!detail) {
    detail = await api.getRoom(roomId);
    state.roomDetails.set(roomId, detail);
  }
  if (!state.roomKeys.has(roomId)) {
    const key = await e2e.unwrapRoomKey(detail.wrapped_key, state.privateKey, {
      extractable: detail.owner_id === state.me.id, // seul le propriétaire réenveloppe la clé pour de nouveaux membres
    });
    state.roomKeys.set(roomId, key);
  }
  return detail;
}

async function selectRoom(roomId) {
  state.currentRoomId = roomId;
  state.currentConvId = null;
  state.unread.delete(roomId);
  el.app.classList.remove('thread-dm', 'rail-open', 'members-open');
  renderRoomList();
  renderConvList();
  try {
    await ensureRoom(roomId);
    await loadLatest(roomId);
    void fillAvatars(roomId); // avatars déchiffrés en arrière-plan, sans bloquer l'affichage
  } catch (error) {
    reportError(error, "Impossible d'ouvrir ce salon.");
    return;
  }
  if (state.currentRoomId === roomId) renderChat({ scroll: 'bottom' });
}

// ---------- Conversations directes ----------

async function refreshConversations() {
  state.convs = await api.listConversations();
  renderConvList();
}

function renderConvList() {
  clear(el.convList);
  el.convEmpty.hidden = state.convs.length > 0;
  const sorted = [...state.convs].sort((a, b) => a.created_at.localeCompare(b.created_at));
  for (const conv of sorted) {
    const active = conv.id === state.currentConvId;
    const key = threadKey({ kind: 'conv', id: conv.id });
    const peer = conv.peer;
    const online = state.convOnline.get(peer.id);
    el.convList.append(
      h(
        'li',
        {},
        h(
          'button',
          {
            type: 'button',
            class: `room${active ? ' active' : ''}`,
            'aria-current': active ? 'true' : null,
            onclick: () => selectConversation(conv.id),
          },
          h('span', { class: 'room-name' }, peer.display_name || peer.username),
          online === undefined
            ? null
            : h(
                'span',
                { class: `presence${online ? '' : ' offline'}`, title: online ? 'En ligne' : 'Hors ligne' },
                online ? 'en ligne' : 'hors ligne',
              ),
          state.unread.has(key) ? h('span', { class: 'unread', title: 'Nouveaux messages' }) : null,
          state.unread.has(key) ? h('span', { class: 'sr-only' }, ' (nouveaux messages)') : null,
        ),
      ),
    );
  }
}

/** Charge le détail d'une conversation et déballe sa clé (jamais envoyée au serveur). */
async function ensureConversation(convId) {
  let detail = state.convDetails.get(convId);
  if (!detail) {
    detail = await api.getConversation(convId);
    state.convDetails.set(convId, detail);
  }
  if (!state.convKeys.has(convId)) {
    const key = await e2e.unwrapRoomKey(detail.wrapped_key, state.privateKey);
    state.convKeys.set(convId, key);
  }
  return detail;
}

async function selectConversation(convId) {
  state.currentConvId = convId;
  state.unread.delete(threadKey({ kind: 'conv', id: convId }));
  el.app.classList.remove('rail-open', 'members-open');
  el.app.classList.add('thread-dm');
  renderRoomList();
  renderConvList();
  try {
    await ensureConversation(convId);
    await loadLatestConv(convId);
  } catch (error) {
    reportError(error, "Impossible d'ouvrir cette conversation.");
    return;
  }
  if (state.currentConvId === convId) renderChat({ scroll: 'bottom' });
}

async function mergeConvPage(convId, page) {
  const convKey = state.convKeys.get(convId);
  const timeline = state.convTimelines.get(convId) ?? new Map();
  state.convTimelines.set(convId, timeline);
  for (const raw of page.messages) {
    // La crypto utilise `room_id` (AAD = fil:expéditeur) : on expose le fil sous le même nom côté client.
    const message = { ...raw, room_id: raw.conversation_id };
    if (!timeline.has(message.seq)) {
      timeline.set(message.seq, { message, ...(await decryptOrNull(convKey, message)) });
    }
  }
  return timeline;
}

async function loadLatestConv(convId) {
  const page = await api.conversationHistory(convId, undefined, HISTORY_PAGE_SIZE);
  const known = state.convTimelines.get(convId);
  const newest = known && known.size > 0 ? Math.max(...known.keys()) : 0;
  const gap = page.messages.length > 0 && page.messages[0].seq > newest + 1;
  if (!known || known.size === 0 || gap) {
    state.convTimelines.set(convId, new Map()); // trou dans l'historique : on repart de la page la plus récente
    state.convHasMore.set(convId, page.has_more);
  }
  await mergeConvPage(convId, page);
}

async function loadOlderConvMessages() {
  const convId = state.currentConvId;
  const timeline = state.convTimelines.get(convId);
  if (!timeline || timeline.size === 0) return;
  try {
    const page = await api.conversationHistory(convId, Math.min(...timeline.keys()), HISTORY_PAGE_SIZE);
    await mergeConvPage(convId, page);
    state.convHasMore.set(convId, page.has_more);
    if (state.currentConvId === convId) renderMessages({ scroll: 'preserve' });
  } catch (error) {
    reportError(error, "Impossible de charger les messages plus anciens.");
  }
}

async function openConversationWith(friend) {
  setRailTab('sessions');
  const existing = state.convs.find((conv) => conv.peer.id === friend.id);
  if (existing) {
    await selectConversation(existing.id);
    return;
  }
  try {
    const convKey = await e2e.generateRoomKey();
    const [wrappedKey, peerWrappedKey] = await Promise.all([
      e2e.wrapRoomKey(convKey, state.me.publicKey), // enveloppée pour nous seuls
      e2e.wrapRoomKey(convKey, friend.public_key), // et pour l'ami : seul son navigateur pourra l'ouvrir
    ]);
    const detail = await api.createConversation({
      username: friend.username,
      wrapped_key: wrappedKey,
      peer_wrapped_key: peerWrappedKey,
    });
    state.convKeys.set(detail.id, convKey);
    state.convDetails.set(detail.id, detail);
    state.convs = [...state.convs, { id: detail.id, created_at: detail.created_at, peer: detail.peer, member_count: 2 }];
    renderConvList();
    await selectConversation(detail.id);
  } catch (error) {
    if (error instanceof api.ApiError && error.status === 409) {
      await refreshConversations();
      const nowExisting = state.convs.find((conv) => conv.peer.id === friend.id);
      if (nowExisting) await selectConversation(nowExisting.id);
      else notify('La conversation existe déjà.', 'info');
    } else if (error instanceof api.ApiError && error.status === 403) {
      notify('Les conversations sont réservées aux amis.', 'error');
    } else reportError(error, "La conversation n'a pas pu être ouverte.");
  }
}

// ---------- Amis ----------

async function refreshFriends() {
  const [friends, requests] = await Promise.all([api.listFriends(), api.listFriendRequests()]);
  state.friends = friends;
  state.friendRequests = requests;
  renderFriendList();
  renderFriendRequests();
}

function renderFriendRequests() {
  clear(el.friendRequests);
  el.friendRequestsGroup.hidden = state.friendRequests.length === 0;
  for (const requester of state.friendRequests) {
    const name = requester.display_name || requester.username;
    el.friendRequests.append(
      h(
        'li',
        { class: 'friend-request' },
        h('span', { class: 'member-name' }, avatarThumb(requester, null), h('span', { class: 'member-id' }, name)),
        h(
          'span',
          { class: 'friend-actions' },
          h('button', { type: 'button', class: 'primary', onclick: () => void acceptRequest(requester) }, 'Accepter'),
          h('button', { type: 'button', class: 'link', onclick: () => void declineRequest(requester) }, 'Refuser'),
        ),
      ),
    );
  }
}

function renderFriendList() {
  clear(el.friendList);
  el.friendEmpty.hidden = state.friends.length > 0;
  for (const friend of state.friends) {
    const name = friend.display_name || friend.username;
    el.friendList.append(
      h(
        'li',
        { class: 'friend-row' },
        h(
          'button',
          { type: 'button', class: 'friend', title: `Ouvrir une conversation avec ${name}`, onclick: () => void openConversationWith(friend) },
          h(
            'span',
            { class: 'member-name' },
            avatarThumb(friend, null),
            h('span', { class: 'member-id' }, name),
          ),
        ),
        h('button', { type: 'button', class: 'link remove-item', title: `Retirer ${name} de vos amis`,
            onclick: (event) => { event.stopPropagation(); void removeFriend(friend); } },
            'Retirer'),
      ),
    );
  }
}

el.addFriendForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const username = el.addFriendName.value.trim().toLowerCase();
  if (!USERNAME_PATTERN.test(username)) {
    notify("Nom d'utilisateur invalide.", 'error');
    return;
  }
  try {
    await api.sendFriendRequest(username);
    el.addFriendName.value = '';
    notify(`Demande envoyée à ${username}.`);
  } catch (error) {
    if (error instanceof api.ApiError && error.status === 409) notify('Vous êtes déjà amis, ou la demande existe déjà.', 'error');
    else if (error instanceof api.ApiError && error.status === 404) notify('Utilisateur introuvable.', 'error');
    else reportError(error, "La demande n'a pas pu être envoyée.");
  }
});

async function acceptRequest(requester) {
  try {
    await api.acceptFriend(requester.username);
    await refreshFriends();
    notify(`Vous êtes maintenant ami(e)s avec ${requester.display_name || requester.username}.`);
  } catch (error) {
    reportError(error, "La demande n'a pas pu être acceptée.");
  }
}

async function declineRequest(requester) {
  try {
    await api.declineFriend(requester.username);
    state.friendRequests = state.friendRequests.filter((member) => member.id !== requester.id);
    renderFriendRequests();
    notify(`Demande de ${requester.display_name || requester.username} refusée.`);
  } catch (error) {
    reportError(error, "La demande n'a pas pu être refusée.");
  }
}

async function removeFriend(friend) {
  try {
    await api.removeFriend(friend.username);
    state.friends = state.friends.filter((member) => member.id !== friend.id);
    renderFriendList();
    notify(`${friend.display_name || friend.username} retiré(e) de vos amis.`);
  } catch (error) {
    reportError(error, "L'ami n'a pas pu être retiré.");
  }
}

function setRailTab(tab) {
  const sessions = tab === 'sessions';
  el.tabSessions.setAttribute('aria-selected', sessions ? 'true' : 'false');
  el.tabFriends.setAttribute('aria-selected', sessions ? 'false' : 'true');
  el.sessionsPanel.hidden = !sessions;
  el.friendsPanel.hidden = sessions;
}

el.tabSessions.addEventListener('click', () => setRailTab('sessions'));
el.tabFriends.addEventListener('click', () => setRailTab('friends'));

async function fillAvatars(roomId) {
  const detail = state.roomDetails.get(roomId);
  const roomKey = state.roomKeys.get(roomId);
  if (!detail || !roomKey) return;
  let decoded = state.avatars.get(roomId);
  if (!decoded) {
    decoded = new Map();
    state.avatars.set(roomId, decoded);
  }
  let changed = false;
  for (const member of detail.members) {
    if (decoded.has(member.id)) continue;
    const envelope = detail.avatars?.[member.id];
    if (!envelope) {
      decoded.set(member.id, null); // aucun avatar : on ne redemandera pas
      continue;
    }
    try {
      const bytes = new Uint8Array(
        await e2e.decryptBytes(roomKey, { ...envelope, room_id: roomId, sender_id: member.id }),
      );
      decoded.set(member.id, URL.createObjectURL(new Blob([bytes], { type: 'image/jpeg' })));
      changed = true;
    } catch {
      decoded.set(member.id, null); // avatar altéré ou clé modifiée
    }
  }
  if (changed && roomId === state.currentRoomId) renderMembers();
}

async function decryptOrNull(roomKey, message) {
  try {
    if (message.kind === 'text') return { text: await e2e.decryptMessage(roomKey, message) };
    const bytes = new Uint8Array(await e2e.decryptBytes(roomKey, message));
    const blob = new Blob([bytes], { type: message.mime ?? 'application/octet-stream' });
    return { media: { kind: message.kind, mime: blob.type, blob, url: URL.createObjectURL(blob) } };
  } catch {
    return null; // clé incorrecte ou message altéré
  }
}

async function mergePage(roomId, page) {
  const roomKey = state.roomKeys.get(roomId);
  const timeline = state.timelines.get(roomId) ?? new Map();
  state.timelines.set(roomId, timeline);
  for (const message of page.messages) {
    if (!timeline.has(message.seq)) {
      timeline.set(message.seq, { message, ...(await decryptOrNull(roomKey, message)) });
    }
  }
  return timeline;
}

async function loadLatest(roomId) {
  const page = await api.history(roomId, undefined, HISTORY_PAGE_SIZE);
  const known = state.timelines.get(roomId);
  const newest = known && known.size > 0 ? Math.max(...known.keys()) : 0;
  const gap = page.messages.length > 0 && page.messages[0].seq > newest + 1;
  if (!known || known.size === 0 || gap) {
    state.timelines.set(roomId, new Map()); // rien de connu, ou trou dans l'historique : on repart de la page la plus récente
    state.hasMore.set(roomId, page.has_more);
  }
  await mergePage(roomId, page);
}

async function loadOlderMessages() {
  const thread = currentThread();
  if (!thread) return;
  if (thread.kind === 'conv') {
    await loadOlderConvMessages();
    return;
  }
  const roomId = thread.id;
  const timeline = state.timelines.get(roomId);
  if (!timeline || timeline.size === 0) return;
  try {
    const page = await api.history(roomId, Math.min(...timeline.keys()), HISTORY_PAGE_SIZE);
    await mergePage(roomId, page);
    state.hasMore.set(roomId, page.has_more);
    if (state.currentRoomId === roomId) renderMessages({ scroll: 'preserve' });
  } catch (error) {
    reportError(error, "Impossible de charger les messages plus anciens.");
  }
}

el.createRoomForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const name = el.newRoomName.value.trim();
  if (!name) return;
  try {
    const roomKey = await e2e.generateRoomKey();
    const wrappedKey = await e2e.wrapRoomKey(roomKey, state.me.publicKey); // enveloppée pour nous seuls
    const room = await api.createRoom({ name, wrapped_key: wrappedKey });
    state.roomKeys.set(room.id, roomKey);
    el.newRoomName.value = '';
    await refreshRooms();
    await selectRoom(room.id);
  } catch (error) {
    if (error instanceof api.ApiError && error.status === 422) {
      notify('Nom de salon invalide : 50 caractères maximum, sans < ni >.', 'error');
    } else reportError(error, "Le salon n'a pas pu être créé.");
  }
});

// ---------- Membres ----------

async function fingerprintOf(publicKey) {
  if (!state.fingerprints.has(publicKey)) state.fingerprints.set(publicKey, await e2e.fingerprint(publicKey));
  return state.fingerprints.get(publicKey);
}

let memberRenderId = 0;

async function renderMembers() {
  const renderId = (memberRenderId += 1);
  const detail = state.roomDetails.get(state.currentRoomId);
  if (!detail) {
    clear(el.memberList);
    el.addMemberForm.hidden = true;
    el.memberCount.textContent = '';
    return;
  }

  const prints = await Promise.all(detail.members.map((member) => fingerprintOf(member.public_key)));
  if (renderId !== memberRenderId) return; // un rendu plus récent (autre salon, membre ajouté…) a pris le relais

  const decoded = state.avatars.get(state.currentRoomId) ?? new Map();
  const items = detail.members.map((member, index) => {
    const role = detail.roles?.[member.id];
    return h(
      'li',
      {},
      h(
        'span',
        { class: 'member-name' },
        avatarThumb(member, decoded.get(member.id)),
        h(
          'span',
          { class: 'member-id', title: 'Nom d\'utilisateur' },
          `${member.display_name || member.username}${member.id === state.me.id ? ' (vous)' : ''}`,
        ),
        detail.online?.[member.id]
          ? h('span', { class: 'presence', title: 'En ligne' }, 'en ligne')
          : h('span', { class: 'presence offline', title: 'Hors ligne' }, 'hors ligne'),
        member.id === detail.owner_id
          ? h('span', { class: 'tag' }, 'chef', h('span', { class: 'sr-only' }, ' (propriétaire)'))
          : role === ROLE_CO
            ? h('span', { class: 'tag' }, 'sous-chef')
            : null,
      ),
      h('code', { class: 'print', title: 'Empreinte de la clé publique' }, prints[index]),
      member.id === state.me.id
        ? null
        : h(
            'button',
            {
              type: 'button',
              class: 'link call',
              onclick: () => callMember(member, detail.online?.[member.id]),
            },
            'Appel vocal',
          ),
      detail.owner_id === state.me.id && member.id !== state.me.id ? roleField(member, role ?? 'member') : null,
    );
  });
  el.memberList.replaceChildren(...items); // remplacement atomique : jamais de doublons
  el.memberCount.textContent = String(detail.members.length);
  el.addMemberForm.hidden = detail.owner_id !== state.me.id && roleOf(detail, state.me.id) !== ROLE_CO;
}

/** Grade d'un membre dans un salon (défaut : membre). */
function roleOf(detail, memberId) {
  return detail.roles?.[memberId] ?? (memberId === detail.owner_id ? ROLE_OWNER : ROLE_MEMBER);
}

/** Sélecteur de grade (sous-chef ↔ membre), réservé au chef du salon. */
function roleField(member, role) {
  return h(
    'label',
    { class: 'role-field' },
    'Grade ',
    h(
      'select',
      {
        class: 'role',
        'aria-label': `Grade de ${member.username}`,
        onchange: (event) => void changeRole(member, event.target.value),
      },
      h('option', { value: ROLE_MEMBER, selected: role === ROLE_MEMBER ? true : null }, 'Membre'),
      h('option', { value: ROLE_CO, selected: role === ROLE_CO ? true : null }, 'Sous-chef'),
    ),
  );
}

async function changeRole(member, role) {
  const roomId = state.currentRoomId;
  if (!roomId) return;
  try {
    await api.setRole(roomId, { username: member.username, role });
    const detail = state.roomDetails.get(roomId);
    if (detail) state.roomDetails.set(roomId, { ...detail, roles: { ...(detail.roles ?? {}), [member.id]: role } });
    await renderMembers();
    notify(`${member.display_name || member.username} est maintenant ${role === ROLE_CO ? 'sous-chef' : 'membre'}.`);
  } catch (error) {
    reportError(error, "Le grade n'a pas pu être modifié.");
  }
}

function avatarThumb(member, url) {
  if (url) return h('img', { src: url, class: 'avatar thumb', alt: '' });
  const initial = (member.display_name || member.username).charAt(0).toUpperCase();
  return h('span', { class: 'avatar thumb mono', 'aria-label': `Avatar de ${member.username}` }, initial);
}

el.addMemberForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const roomId = state.currentRoomId;
  const username = el.addMemberName.value.trim().toLowerCase();
  const roomKey = state.roomKeys.get(roomId);
  if (!roomId || !roomKey || !USERNAME_PATTERN.test(username)) {
    notify("Nom d'utilisateur invalide.", 'error');
    return;
  }
  try {
    const target = await api.getUser(username);
    const wrappedKey = await e2e.wrapRoomKey(roomKey, target.public_key); // seul le nouveau membre pourra l'ouvrir
    await api.addMember(roomId, { username: target.username, wrapped_key: wrappedKey });
    el.addMemberName.value = '';
    state.roomDetails.delete(roomId);
    await ensureRoom(roomId);
    await Promise.all([refreshRooms(), state.currentRoomId === roomId ? renderMembers() : null]);
    notify(`${target.username} a rejoint le salon.`);
  } catch (error) {
    if (error instanceof api.ApiError && error.status === 404) notify('Utilisateur introuvable.', 'error');
    else if (error instanceof api.ApiError && error.status === 409) notify('Cet utilisateur est déjà dans le salon.', 'error');
    else reportError(error, "Le membre n'a pas pu être ajouté.");
  }
});

// ---------- Messages ----------

function sameDay(first, second) {
  return first.toDateString() === second.toDateString();
}

/** Brève animation « déchiffrement » pour un message reçu en direct ; le texte final est toujours le vrai. */
function reveal(element, text) {
  if (prefersReducedMotion()) return;
  const characters = Array.from(text);
  const paint = (frame) => {
    const resolved = Math.floor((characters.length * frame) / REVEAL_FRAMES);
    element.textContent = characters
      .map((character, index) =>
        index < resolved || /\s/.test(character)
          ? character
          : REVEAL_GLYPHS[Math.floor(Math.random() * REVEAL_GLYPHS.length)],
      )
      .join('');
  };
  let frame = 0;
  paint(frame);
  const timer = setInterval(() => {
    frame += 1;
    if (frame >= REVEAL_FRAMES) {
      clearInterval(timer);
      element.textContent = text;
    } else paint(frame);
  }, 30);
}

function messageBody(message, text, media) {
  if (text !== null && text !== undefined) {
    return h('p', { class: `body${text === null ? ' undecryptable' : ''}` }, text);
  }
  if (media) {
    if (media.kind === 'image') {
      return h(
        'p',
        { class: 'body media' },
        h('img', { src: media.url, class: 'media-img', alt: 'Image chiffrée partagée dans ce salon', loading: 'lazy' }),
      );
    }
    if (media.kind === 'voice') {
      return h('audio', { class: 'voice', src: media.url, controls: true, preload: 'metadata' });
    }
    return h('p', { class: 'body' }, 'Média reçu (type inconnu).');
  }
  return h(
    'p',
    { class: 'body undecryptable' },
    'Média indéchiffrable : clé du salon incorrecte ou contenu altéré.',
  );
}

/** Libère les URL d'objets créées pour les médias et avatars d'une session. */
function revokeAllMedia(...collections) {
  for (const map of collections) {
    if (!map) continue;
    for (const inner of map.values()) {
      if (inner instanceof Map) {
        for (const url of inner.values()) if (url) URL.revokeObjectURL(url);
      } else if (inner?.media?.url) URL.revokeObjectURL(inner.media.url);
    }
  }
}

function renderMessages({ animateSeq, scroll = 'auto' } = {}) {
  const thread = currentThread();
  const threadId = thread?.id;
  if (!threadId) return;
  const isConv = thread.kind === 'conv';
  const container = el.messages;
  const timelines = isConv ? state.convTimelines : state.timelines;
  const hasMore = isConv ? state.convHasMore : state.hasMore;
  const previousHeight = container.scrollHeight;
  const previousTop = container.scrollTop;
  const nearBottom = container.scrollHeight - container.scrollTop - container.clientHeight < NEAR_BOTTOM_PX;

  clear(container);
  const entries = [...(timelines.get(threadId)?.values() ?? [])].sort((a, b) => a.message.seq - b.message.seq);

  if (hasMore.get(threadId)) {
    container.append(h('button', { type: 'button', class: 'link older', onclick: loadOlderMessages }, 'Afficher les messages précédents'));
  }
  if (entries.length === 0) {
    container.append(h('p', { class: 'empty' }, 'Aucun message pour l\'instant. Écrivez le premier : il sera chiffré avant de quitter votre navigateur.'));
    return;
  }

  let previous = null;
  for (const { message, text, media } of entries) {
    const date = new Date(message.created_at);
    const previousDate = previous ? new Date(previous.created_at) : null;
    if (!previousDate || !sameDay(previousDate, date)) container.append(h('div', { class: 'day' }, dayFormat.format(date)));

    const continuing =
      previous !== null &&
      previous.sender_id === message.sender_id &&
      sameDay(previousDate, date) &&
      date - previousDate < GROUP_WINDOW_MS;
    const body = messageBody(message, text, media);
    container.append(
      continuing
        ? h('article', { class: 'msg continued' }, body)
        : h(
            'article',
            { class: `msg${message.sender_id === state.me.id ? ' mine' : ''}` },
            h(
              'header',
              {},
              h('span', { class: 'author' }, message.sender_username),
              h('time', { datetime: message.created_at }, timeFormat.format(date)),
            ),
            body,
          ),
    );
    if (message.seq === animateSeq && text !== null && text !== undefined) reveal(body, text);
    previous = message;
  }

  if (scroll === 'bottom' || (scroll === 'auto' && nearBottom)) container.scrollTop = container.scrollHeight;
  else if (scroll === 'preserve') container.scrollTop = container.scrollHeight - previousHeight + previousTop;
}

function renderChat({ scroll = 'bottom' } = {}) {
  const thread = currentThread();
  const ready = Boolean(thread);
  let title = 'Aucun salon sélectionné';
  if (thread?.kind === 'conv') {
    const conv = state.convs.find((candidate) => candidate.id === thread.id);
    if (conv) title = conv.peer.display_name || conv.peer.username;
  } else if (thread) {
    const room = state.rooms.find((candidate) => candidate.id === thread.id);
    if (room) title = room.name;
  }
  el.roomTitle.textContent = title;
  el.e2eBadge.hidden = !ready;
  el.composerInput.disabled = !ready;
  el.composerSend.disabled = !ready;
  el.fileImage.disabled = !ready;
  el.btnVoice.disabled = !ready || recordingLive();
  renderRoomList();
  renderConvList();
  if (!ready) {
    clear(el.messages);
    el.messages.append(h('p', { class: 'empty' }, 'Choisissez un salon ou une conversation dans la liste.'));
    renderMembers();
    return;
  }
  renderMessages({ scroll });
  renderMembers();
  el.composerInput.focus();
}

function markUnread(roomId) {
  if (roomId === state.currentRoomId) return;
  state.unread.add(roomId);
  renderRoomList();
}

function markUnreadConv(convId) {
  if (convId === state.currentConvId) return;
  state.unread.add(threadKey({ kind: 'conv', id: convId }));
  renderConvList();
}

async function handleIncomingMessage(rawMessage, { own = false } = {}) {
  // Une conversation expose `conversation_id` ; la crypto lit `room_id` (AAD = fil:expéditeur).
  const message = rawMessage.conversation_id === undefined ? rawMessage : { ...rawMessage, room_id: rawMessage.conversation_id };
  const isConv = message.conversation_id !== undefined;
  const threadId = message.room_id;
  const roomKey = isConv ? state.convKeys.get(threadId) : state.roomKeys.get(threadId);
  const timeline = isConv ? state.convTimelines.get(threadId) : state.timelines.get(threadId);
  if (!roomKey || !timeline) {
    if (isConv) markUnreadConv(threadId);
    else markUnread(threadId); // fil jamais ouvert : l'historique sera chargé à l'ouverture
    return;
  }
  if (timeline.has(message.seq)) return; // déjà reçu (réponse HTTP puis WebSocket)

  const entry = await decryptOrNull(roomKey, message);
  timeline.set(message.seq, { message, ...entry });
  if (threadId !== (isConv ? state.currentConvId : state.currentRoomId)) {
    if (isConv) markUnreadConv(threadId);
    else markUnread(threadId);
    return;
  }
  renderMessages({ animateSeq: own ? undefined : message.seq, scroll: own ? 'bottom' : 'auto' });
  if (!own && entry) {
    const label = entry.text !== undefined ? entry.text : entry.media?.kind === 'image' ? 'une image chiffrée' : 'un message vocal chiffré';
    announce(`${message.sender_username} : ${label}`);
  }
}

let sending = false;

el.composer.addEventListener('submit', async (event) => {
  event.preventDefault();
  const thread = currentThread();
  const text = el.composerInput.value.trim();
  if (!thread || !text || sending) return;
  if (Array.from(text).length > MAX_MESSAGE_CHARS) {
    notify(`Message trop long : ${MAX_MESSAGE_CHARS} caractères maximum.`, 'error');
    return;
  }
  sending = true;
  try {
    const isConv = thread.kind === 'conv';
    const key = isConv ? state.convKeys.get(thread.id) : state.roomKeys.get(thread.id);
    const payload = await e2e.encryptMessage(key, text, thread.id, state.me.id);
    const message = isConv
      ? await api.sendConversationMessage(thread.id, payload)
      : await api.sendMessage(thread.id, payload);
    el.composerInput.value = '';
    resizeComposer();
    await handleIncomingMessage(message, { own: true });
  } catch (error) {
    reportError(error, "Le message n'a pas pu être envoyé.");
  } finally {
    sending = false;
  }
});

function resizeComposer() {
  el.composerInput.style.height = 'auto';
  el.composerInput.style.height = `${Math.min(el.composerInput.scrollHeight, 160)}px`;
}

el.composerInput.addEventListener('input', resizeComposer);
el.composerInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    el.composer.requestSubmit();
  }
});

// ---------- Médias (images, messages vocaux) ----------

function recordingLive() {
  return Boolean(state.recorder);
}

el.fileImage.addEventListener('change', () => {
  const file = el.fileImage.files?.[0];
  el.fileImage.value = '';
  if (file) void sendImage(file);
});

async function sendImage(file) {
  let blob = file;
  if (!ALLOWED_IMAGE_TYPES.has(file.type) || file.size >= MAX_MEDIA_BYTES) {
    if (file.size > MAX_IMAGE_BYTES) {
      notify('Image trop volumineuse : choisissez une image de moins de 8 Mo.', 'error');
      return;
    }
    blob = await reencodeImage(file);
    if (!blob) return;
  }
  if (blob.size > MAX_MEDIA_BYTES) {
    notify('Image trop volumineuse : 2 Mo de contenu chiffré maximum.', 'error');
    return;
  }
  await sendMedia('image', blob.type || 'image/jpeg', new Uint8Array(await blob.arrayBuffer()));
}

/** Ré-encode une image trop grosse ou d'un type non pris en charge en JPEG (via canvas). */
async function reencodeImage(file) {
  try {
    const bitmap = await createImageBitmap(file);
    const scale = Math.min(1, 1920 / Math.max(bitmap.width, bitmap.height));
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(bitmap.width * scale));
    canvas.height = Math.max(1, Math.round(bitmap.height * scale));
    canvas.getContext('2d').drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    bitmap.close?.();
    return new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', 0.85));
  } catch (error) {
    console.error(error);
    notify("Cette image n'a pas pu être traitée.", 'error');
    return null;
  }
}

async function sendMedia(kind, mime, bytes) {
  const thread = currentThread();
  if (!thread) return;
  const isConv = thread.kind === 'conv';
  const key = isConv ? state.convKeys.get(thread.id) : state.roomKeys.get(thread.id);
  if (!key || bytes.length === 0 || sending) return;
  sending = true;
  try {
    const payload = await e2e.encryptBytes(key, bytes, thread.id, state.me.id);
    const message = isConv
      ? await api.sendConversationMessage(thread.id, { kind, mime, ...payload })
      : await api.sendMessage(thread.id, { kind, mime, ...payload });
    await handleIncomingMessage(message, { own: true });
  } catch (error) {
    if (error instanceof api.ApiError && error.status === 422) notify('Média trop volumineux pour le serveur.', 'error');
    else reportError(error, "Le média n'a pas pu être envoyé.");
  } finally {
    sending = false;
  }
}

el.btnVoice.addEventListener('click', () => void toggleRecording());

async function toggleRecording() {
  if (state.recorder) {
    stopRecording();
    return;
  }
  const thread = currentThread();
  if (!thread) return;
  const key = thread.kind === 'conv' ? state.convKeys.get(thread.id) : state.roomKeys.get(thread.id);
  if (!key) return;
  if (!navigator.mediaDevices?.getUserMedia) {
    notify("Ce navigateur ne peut pas enregistrer de message vocal.", 'error');
    return;
  }
  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch {
    notify("Micro inaccessible : vérifiez l'autorisation.", 'error');
    return;
  }
  const chunks = [];
  const mediaRecorder = new MediaRecorder(stream);
  const recorder = { mediaRecorder, stream, chunks, timeoutId: null };
  state.recorder = recorder;
  state.recordingStartedAt = Date.now();
  mediaRecorder.addEventListener('dataavailable', (event) => {
    if (event.data.size > 0) recorder.chunks.push(event.data);
  });
  mediaRecorder.addEventListener('stop', async () => {
    clearTimeout(recorder.timeoutId);
    stream.getTracks().forEach((track) => track.stop());
    const elapsed = Date.now() - state.recordingStartedAt;
    const mime = recorder.chunks.map((chunk) => chunk.type).find(Boolean) ?? 'audio/webm';
    const blob = new Blob(recorder.chunks, { type: mime });
    if (state.recorder === recorder) state.recorder = null;
    resetVoiceUI();
    if (elapsed < MIN_VOICE_MS) {
      notify('Message trop court : maintenez le bouton pour enregistrer.', 'info');
      return;
    }
    void sendMedia('voice', blob.type || 'audio/webm', new Uint8Array(await blob.arrayBuffer()));
  });
  mediaRecorder.start();
  el.btnVoice.classList.add('recording');
  el.btnVoice.textContent = "Arrêter l'enregistrement";
  recorder.timeoutId = setTimeout(() => stopRecording(), MAX_VOICE_MS);
  startVoiceTimer();
}

let voiceTimer = null;

function startVoiceTimer() {
  clearInterval(voiceTimer);
  voiceTimer = setInterval(() => {
    if (!state.recorder) {
      clearInterval(voiceTimer);
      return;
    }
    const elapsed = Math.round((Date.now() - state.recordingStartedAt) / 1000);
    const minutes = String(Math.floor(elapsed / 60)).padStart(2, '0');
    const seconds = String(elapsed % 60).padStart(2, '0');
    el.voiceStatus.hidden = false;
    el.voiceStatus.textContent = `Enregistrement ${minutes}:${seconds}`;
  }, 250);
}

function resetVoiceUI() {
  el.btnVoice.classList.remove('recording');
  el.btnVoice.textContent = 'Message vocal';
  el.voiceStatus.hidden = true;
  el.voiceStatus.textContent = '';
  clearInterval(voiceTimer);
}

function stopRecording() {
  state.recorder?.mediaRecorder.stop();
}

// ---------- Profil et avatar ----------

let pendingAvatarBlob = null;

function updateOwnAvatar(url) {
  el.meAvatar.replaceChildren();
  el.meAvatar.classList.toggle('mono', !url);
  if (url) {
    el.meAvatar.append(h('img', { src: url, class: 'avatar img', alt: '' }));
  } else {
    el.meAvatar.textContent = (state.me?.displayName || state.me?.username || '?').charAt(0).toUpperCase();
  }
}

el.btnProfile.addEventListener('click', () => {
  el.profileName.value = state.me?.displayName || state.me?.username || '';
  el.profileBio.value = state.me?.bio || '';
  el.profileError.hidden = true;
  el.profilePreview.hidden = true;
  el.profilePreview.removeAttribute('src');
  pendingAvatarBlob = null;
  el.profileDialog.showModal();
});

el.profileCancel.addEventListener('click', () => el.profileDialog.close());

el.profileAvatar.addEventListener('change', () => {
  const file = el.profileAvatar.files?.[0];
  if (!file) return;
  if (!ALLOWED_IMAGE_TYPES.has(file.type)) {
    el.profileError.textContent = 'Format non pris en charge : PNG, JPEG, WebP ou GIF.';
    el.profileError.hidden = false;
    return;
  }
  if (file.size > MAX_IMAGE_BYTES) {
    el.profileError.textContent = 'Image trop volumineuse (8 Mo maximum).';
    el.profileError.hidden = false;
    return;
  }
  el.profileError.hidden = true;
  void renderProfilePreview(file);
});

async function renderProfilePreview(file) {
  try {
    const blob = await makeAvatar(file);
    el.profilePreview.src = URL.createObjectURL(blob);
    el.profilePreview.hidden = false;
    pendingAvatarBlob = blob;
  } catch (error) {
    console.error(error);
    el.profileError.textContent = "Cette image n'a pas pu être traitée.";
    el.profileError.hidden = false;
  }
}

el.profileForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const save = el.profileSave;
  const displayName = el.profileName.value.trim() || state.me.username;
  const bio = el.profileBio.value.trim();
  save.disabled = true;
  try {
    const updated = await api.updateProfile({ display_name: displayName, bio });
    state.me.displayName = updated.display_name;
    state.me.bio = updated.bio;
    for (const detail of state.roomDetails.values()) {
      const own = detail.members.find((member) => member.id === state.me.id);
      if (own) own.display_name = displayName;
    }
    el.meName.textContent = displayName;
    if (state.currentRoomId) renderMembers();
    const preview = el.profilePreview;
    const avatar = pendingAvatarBlob;
    pendingAvatarBlob = null;
    if (!preview.hidden && avatar) {
      await uploadAvatar(new Blob([await avatar.arrayBuffer()], { type: 'image/jpeg' }));
    }
    notify('Profil enregistré.');
    el.profileDialog.close();
  } catch (error) {
    el.profileError.textContent =
      error instanceof api.ApiError && error.status === 422 ? 'Saisie invalide (surnom 32 caractères, biographie 200).' : 'Enregistrement impossible, réessayez.';
    el.profileError.hidden = false;
  } finally {
    save.disabled = false;
  }
});

async function makeAvatar(file) {
  const bitmap = await createImageBitmap(file);
  const canvas = document.createElement('canvas');
  canvas.width = AVATAR_SIZE;
  canvas.height = AVATAR_SIZE;
  const ctx = canvas.getContext('2d');
  const ratio = Math.max(AVATAR_SIZE / bitmap.width, AVATAR_SIZE / bitmap.height);
  const width = Math.round(bitmap.width * ratio);
  const height = Math.round(bitmap.height * ratio);
  ctx.drawImage(bitmap, Math.round((AVATAR_SIZE - width) / 2), Math.round((AVATAR_SIZE - height) / 2), width, height);
  bitmap.close?.();
  return new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', 0.85));
}

/** Chiffre et envoie l'avatar pour CHAQUE salon : il est déchiffrable par chaque membre. */
async function uploadAvatar(blob) {
  if (blob.size > MAX_MEDIA_BYTES) {
    notify('Avatar trop volumineux après recadrage.', 'error');
    return;
  }
  const bytes = new Uint8Array(await blob.arrayBuffer());
  notify('Chiffrement de votre avatar pour chaque salon…');
  let updated = 0;
  for (const room of [...state.roomKeys.keys()]) {
    try {
      await ensureRoom(room);
      const roomKey = state.roomKeys.get(room);
      if (!roomKey) continue;
      const payload = await e2e.encryptBytes(roomKey, bytes, room, state.me.id);
      await api.setAvatar(room, payload);
      const detail = state.roomDetails.get(room);
      if (detail) detail.avatars = { ...(detail.avatars ?? {}), [state.me.id]: payload };
      const decoded = state.avatars.get(room) ?? new Map();
      decoded.set(state.me.id, URL.createObjectURL(new Blob([bytes], { type: 'image/jpeg' })));
      state.avatars.set(room, decoded);
      updated += 1;
    } catch (error) {
      console.error(error);
    }
  }
  updateOwnAvatar(URL.createObjectURL(new Blob([bytes], { type: 'image/jpeg' })));
  if (updated > 0 && state.currentRoomId) renderMembers();
  notify(updated > 0 ? `Avatar chiffré dans ${updated} salon(s).` : 'Aucun salon : l\'avatar sera partagé au prochain salon.');
}

// ---------- Temps réel (WebSocket) ----------

function setConnection(status) {
  el.connStatus.dataset.state = status;
  el.connStatus.textContent = status === 'online' ? 'En direct' : 'Reconnexion…';
}

function connectSocket() {
  if (!state.loggedIn) return;
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const socket = new WebSocket(`${protocol}//${location.host}/ws`);
  state.socket = socket;

  socket.addEventListener('open', () => {
    state.reconnectAttempt = 0;
    setConnection('online');
    if (state.everConnected) resync().catch((error) => reportError(error));
    state.everConnected = true;
  });
  socket.addEventListener('message', (event) => {
    let payload;
    try {
      payload = JSON.parse(event.data);
    } catch {
      return;
    }
    switch (payload.type) {
      case 'message':
        handleIncomingMessage(payload.message).catch((error) => reportError(error));
        break;
      case 'dm':
        handleIncomingMessage(payload.message).catch((error) => reportError(error));
        break;
      case 'member_added':
        handleMemberAdded(payload).catch((error) => reportError(error));
        break;
      case 'presence':
        handlePresence(payload);
        break;
      case 'presence_dm':
        handleConvPresence(payload);
        break;
      case 'friend_request':
        handleFriendRequest(payload).catch((error) => reportError(error));
        break;
      case 'friend_accepted':
        handleFriendAccepted(payload).catch((error) => reportError(error));
        break;
      case 'friend_declined':
        handleFriendDeclined(payload);
        break;
      case 'role_changed':
        handleRoleChanged(payload).catch((error) => reportError(error));
        break;
      case 'call_offer':
        void onIncomingCall(payload);
        break;
      case 'call_answer':
        void onCallAnswer(payload);
        break;
      case 'ice_candidate':
        void onIce(payload);
        break;
      case 'call_end':
        onRemoteEnd(payload);
        break;
      case 'call_unreachable':
        onUnreachable(payload);
        break;
      case 'signal_error':
        notify('Appel refusé : il faut partager un salon avec votre correspondant.', 'error');
        break;
      default:
        break;
    }
  });
  socket.addEventListener('close', () => {
    if (state.socket !== socket) return; // fermeture volontaire (déconnexion)
    state.socket = null;
    setConnection('offline');
    scheduleReconnect();
  });
}

function scheduleReconnect() {
  if (!state.loggedIn) return;
  const delay = RECONNECT_DELAYS_MS[Math.min(state.reconnectAttempt, RECONNECT_DELAYS_MS.length - 1)];
  state.reconnectAttempt += 1;
  state.reconnectTimer = setTimeout(async () => {
    try {
      await api.me(); // détecte une session expirée (401 → retour à la connexion)
    } catch (error) {
      if (error instanceof api.ApiError && error.status === 401) return;
    }
    connectSocket();
  }, delay);
}

/** Après une coupure : rattrape les messages manqués du fil ouvert. */
async function resync() {
  await Promise.all([refreshRooms(), refreshConversations(), refreshFriends()]);
  const thread = currentThread();
  if (!thread) return;
  if (thread.kind === 'conv') {
    if (!state.convKeys.has(thread.id)) return;
    await loadLatestConv(thread.id);
    if (state.currentConvId === thread.id) renderMessages({ scroll: 'auto' });
  } else {
    if (!state.roomKeys.has(thread.id)) return;
    await loadLatest(thread.id);
    if (state.currentRoomId === thread.id) renderMessages({ scroll: 'auto' });
  }
}

async function handleMemberAdded({ room_id: roomId, user }) {
  state.roomDetails.delete(roomId);
  await refreshRooms();
  if (user.id === state.me.id) {
    markUnread(roomId);
    notify('Vous avez été ajouté(e) à un nouveau salon.');
  }
  if (roomId === state.currentRoomId) {
    await ensureRoom(roomId);
    await renderMembers();
  }
}

function handleConvPresence({ user_id: userId, online }) {
  state.convOnline.set(userId, online);
  renderConvList();
}

async function handleFriendRequest({ from }) {
  await refreshFriends();
  const name = from.display_name || from.username;
  notify(`${name} souhaite devenir votre ami.`);
  announce(`Demande d'ami de ${name}`);
}

async function handleFriendAccepted({ user }) {
  if (user.id === state.me.id) return;
  await refreshFriends();
  const name = user.display_name || user.username;
  notify(`Vous êtes maintenant ami(e)s avec ${name}.`);
  announce(`Vous êtes ami(e)s avec ${name}`);
}

function handleFriendDeclined({ user }) {
  const name = user.display_name || user.username;
  notify(`${name} a refusé votre demande d'ami.`);
}

async function handleRoleChanged({ room_id: roomId, user, role }) {
  const detail = state.roomDetails.get(roomId);
  if (detail) {
    state.roomDetails.set(roomId, { ...detail, roles: { ...(detail.roles ?? {}), [user.id]: role } });
    if (roomId === state.currentRoomId) await renderMembers();
  }
}

// ---------- Appels vocaux (WebRTC) ----------

function wsSend(payload) {
  if (state.socket && state.socket.readyState === WebSocket.OPEN) {
    state.socket.send(JSON.stringify(payload));
    return true;
  }
  return false;
}

function handlePresence({ room_id: roomId, user_id: userId, online }) {
  const detail = state.roomDetails.get(roomId);
  if (detail) detail.online = { ...(detail.online ?? {}), [userId]: online };
  if (roomId === state.currentRoomId) renderMembers();
  if (state.call?.peerId === userId && !online) teardownCall({ reason: 'Votre correspondant a quitté : appel terminé.' });
  if (state.incoming?.id === userId && !online) hideIncomingView();
}

async function callMember(member, online) {
  if (state.call) {
    notify('Un appel est déjà en cours.', 'error');
    return;
  }
  if (!navigator.mediaDevices?.getUserMedia) {
    notify("Ce navigateur ne peut pas passer d'appel vocal.", 'error');
    return;
  }
  notify(online ? `Appel de ${member.display_name || member.username}…` : `${member.display_name || member.username} est hors ligne : l'appel sera sans réponse.`, 'info');
  try {
    const localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const pc = new RTCPeerConnection(RTC_CONFIG);
    localStream.getTracks().forEach((track) => pc.addTrack(track, localStream));
    setupPeerSession(pc, member.id);
    state.call = {
      peerId: member.id,
      peerName: member.display_name || member.username,
      pc,
      localStream,
      remoteStream: null,
      state: 'dialing',
      muted: false,
    };
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    showCallView('dialing');
    if (!wsSend({ type: 'call_offer', to: member.id, sdp: pc.localDescription })) {
      teardownCall({ reason: 'Connexion au serveur perdue : reconnexion en cours…' });
    }
  } catch (error) {
    console.error(error);
    notify("Impossible de démarrer l'appel (micro ou réseau).", 'error');
    teardownCall({ silent: true, sendSignal: false });
  }
}

function setupPeerSession(pc, peerId) {
  pc.onicecandidate = ({ candidate }) => {
    if (candidate) wsSend({ type: 'ice_candidate', to: peerId, candidate });
  };
  pc.ontrack = ({ streams }) => {
    const call = state.call;
    if (!call || call.peerId !== peerId) return;
    call.remoteStream = streams[0];
    el.callRemote.srcObject = streams[0];
    el.callRemote.hidden = false;
    el.callRemote.play().catch(() => {});
  };
  pc.onconnectionstatechange = () => {
    if (state.call?.peerId === peerId && ['failed', 'closed', 'disconnected'].includes(pc.connectionState)) {
      teardownCall({ reason: 'Connexion audio interrompue.' });
    }
  };
}

async function onIncomingCall({ from, from_username, sdp }) {
  if (state.call) {
    wsSend({ type: 'call_end', to: from }); // occupé : on refuse poliment
    return;
  }
  state.incoming = { id: from, name: from_username || 'un membre du salon', offer: sdp };
  el.callPeer.textContent = state.incoming.name;
  el.callState.textContent = 'Appel vocal entrant…';
  el.callAccept.hidden = false;
  el.callDecline.hidden = false;
  el.callMute.hidden = true;
  el.callEnd.hidden = true;
  el.callView.hidden = false;
  announce(`Appel vocal entrant de ${state.incoming.name}`);
}

function hideIncomingView() {
  state.incoming = null;
  el.callAccept.hidden = true;
  el.callDecline.hidden = true;
  el.callEnd.hidden = false;
  el.callView.hidden = true;
}

function showCallView(mode) {
  const call = state.call;
  if (!call) return;
  el.callPeer.textContent = call.peerName;
  el.callState.textContent = mode === 'incall' ? 'Appel en cours' : 'Appel en cours…';
  el.callAccept.hidden = true;
  el.callDecline.hidden = true;
  el.callMute.hidden = mode !== 'incall';
  el.callEnd.hidden = false;
  el.callView.hidden = false;
}

async function acceptCall() {
  const incoming = state.incoming;
  if (!incoming) return;
  try {
    const localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const pc = new RTCPeerConnection(RTC_CONFIG);
    localStream.getTracks().forEach((track) => pc.addTrack(track, localStream));
    setupPeerSession(pc, incoming.id);
    state.call = {
      peerId: incoming.id,
      peerName: incoming.name,
      pc,
      localStream,
      remoteStream: null,
      state: 'incall',
      muted: false,
    };
    state.incoming = null;
    await pc.setRemoteDescription(incoming.offer);
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    showCallView('incall');
    wsSend({ type: 'call_answer', to: incoming.id, sdp: pc.localDescription });
  } catch (error) {
    console.error(error);
    teardownCall({ reason: "Impossible d'accepter l'appel (micro ou réseau)." });
  }
}

function declineCall() {
  const incoming = state.incoming;
  if (incoming) wsSend({ type: 'call_end', to: incoming.id });
  hideIncomingView();
}

async function onCallAnswer({ from, sdp }) {
  const call = state.call;
  if (!call || call.peerId !== from || call.state !== 'dialing') return;
  try {
    await call.pc.setRemoteDescription(sdp);
    call.state = 'incall';
    showCallView('incall');
  } catch (error) {
    console.error(error);
    teardownCall({ reason: 'Réponse d\u2019appel invalide.' });
  }
}

async function onIce({ from, candidate }) {
  const call = state.call;
  if (!call || call.peerId !== from) return;
  try {
    await call.pc.addIceCandidate(candidate);
  } catch (error) {
    console.error(error);
  }
}

function onRemoteEnd({ from }) {
  if (state.call?.peerId === from) teardownCall({ reason: 'Votre correspondant a raccroché.' });
  if (state.incoming?.id === from) hideIncomingView();
}

function onUnreachable({ to_username }) {
  const name = to_username || 'votre correspondant';
  teardownCall({ reason: `${name} n'est pas joignable pour le moment.` });
}

function teardownCall({ reason = '', silent = false, sendSignal = true } = {}) {
  const call = state.call;
  state.incoming = null;
  if (call) {
    if (sendSignal && state.loggedIn) wsSend({ type: 'call_end', to: call.peerId });
    call.pc.onicecandidate = null;
    call.pc.ontrack = null;
    call.pc.onconnectionstatechange = null;
    call.pc.close();
    call.localStream?.getTracks().forEach((track) => track.stop());
    call.remoteStream?.getTracks().forEach((track) => track.stop());
    state.call = null;
  }
  el.callRemote.srcObject = null;
  el.callRemote.hidden = true;
  el.callView.hidden = true;
  el.callAccept.hidden = true;
  el.callDecline.hidden = true;
  el.callMute.hidden = true;
  el.callEnd.hidden = false;
  if (reason && !silent) notify(reason, 'info');
}

el.callAccept.addEventListener('click', () => void acceptCall());
el.callDecline.addEventListener('click', declineCall);
el.callEnd.addEventListener('click', () => teardownCall({ reason: 'Appel terminé.' }));
el.callMute.addEventListener('click', () => {
  const call = state.call;
  if (!call) return;
  call.muted = !call.muted;
  el.callMute.textContent = call.muted ? 'Réactiver le micro' : 'Couper le micro';
  call.localStream?.getAudioTracks().forEach((track) => {
    track.enabled = !call.muted;
  });
});

// ---------- Panneaux (petits écrans) ----------

el.toggleRail.addEventListener('click', () => {
  el.app.classList.remove('members-open');
  el.app.classList.toggle('rail-open');
});
el.toggleMembers.addEventListener('click', () => {
  el.app.classList.remove('rail-open');
  el.app.classList.toggle('members-open');
});

// ---------- Démarrage ----------

if (!globalThis.crypto?.subtle) {
  showAuthError('Ce navigateur ne peut pas chiffrer sur cette page : utilisez HTTPS ou http://localhost.');
  el.authSubmit.disabled = true;
} else {
  setAuthMode('login');
}
el.authUsername.focus();
