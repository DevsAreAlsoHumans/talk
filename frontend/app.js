// Les deux écrans : connexion et chat
const authScreen = document.querySelector('#auth');
const appScreen = document.querySelector('#app');
// Tout l'état de l'appli est gardé ici
const state = {
  csrf: '', username: '', signup: false,
  userKeys: null, roomKeys: new Map(),
  servers: [], server: null, channels: [], channel: null, members: [],
};
// Raccourci pour pas réécrire document.querySelector partout
const $ = (selector) => document.querySelector(selector);
const serverPath = () => `/servers/${encodeURIComponent(state.server.id)}`;

// Petite notif en bas à droite qui disparaît toute seule
function notify(message) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.classList.add('visible');
  clearTimeout(notify.timer);
  notify.timer = setTimeout(() => toast.classList.remove('visible'), 3500);
}

// Appel à l'API, on envoie toujours le jeton CSRF dans le header
async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': state.csrf, ...options.headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(typeof body.detail === 'string' ? body.detail : `Erreur ${response.status}`);
  }
  return response.json();
}

// ---------- Clés ----------

// Ma paire de clés RSA : créée une fois, gardée dans ce navigateur. Seule la publique part au serveur
async function setupUserKeys(publicKeyOnServer) {
  const storageKey = `talk:user-keys:${state.username}`;
  let saved = null;
  try { saved = JSON.parse(localStorage.getItem(storageKey)); } catch { saved = null; }
  if (!saved) {
    saved = await exportUserKeys(await newUserKeys());
    localStorage.setItem(storageKey, JSON.stringify(saved));
  }
  state.userKeys = await importUserKeys(saved);
  if (publicKeyOnServer !== saved.publicKey) {
    await api('/me/public-key', { method: 'PUT', body: JSON.stringify({ public_key: saved.publicKey }) });
  }
}

// Clé du salon : le serveur donne ma copie chiffrée, je l'ouvre avec ma clé privée
async function roomKey(serverId) {
  if (!state.roomKeys.has(serverId)) {
    const { wrapped_key: wrappedKey } = await api(`/servers/${encodeURIComponent(serverId)}/key`);
    try { state.roomKeys.set(serverId, await unwrapRoomKey(wrappedKey, state.userKeys.privateKey)); }
    catch { throw new Error('Clé illisible sur cet appareil : demandez au créateur de vous ajouter à nouveau.'); }
  }
  return state.roomKeys.get(serverId);
}

// ---------- Affichage ----------

// Affiche l'écran de connexion
function showAuth() {
  authScreen.hidden = false;
  appScreen.hidden = true;
}

// Affiche le chat avec le nom de l'utilisateur
function showApp() {
  authScreen.hidden = true;
  appScreen.hidden = false;
  $('#username-display').textContent = state.username;
  $('#user-avatar').textContent = state.username.slice(0, 1).toUpperCase();
}

// Dessine la liste des salons à gauche
function renderServers() {
  const list = $('#server-list');
  list.replaceChildren();
  for (const server of state.servers) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `server-icon${state.server?.id === server.id ? ' selected' : ''}`;
    button.textContent = server.name.slice(0, 2).toUpperCase();
    button.title = server.name;
    button.setAttribute('aria-label', server.name);
    button.addEventListener('click', () => selectServer(server));
    list.append(button);
  }
}

// Dessine la liste des canaux du salon choisi
function renderChannels() {
  const list = $('#channel-list');
  list.replaceChildren();
  for (const channel of state.channels) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `channel-item${state.channel?.id === channel.id ? ' selected' : ''}`;
    const symbol = document.createElement('span');
    symbol.textContent = '#';
    // textContent et pas innerHTML pour éviter le XSS
    button.append(symbol, document.createTextNode(` ${channel.name}`));
    button.addEventListener('click', () => selectChannel(channel));
    list.append(button);
  }
}

// Dessine les membres, avec un bouton pour les retirer si je suis le créateur
function renderMembers() {
  const list = $('#member-list');
  list.replaceChildren();
  for (const member of state.members) {
    const item = document.createElement('li');
    item.textContent = member.username;
    if (member.owner) {
      const badge = document.createElement('span');
      badge.className = 'muted';
      badge.textContent = ' créateur';
      item.append(badge);
    } else if (state.server?.owner) {
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.textContent = '×';
      remove.title = `Retirer ${member.username}`;
      remove.setAttribute('aria-label', `Retirer ${member.username}`);
      remove.addEventListener('click', () => removeMember(member.username));
      item.append(remove);
    }
    list.append(item);
  }
}

// ---------- Chargement ----------

// Récupère mes salons et ouvre le premier
async function loadServers() {
  state.servers = await api('/servers');
  renderServers();
  if (state.servers.length && !state.server) await selectServer(state.servers[0]);
}

// Quand on clique sur un salon : on charge ses canaux et ses membres
async function selectServer(server) {
  state.server = server;
  state.channel = null;
  $('#server-name').textContent = server.name;
  $('#message-form').hidden = true;
  // Seul le créateur peut ajouter des canaux et des membres
  $('#new-channel').hidden = !server.owner;
  $('#add-member').hidden = !server.owner;
  renderServers();
  try {
    state.channels = await api(`${serverPath()}/channels`);
    renderChannels();
    await loadMembers();
    if (state.channels.length) await selectChannel(state.channels[0]);
  } catch (error) { notify(error.message); }
}

async function loadMembers() {
  state.members = await api(`${serverPath()}/members`);
  renderMembers();
}

// Quand on clique sur un canal : on affiche ses messages
async function selectChannel(channel) {
  state.channel = channel;
  $('#channel-name').textContent = channel.name;
  $('#message-form').hidden = false;
  $('#chat-error').textContent = '';
  renderChannels();
  await loadMessages();
}

// Charge les messages du canal et les déchiffre un par un
async function loadMessages() {
  const server = state.server;
  const channel = state.channel;
  if (!server || !channel) return;
  try {
    const key = await roomKey(server.id);
    const messages = await api(`/servers/${encodeURIComponent(server.id)}/channels/${encodeURIComponent(channel.id)}/messages`);
    // Si on a changé de canal pendant le chargement, on ignore
    if (state.server?.id !== server.id || state.channel?.id !== channel.id) return;
    const container = $('#messages');
    // On descend en bas seulement si on y était déjà
    const nearBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 100;
    const items = [];
    if (!messages.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.innerHTML = '<p>Aucun message.</p>';
      items.push(empty);
    }
    for (const message of messages) {
      const row = document.createElement('article');
      row.className = 'message';
      const avatar = document.createElement('span');
      avatar.className = 'message-avatar';
      avatar.textContent = message.author.slice(0, 1).toUpperCase();
      const content = document.createElement('div');
      const meta = document.createElement('div');
      meta.className = 'message-meta';
      const author = document.createElement('strong');
      author.textContent = message.author;
      const time = document.createElement('time');
      time.textContent = new Date(message.created_at).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' });
      const text = document.createElement('p');
      // Toujours textContent : le HTML d'un message n'est jamais interprété
      try { text.textContent = await decryptText(key, channel.id, message); }
      catch { text.textContent = 'Impossible de déchiffrer ce message.'; text.className = 'decrypt-error'; }
      meta.append(author, time);
      content.append(meta, text);
      row.append(avatar, content);
      items.push(row);
    }
    container.replaceChildren(...items);
    if (nearBottom) container.scrollTop = container.scrollHeight;
    $('#chat-error').textContent = '';
  } catch (error) { $('#chat-error').textContent = error.message; }
}

// Après connexion : mes clés, puis mes salons
async function enterApp() {
  const me = await api('/me');
  state.username = me.username;
  await setupUserKeys(me.public_key);
  showApp();
  await loadServers();
}

// ---------- Actions ----------

// Bascule entre connexion et inscription
$('#auth-switch').addEventListener('click', () => {
  state.signup = !state.signup;
  $('#auth-title').textContent = state.signup ? 'Inscription' : 'Connexion';
  $('#auth-submit').textContent = state.signup ? 'Créer le compte' : 'Se connecter';
  $('#auth-switch').textContent = state.signup ? 'J’ai déjà un compte' : 'Créer un compte';
  $('#password').autocomplete = state.signup ? 'new-password' : 'current-password';
  $('#auth-error').textContent = '';
});

// Envoi du formulaire de connexion / inscription
$('#auth-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('#auth-error').textContent = '';
  try {
    const data = { username: $('#username').value, password: $('#password').value };
    await api(state.signup ? '/signup' : '/login', { method: 'POST', body: JSON.stringify(data) });
    $('#password').value = '';
    await enterApp();
  } catch (error) { $('#auth-error').textContent = error.message; }
});

// Déconnexion : on oublie aussi les clés gardées en mémoire
$('#logout').addEventListener('click', async () => {
  try { await api('/logout', { method: 'POST' }); }
  catch (error) { notify(error.message); return; }
  Object.assign(state, { userKeys: null, roomKeys: new Map(), servers: [], server: null, channel: null });
  showAuth();
});

// Fenêtre pour créer un salon, un canal ou ajouter un membre (même fenêtre pour les trois)
const dialogs = {
  server: { title: 'Nouveau salon', placeholder: 'Nom', maxLength: 40 },
  channel: { title: 'Nouveau canal', placeholder: 'Nom', maxLength: 40 },
  member: { title: 'Ajouter un membre', placeholder: 'Identifiant', maxLength: 24 },
};
let dialogMode = 'server';
function openDialog(mode) {
  dialogMode = mode;
  $('#dialog-title').textContent = dialogs[mode].title;
  $('#new-name').placeholder = dialogs[mode].placeholder;
  $('#new-name').maxLength = dialogs[mode].maxLength;
  $('#new-name').value = '';
  $('#dialog-error').textContent = '';
  $('#name-dialog').showModal();
  $('#new-name').focus();
}
$('#new-server').addEventListener('click', () => openDialog('server'));
$('#new-channel').addEventListener('click', () => { if (state.server) openDialog('channel'); });
$('#add-member').addEventListener('click', () => { if (state.server) openDialog('member'); });
$('#dialog-cancel').addEventListener('click', () => $('#name-dialog').close());

// Nouveau salon : je crée sa clé AES et je l'envoie chiffrée avec MA clé publique
async function createServer(name) {
  const key = await newRoomKey();
  const wrappedKey = await wrapRoomKey(key, state.userKeys.publicKey);
  const server = await api('/servers', { method: 'POST', body: JSON.stringify({ name, wrapped_key: wrappedKey }) });
  state.roomKeys.set(server.id, key);
  state.server = null;
  await loadServers();
  await selectServer(state.servers.find((item) => item.id === server.id));
  notify('Salon créé');
}

async function createChannel(name) {
  const channel = await api(`${serverPath()}/channels`, { method: 'POST', body: JSON.stringify({ name }) });
  state.channels.push(channel);
  await selectChannel(channel);
}

// Ajout d'un membre : je chiffre la clé du salon avec SA clé publique
async function addMember(username) {
  const { public_key: publicKey } = await api(`/users/${encodeURIComponent(username)}/public-key`);
  const wrappedKey = await wrapRoomKey(await roomKey(state.server.id), await importPublicKey(publicKey));
  await api(`${serverPath()}/members`, { method: 'POST', body: JSON.stringify({ username, wrapped_key: wrappedKey }) });
  await loadMembers();
  notify(`${username} ajouté`);
}

async function removeMember(username) {
  if (!confirm(`Retirer ${username} du salon ?`)) return;
  try {
    await api(`${serverPath()}/members/${encodeURIComponent(username)}`, { method: 'DELETE' });
    await loadMembers();
  } catch (error) { notify(error.message); }
}

$('#name-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const name = $('#new-name').value.trim();
  if (!name) return;
  try {
    if (dialogMode === 'server') await createServer(name);
    else if (dialogMode === 'channel') await createChannel(name);
    else await addMember(name);
    $('#name-dialog').close();
  } catch (error) { $('#dialog-error').textContent = error.message; }
});

// Envoi d'un message : on chiffre puis on envoie
$('#message-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const input = $('#message-input');
  const text = input.value.trim();
  if (!text || !state.server || !state.channel) return;
  const serverId = state.server.id;
  const channelId = state.channel.id;
  $('#chat-error').textContent = '';
  try {
    const encrypted = await encryptText(await roomKey(serverId), channelId, text);
    await api(`/servers/${encodeURIComponent(serverId)}/channels/${encodeURIComponent(channelId)}/messages`, {
      method: 'POST', body: JSON.stringify(encrypted),
    });
    input.value = '';
    await loadMessages();
  } catch (error) { $('#chat-error').textContent = error.message; }
});

// Recharge la liste des salons (pour voir ceux où on vient d'être ajouté)
async function refreshServers() {
  try {
    state.servers = await api('/servers');
    renderServers();
    if (!state.server && state.servers.length) await selectServer(state.servers[0]);
  } catch { /* on réessaiera au prochain tour */ }
}

// Au chargement : on récupère le CSRF puis on regarde si on est déjà connecté
async function start() {
  if (!crypto.subtle) { showAuth(); $('#auth-error').textContent = 'Le chiffrement nécessite HTTPS ou localhost.'; return; }
  try {
    state.csrf = (await api('/csrf')).csrf_token;
    await enterApp();
  } catch { showAuth(); }
  // Toutes les 2,5 s on recharge les messages (polling), et les salons toutes les 10 s
  setInterval(() => { if (state.channel && !appScreen.hidden) loadMessages(); }, 2500);
  setInterval(() => { if (!appScreen.hidden) refreshServers(); }, 10000);
}
start();
