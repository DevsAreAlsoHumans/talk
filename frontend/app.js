// Les deux écrans : connexion et chat
const authScreen = document.querySelector('#auth');
const appScreen = document.querySelector('#app');
// Tout l'état de l'appli est gardé ici
const state = { csrf: '', username: '', servers: [], server: null, channel: null, channels: [], signup: false };
// Raccourci pour pas réécrire document.querySelector partout
const $ = (selector) => document.querySelector(selector);

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

// La clé du salon est gardée dans le navigateur, jamais envoyée au serveur
function keyFor(serverId) {
  return localStorage.getItem(`talk:key:${serverId}`);
}

async function roomKey(serverId) {
  const raw = keyFor(serverId);
  if (!raw) throw new Error('Clé absente sur cet appareil. Ouvrez le lien d’invitation du salon.');
  return importRoomKey(raw);
}

// Chiffre le message avant de l'envoyer (fonctions dans crypto.js)
async function encryptMessage(serverId, channelId, text) {
  return encryptText(await roomKey(serverId), channelId, text);
}

async function decryptMessage(serverId, channelId, message) {
  return decryptText(await roomKey(serverId), channelId, message);
}

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

// Récupère mes salons et ouvre le premier
async function loadServers() {
  state.servers = await api('/servers');
  renderServers();
  if (state.servers.length && !state.server) await selectServer(state.servers[0]);
}

// Quand on clique sur un salon : on charge ses canaux
async function selectServer(server) {
  state.server = server;
  state.channel = null;
  $('#server-name').textContent = server.name;
  $('#message-form').hidden = true;
  renderServers();
  try {
    state.channels = await api(`/servers/${encodeURIComponent(server.id)}/channels`);
    renderChannels();
    if (state.channels.length) await selectChannel(state.channels[0]);
  } catch (error) { notify(error.message); }
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
      try { text.textContent = await decryptMessage(server.id, channel.id, message); }
      catch { text.textContent = 'Impossible de déchiffrer ce message.'; text.className = 'decrypt-error'; }
      meta.append(author, time);
      content.append(meta, text);
      row.append(avatar, content);
      items.push(row);
    }
    container.replaceChildren(...items);
    if (nearBottom) container.scrollTop = container.scrollHeight;
  } catch (error) { $('#chat-error').textContent = error.message; }
}

// Lien d'invitation : l'id du salon et la clé sont après le #
async function acceptInvite() {
  const params = new URLSearchParams(location.hash.slice(1));
  const serverId = params.get('server');
  const key = params.get('key');
  if (!serverId || !key) return false;
  // On enlève la clé de la barre d'adresse tout de suite
  history.replaceState(null, '', location.pathname);
  try {
    if (base64ToBytes(key).length !== 32) throw new Error('Clé d’invitation invalide.');
    const joined = await api(`/servers/${encodeURIComponent(serverId)}/join`, { method: 'POST' });
    localStorage.setItem(`talk:key:${serverId}`, key);
    state.server = null;
    await loadServers();
    await selectServer(joined);
    notify(`Salon « ${joined.name} » rejoint.`);
    return true;
  } catch (error) { notify(error.message); return false; }
}

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
    const result = await api(state.signup ? '/signup' : '/login', { method: 'POST', body: JSON.stringify(data) });
    state.username = result.username;
    showApp();
    if (!(await acceptInvite())) await loadServers();
  } catch (error) { $('#auth-error').textContent = error.message; }
});

// Déconnexion
$('#logout').addEventListener('click', async () => {
  try { await api('/logout', { method: 'POST' }); }
  catch (error) { notify(error.message); return; }
  state.server = null;
  state.channel = null;
  showAuth();
});

// Fenêtre pour créer un salon ou un canal (même fenêtre pour les deux)
let dialogMode = 'server';
function openNameDialog(mode) {
  dialogMode = mode;
  $('#dialog-title').textContent = mode === 'server' ? 'Nouveau salon' : 'Nouveau canal';
  $('#new-name').value = '';
  $('#dialog-error').textContent = '';
  $('#name-dialog').showModal();
  $('#new-name').focus();
}
$('#new-server').addEventListener('click', () => openNameDialog('server'));
$('#new-channel').addEventListener('click', () => {
  if (state.server) openNameDialog('channel');
});
$('#dialog-cancel').addEventListener('click', () => $('#name-dialog').close());
// Création du salon ou du canal
$('#name-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const name = $('#new-name').value.trim();
  if (!name) return;
  try {
    if (dialogMode === 'server') {
      // Nouveau salon = nouvelle clé AES de 256 bits générée ici
      const key = newRoomKey();
      const server = await api('/servers', { method: 'POST', body: JSON.stringify({ name }) });
      localStorage.setItem(`talk:key:${server.id}`, key);
      state.server = null;
      await loadServers();
      await selectServer(server);
      notify('Salon créé');
    } else {
      const channel = await api(`/servers/${encodeURIComponent(state.server.id)}/channels`, {
        method: 'POST', body: JSON.stringify({ name }),
      });
      state.channels.push(channel);
      await selectChannel(channel);
    }
    $('#name-dialog').close();
  } catch (error) { $('#dialog-error').textContent = error.message; }
});

// Copie le lien d'invitation avec la clé dedans
$('#invite').addEventListener('click', async () => {
  if (!state.server) return;
  const key = keyFor(state.server.id);
  if (!key) { notify('Clé du salon absente sur cet appareil'); return; }
  const url = `${location.origin}/#server=${encodeURIComponent(state.server.id)}&key=${encodeURIComponent(key)}`;
  try { await navigator.clipboard.writeText(url); notify('Lien copié, à envoyer en privé'); }
  catch { notify('Copie impossible (HTTPS requis)'); }
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
    const encrypted = await encryptMessage(serverId, channelId, text);
    await api(`/servers/${encodeURIComponent(serverId)}/channels/${encodeURIComponent(channelId)}/messages`, {
      method: 'POST', body: JSON.stringify(encrypted),
    });
    input.value = '';
    await loadMessages();
  } catch (error) { $('#chat-error').textContent = error.message; }
});

// Au chargement : on récupère le CSRF puis on regarde si on est déjà connecté
async function start() {
  if (!crypto.subtle) { showAuth(); $('#auth-error').textContent = 'Le chiffrement nécessite HTTPS ou localhost.'; return; }
  try {
    const token = await api('/csrf');
    state.csrf = token.csrf_token;
    const me = await api('/me');
    state.username = me.username;
    showApp();
    if (!(await acceptInvite())) await loadServers();
  } catch { showAuth(); }
  // Toutes les 2,5 s on recharge les messages (polling)
  setInterval(() => { if (state.channel && !appScreen.hidden) loadMessages(); }, 2500);
}
start();
