const state = { mode: 'login', user: null, servers: [], activeServer: null, channels: [], activeChannel: null, socket: null, channelKeys: new Map() };
const $ = (selector) => document.querySelector(selector);

async function api(path, options = {}) {
  const headers = { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) };
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(options.method)) headers['X-CSRF-Token'] = getCookie('talk_csrf') || '';
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) { const data = await response.json().catch(() => ({})); throw new Error(data.detail || `Erreur ${response.status}`); }
  return response.status === 204 ? null : response.json();
}
function getCookie(name) { return document.cookie.split('; ').find((part) => part.startsWith(`${name}=`))?.split('=')[1]; }
function showError(message) { $('#auth-error').textContent = message; }
function setView(authenticated) { $('#auth-view').classList.toggle('hidden', authenticated); $('#app-view').classList.toggle('hidden', !authenticated); }
function initials(name) { return name.slice(0, 2).toUpperCase(); }

async function loadIdentity() {
  const key = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
  const publicKey = await crypto.subtle.exportKey('spki', key.publicKey);
  const encoded = btoa(String.fromCharCode(...new Uint8Array(publicKey)));
  await api('/api/keys', { method: 'POST', body: JSON.stringify({ public_key: encoded }) });
}
async function channelKey(channelId) {
  if (!state.channelKeys.has(channelId)) state.channelKeys.set(channelId, await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']));
  return state.channelKeys.get(channelId);
}
async function encryptMessage(channelId, text) {
  const key = await channelKey(channelId); const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
  return { ciphertext: btoa(String.fromCharCode(...new Uint8Array(encrypted))), nonce: btoa(String.fromCharCode(...iv)), key_version: 'local-v1' };
}
function decodeBase64(value) { return Uint8Array.from(atob(value), (character) => character.charCodeAt(0)); }
async function decryptMessage(message) {
  try {
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decodeBase64(message.nonce) }, await channelKey(message.channel_id), decodeBase64(message.ciphertext));
    return new TextDecoder().decode(plaintext);
  } catch {
    return '[message chiffré indisponible sur cet appareil]';
  }
}
function renderServers() { const list = $('#server-list'); list.replaceChildren(); state.servers.forEach((server) => { const button = document.createElement('button'); button.className = `server-item ${state.activeServer?.id === server.id ? 'active' : ''}`; button.textContent = server.name; button.title = server.name; button.onclick = () => selectServer(server); list.append(button); }); }
function renderChannels() { const list = $('#channel-list'); list.replaceChildren(); state.channels.forEach((channel) => { const button = document.createElement('button'); button.className = `channel-item ${state.activeChannel?.id === channel.id ? 'active' : ''}`; button.textContent = `# ${channel.name}`; button.onclick = () => selectChannel(channel); list.append(button); }); }
async function renderMessages(messages) { const list = $('#message-list'); list.replaceChildren(); if (!messages.length) { const empty = document.createElement('div'); empty.className = 'empty-state'; const icon = document.createElement('div'); icon.className = 'empty-icon'; icon.textContent = '✦'; const title = document.createElement('h3'); title.textContent = 'Le canal est silencieux.'; const text = document.createElement('p'); text.textContent = 'Écrivez le premier message. Il sera chiffré avant son envoi.'; empty.append(icon, title, text); list.append(empty); return; } for (const message of messages) await appendMessage(message); }
async function appendMessage(message) { const list = $('#message-list'); const item = document.createElement('article'); item.className = 'message'; const avatar = document.createElement('span'); avatar.className = 'avatar'; avatar.textContent = state.user?.id === message.sender_id ? initials(state.user.username) : '·'; const content = document.createElement('div'); const meta = document.createElement('div'); meta.className = 'message-meta'; meta.textContent = state.user?.id === message.sender_id ? `${state.user.username} · maintenant` : 'membre · message chiffré'; const body = document.createElement('div'); body.className = 'message-body'; body.textContent = await decryptMessage(message); content.append(meta, body); item.append(avatar, content); list.append(item); list.scrollTop = list.scrollHeight; }
async function selectServer(server) { state.activeServer = server; $('#server-name').textContent = server.name; state.channels = await api(`/api/servers/${server.id}/channels`); state.activeChannel = null; $('#channel-name').textContent = 'Sélectionnez un canal'; $('#message-form').classList.add('hidden'); renderServers(); renderChannels(); }
async function selectChannel(channel) { state.activeChannel = channel; $('#channel-name').textContent = `# ${channel.name}`; renderChannels(); const messages = await api(`/api/channels/${channel.id}/messages`); await renderMessages(messages); $('#message-form').classList.remove('hidden'); if (state.socket) state.socket.close(); const protocol = location.protocol === 'https:' ? 'wss' : 'ws'; state.socket = new WebSocket(`${protocol}://${location.host}/ws/channels/${channel.id}`); state.socket.onopen = () => { $('#connection-state').className = 'status online'; $('#connection-state').lastChild.textContent = 'en direct'; }; state.socket.onclose = () => { $('#connection-state').className = 'status'; $('#connection-state').lastChild.textContent = 'hors ligne'; }; state.socket.onmessage = async (event) => appendMessage(JSON.parse(event.data)); }
async function loadApp() { state.user = await api('/api/auth/me'); $('#profile-name').textContent = state.user.username; $('#profile-initial').textContent = initials(state.user.username); await loadIdentity(); state.servers = await api('/api/servers'); renderServers(); if (state.servers[0]) await selectServer(state.servers[0]); }

$('#auth-mode').onclick = () => { state.mode = state.mode === 'login' ? 'register' : 'login'; $('#auth-submit-label').textContent = state.mode === 'login' ? 'Se connecter' : 'Créer mon compte'; $('#auth-mode').textContent = state.mode === 'login' ? 'Créer un compte' : 'J’ai déjà un compte'; showError(''); };
$('#auth-form').onsubmit = async (event) => { event.preventDefault(); showError(''); try { await api(`/api/auth/${state.mode}`, { method: 'POST', body: JSON.stringify({ username: $('#username').value, password: $('#password').value }) }); setView(true); await loadApp(); } catch (error) { showError(error.message); } };
$('#logout').onclick = async () => { try { await api('/api/auth/logout', { method: 'POST' }); } finally { if (state.socket) state.socket.close(); state.user = null; setView(false); } };
let dialogMode = 'server';
$('#new-server').onclick = () => { dialogMode = 'server'; $('#dialog-eyebrow').textContent = 'nouvel espace'; $('#dialog-title').textContent = 'Créer un espace'; $('#dialog-name').value = ''; $('#name-dialog').showModal(); };
$('#new-channel').onclick = () => { if (!state.activeServer) return; dialogMode = 'channel'; $('#dialog-eyebrow').textContent = 'nouveau canal'; $('#dialog-title').textContent = 'Créer un canal'; $('#dialog-name').value = ''; $('#name-dialog').showModal(); };
$('#name-form').onsubmit = async (event) => { event.preventDefault(); const name = $('#dialog-name').value; try { if (dialogMode === 'server') { const server = await api('/api/servers', { method: 'POST', body: JSON.stringify({ name }) }); state.servers.push(server); $('#name-dialog').close(); await selectServer(server); } else { const channel = await api(`/api/servers/${state.activeServer.id}/channels`, { method: 'POST', body: JSON.stringify({ name }) }); state.channels.push(channel); $('#name-dialog').close(); renderChannels(); await selectChannel(channel); } } catch (error) { $('#dialog-name').setCustomValidity(error.message); $('#dialog-name').reportValidity(); } };
$('#message-form').onsubmit = async (event) => { event.preventDefault(); const input = $('#message-input'); const text = input.value.trim(); if (!text || !state.activeChannel) return; try { const payload = await encryptMessage(state.activeChannel.id, text); await api(`/api/channels/${state.activeChannel.id}/messages`, { method: 'POST', body: JSON.stringify(payload) }); input.value = ''; } catch (error) { showError(error.message); } };
(async () => { try { await api('/api/auth/me'); setView(true); await loadApp(); } catch { setView(false); } })();
