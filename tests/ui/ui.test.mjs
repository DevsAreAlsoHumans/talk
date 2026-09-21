// Test de bout en bout de l'interface : pilote le VRAI frontend (frontend/js/app.js) dans jsdom,
// contre un VRAI serveur talk + Redis, avec deux utilisateurs. Aucun navigateur n'est nécessaire.
//
// Prérequis : le serveur tourne (voir README, « Tests de l'interface »).
// Variables : TALK_URL (défaut http://localhost:8000) ; TALK_REDIS_DB (optionnel) : si défini et si
// `redis-cli` est installé, le test vérifie aussi qu'aucun texte en clair n'est stocké dans Redis.
// Usage : npm run test:ui
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';
import WebSocketBase from 'ws';

const BASE = process.env.TALK_URL ?? 'http://localhost:8000';
const REDIS_DB = process.env.TALK_REDIS_DB;
const FRONTEND = new URL('../../frontend/', import.meta.url);
const realFetch = globalThis.fetch;

// ----- environnement navigateur simulé (cookies + Origin + WebSocket avec en-têtes) -----
const cookies = new Map();
const cookieHeader = (jar) => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
function storeCookies(jar, response) {
  for (const line of response.headers.getSetCookie()) {
    const [pair] = line.split(';');
    const [name, ...rest] = pair.split('=');
    const value = rest.join('=');
    if (/max-age=0/i.test(line) || !value || value === '""') jar.delete(name.trim()); else jar.set(name.trim(), value);
  }
}
function makeFetch(jar) {
  return async (path, init = {}) => {
    const headers = new Headers(init.headers);
    headers.set('Origin', BASE);
    if (jar.size) headers.set('Cookie', cookieHeader(jar));
    const response = await realFetch(new URL(path, BASE), { ...init, headers });
    storeCookies(jar, response);
    return response;
  };
}
globalThis.fetch = makeFetch(cookies);
globalThis.WebSocket = class extends WebSocketBase {
  constructor(url) { super(url, { headers: { Origin: BASE, Cookie: cookieHeader(cookies) } }); }
};

const dom = new JSDOM(readFileSync(new URL('index.html', FRONTEND), 'utf8'), { url: `${BASE}/`, pretendToBeVisual: true });
const { window } = dom;
Object.assign(globalThis, { window, document: window.document, location: window.location, Node: window.Node });
globalThis.matchMedia = () => ({ matches: false }); // animation de déchiffrement active
if (URL.createObjectURL === undefined) {
  let fakeUrlSeq = 0;
  URL.createObjectURL = () => `blob:ui-${++fakeUrlSeq}`;
  URL.revokeObjectURL = () => {};
}
window.HTMLDialogElement.prototype.showModal = function showModal() { this.setAttribute('open', ''); };
window.HTMLDialogElement.prototype.close = function close() { this.removeAttribute('open'); };
const errors = [];
const realConsoleError = console.error;
console.error = (...args) => {
  const line = args.map(String).join(' ');
  errors.push(line);
  if (!line.includes('Identifiants invalides')) realConsoleError(...args); // celle-ci est provoquée volontairement
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function waitFor(check, label, timeout = 10000) {
  const start = Date.now();
  for (;;) {
    let value;
    try { value = check(); } catch { value = false; }
    if (value) return value;
    if (Date.now() - start > timeout) throw new Error(`Timeout : ${label}\n  membres : ${$('#member-list')?.textContent}\n  toast : ${$('#toast')?.textContent}\n  salon : ${$('#room-title')?.textContent}`);
    await sleep(25);
  }
}
let passed = 0;
function ok(condition, label) {
  if (!condition) throw new Error(`ÉCHEC : ${label}`);
  passed += 1;
  console.log(`  ✓ ${label}`);
}
const submit = (form) => form.requestSubmit();
const setValue = (selector, value) => { $(selector).value = value; };

// ----- client « Bob » : autre utilisateur, piloté par l'API + crypto.js (comme un second navigateur) -----
const crypto2 = await import(new URL('js/crypto.js', FRONTEND));
class Bob {
  constructor() { this.jar = new Map(); this.fetch = makeFetch(this.jar); this.csrf = null; }
  async call(method, path, body) {
    if (method !== 'GET' && !this.csrf) this.csrf = (await (await this.fetch('/api/csrf')).json()).csrf_token;
    const response = await this.fetch(path, { method, headers: { 'Content-Type': 'application/json', ...(method !== 'GET' ? { 'X-CSRF-Token': this.csrf } : {}) }, body: body && JSON.stringify(body) });
    const data = response.status === 204 ? null : await response.json();
    if (!response.ok) throw new Error(`${method} ${path} → ${response.status} ${JSON.stringify(data)}`);
    return data;
  }
  async signUp(username, password) {
    const { wrapKey, authSecret } = await crypto2.deriveKeys(password, username);
    const identity = await crypto2.generateIdentity();
    await this.call('POST', '/api/auth/register', { username, auth_secret: authSecret, public_key: identity.publicKey, encrypted_private_key: await crypto2.encryptPrivateKey(identity.pkcs8, wrapKey) });
    const { user, csrf_token } = await this.call('POST', '/api/auth/login', { username, auth_secret: authSecret });
    this.csrf = csrf_token; this.user = user;
    this.privateKey = await crypto2.decryptPrivateKey(user.encrypted_private_key, wrapKey);
  }
  async roomKey(roomId) {
    const room = await this.call('GET', `/api/rooms/${roomId}`);
    return crypto2.unwrapRoomKey(room.wrapped_key, this.privateKey);
  }
  async say(roomId, text) {
    const key = await this.roomKey(roomId);
    return this.call('POST', `/api/rooms/${roomId}/messages`, await crypto2.encryptMessage(key, text, roomId, this.user.id));
  }
}

console.log('Chargement de app.js …');
await import(new URL('js/app.js', FRONTEND));

console.log('Inscription');
ok(!$('#auth-screen').hidden && $('#app').hidden, "l'écran de connexion est affiché au départ");
$('#tab-register').click();
ok(!$('#confirm-field').hidden, 'le champ de confirmation apparaît en mode inscription');
setValue('#auth-username', 'alice'); setValue('#auth-password', 'court'); setValue('#auth-confirm', 'court');
submit($('#auth-form'));
ok(!$('#auth-error').hidden && $('#auth-error').textContent.includes('trop court'), 'mot de passe trop court refusé côté client');
setValue('#auth-password', 'un mot de passe solide'); setValue('#auth-confirm', 'différent');
submit($('#auth-form'));
ok($('#auth-error').textContent.includes('ne correspondent pas'), 'confirmation différente refusée');
setValue('#auth-confirm', 'un mot de passe solide');
submit($('#auth-form'));
await waitFor(() => !$('#auth-screen').hidden === false && !$('#app').hidden, 'entrée dans l\'application');
ok($('#me-name').textContent === 'alice', 'connecté en tant qu\'alice');
await waitFor(() => !$('#room-empty').hidden, 'état vide');
ok(true, 'état vide : invitation à créer un salon');
ok($('#composer-input').disabled, 'composeur désactivé sans salon');
await waitFor(() => $('#conn-status').dataset.state === 'online', 'WebSocket connecté');
ok(true, 'WebSocket connecté (cookie de session + Origin acceptés)');

console.log('Salon et messages');
setValue('#new-room-name', 'général');
submit($('#create-room-form'));
await waitFor(() => $('#room-title').textContent === 'général', 'salon créé et ouvert');
ok(!$('#composer-input').disabled, 'composeur activé');
ok(!$('#e2e-badge').hidden, 'badge « chiffré de bout en bout » affiché');
await waitFor(() => $$('#member-list li').length === 1, 'liste des membres');
ok($('#member-list').textContent.includes('alice (vous)') && $('#member-list').textContent.includes('propriétaire'), 'alice est propriétaire');
ok(/^[0-9a-f]{4}( [0-9a-f]{4}){3}$/.test($('.print').textContent), 'empreinte de clé affichée');
ok(!$('#add-member-form').hidden, 'formulaire d\'ajout visible pour le propriétaire');

const secret = 'Le code du coffre est 8492 <b>gras</b> & "guillemets" 🔐';
setValue('#composer-input', secret);
submit($('#composer'));
await waitFor(() => $$('.msg .body').some((node) => node.textContent === secret), 'message affiché');
ok($('.msg .author').textContent === 'alice', 'auteur affiché');
ok($('#composer-input').value === '', 'zone de saisie vidée après envoi');
ok(document.querySelector('.msg .body b') === null, 'HTML dans un message affiché comme texte (pas interprété)');

const imgBytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 13, 73, 68, 65, 84, 120, 218, 99, 0, 1, 0, 0, 5, 0, 1, 13, 74, 0, 60, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130]);
const imageFile = new File([imgBytes], 'pixel.png', { type: 'image/png' });
Object.defineProperty($('#file-image'), 'files', { value: [imageFile], configurable: true });
$('#file-image').dispatchEvent(new window.Event('change'));
await waitFor(() => $$('.msg img.media-img').length === 1, 'image envoyée et affichée');
ok($$('.msg img.media-img').length === 1, 'image envoyée et affichée en <img>');
ok($$('.msg img.media-img')[0].alt.includes('chiffrée'), 'image marquée comme chiffrée');

console.log('Second utilisateur, temps réel');
const bob = new Bob();
await bob.signUp('bob', 'le mot de passe de bob');
setValue('#add-member-name', 'personne');
submit($('#add-member-form'));
await waitFor(() => $('#toast').textContent.includes('introuvable'), 'erreur pour utilisateur inconnu');
ok(true, 'ajout d\'un utilisateur inconnu → message d\'erreur');
setValue('#add-member-name', 'bob');
submit($('#add-member-form'));
await waitFor(() => $$('#member-list li').length === 2, 'bob ajouté à la liste des membres');
ok($('#member-list').textContent.includes('bob'), 'bob apparaît parmi les membres');
ok($('#member-count').textContent === '2', 'compteur de membres à jour');

const roomId = (await bob.call('GET', '/api/rooms'))[0].id;
await bob.say(roomId, 'Salut Alice, ici Bob 👋');
await waitFor(() => $$('.msg .body').some((node) => node.textContent === 'Salut Alice, ici Bob 👋'), 'message de bob reçu en direct (après animation)');
ok($$('.msg .author').some((node) => node.textContent === 'bob'), 'message de bob reçu sans recharger');

console.log('Profil');
$('#btn-profile').click();
await waitFor(() => $('#profile-dialog').open, 'dialogue de profil ouvert');
ok(true, 'dialogue de profil ouvert');
setValue('#profile-name', 'Alicia'); setValue('#profile-bio', 'A distribue le café.');
submit($('#profile-form'));
await waitFor(() => $('#me-name').textContent === 'Alicia', 'surnom enregistré');
ok($('#member-list').textContent.includes('Alicia (vous)'), 'surnom visible dans la liste des membres');
$('#btn-profile').click();
await waitFor(() => $('#profile-dialog').open && $('#profile-bio').value === 'A distribue le café.', 'bio enregistrée');
ok($('#profile-dialog').open && $('#profile-bio').value === 'A distribue le café.', 'bio restaurée dans le dialogue');
$('#profile-cancel').click();

console.log('Autre salon et non-lus');
setValue('#new-room-name', 'projet');
submit($('#create-room-form'));
await waitFor(() => $('#room-title').textContent === 'projet', 'second salon ouvert');
await bob.say(roomId, 'Message pendant que tu es ailleurs');
await waitFor(() => $$('.unread').length === 1, 'pastille de message non lu');
ok(true, 'pastille « non lu » sur le salon en arrière-plan');
$$('button.room').find((button) => button.textContent.includes('général')).click();
await waitFor(() => $$('.msg .body').some((node) => node.textContent === 'Message pendant que tu es ailleurs'), 'retour sur général');
ok($$('.unread').length === 0, 'pastille effacée à l\'ouverture');

console.log('Serveur : rien en clair');
if (REDIS_DB === undefined) {
  console.log('  (inspection Redis ignorée : définir TALK_REDIS_DB pour l\'activer)');
} else {
  const redis = (...args) => execFileSync('redis-cli', ['-n', REDIS_DB, ...args]).toString();
  const keys = redis('--scan').split('\n').filter(Boolean);
  let dump = '';
  for (const key of keys) {
    const type = redis('type', key).trim();
    const read = { string: ['get', key], hash: ['hgetall', key], set: ['smembers', key], zset: ['zrange', key, '0', '-1'] }[type];
    dump += `${key}\n${redis(...read)}\n`;
  }
  ok(keys.length > 5, `${keys.length} clés Redis inspectées`);
  for (const needle of ['8492', 'coffre', 'Salut Alice', 'ailleurs', 'un mot de passe solide', 'le mot de passe de bob']) {
    ok(!dump.includes(needle), `« ${needle} » absent de Redis`);
  }
}

console.log('Déconnexion / reconnexion');
$('#logout').click();
await waitFor(() => !$('#auth-screen').hidden && $('#app').hidden, 'retour à l\'écran de connexion');
ok(cookies.size === 0 || ![...cookies.keys()].some((name) => name.includes('session')), 'cookie de session supprimé');
ok((await realFetch(`${BASE}/api/rooms`, { headers: { Cookie: 'x=1' } })).status === 401, 'API inaccessible sans session');

setValue('#auth-username', 'alice'); setValue('#auth-password', 'mauvais mot de passe');
submit($('#auth-form'));
await waitFor(() => !$('#auth-error').hidden, 'erreur de connexion');
ok($('#auth-error').textContent.includes('incorrect'), 'mauvais mot de passe → message générique');
ok($('#auth-submit').disabled === false && $('#auth-submit').textContent === 'Se connecter', 'bouton de nouveau utilisable après l\'erreur');

setValue('#auth-password', 'un mot de passe solide');
submit($('#auth-form'));
await waitFor(() => !$('#app').hidden, 'reconnexion');
await waitFor(() => $$('#room-list button').length === 2, 'salons rechargés');
$$('button.room').find((button) => button.textContent.includes('général')).click();
await waitFor(() => $$('.msg .body').length >= 3, 'historique rechargé');
const texts = $$('.msg .body').map((node) => node.textContent);
ok(texts.includes(secret) && texts.includes('Salut Alice, ici Bob 👋'), 'historique déchiffré avec la clé privée restaurée depuis le mot de passe');
ok(!texts.some((text) => text.includes('indéchiffrable')), 'aucun message indéchiffrable');

$('#logout').click();
await waitFor(() => $('#app').hidden, 'déconnexion finale');
ok(errors.filter((line) => !line.includes('Identifiants invalides')).length === 0, `aucune erreur inattendue en console (${errors.length} au total)`);
console.log(`\n${passed} vérifications OK`);
process.exit(0);
