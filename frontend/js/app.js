import { api } from "./api.js";
import * as cryptoUtil from "./crypto.js";
import { loadKeyPair, saveKeyPair } from "./idb.js";
import { connectRoomSocket } from "./ws.js";

const authView = document.getElementById("auth-view");
const totpView = document.getElementById("totp-view");
const forgotPasswordView = document.getElementById("forgot-password-view");
const resetPasswordView = document.getElementById("reset-password-view");
const chatView = document.getElementById("chat-view");
const authError = document.getElementById("auth-error");
const totpError = document.getElementById("totp-error");
const currentUserLabel = document.getElementById("current-user");
const currentAvatar = document.getElementById("current-avatar");
const roomList = document.getElementById("room-list");
const activeRoomLabel = document.getElementById("active-room-label");
const messagesList = document.getElementById("messages");
const sendForm = document.getElementById("send-form");

let keyPair = null;
let currentUser = null;
let currentRoom = null; // { id, sharedKey }
let socket = null;
let pendingTotpToken = null;

function hideAllViews() {
  authView.hidden = true;
  totpView.hidden = true;
  forgotPasswordView.hidden = true;
  resetPasswordView.hidden = true;
  chatView.hidden = true;
}

async function ensureKeyPair() {
  if (keyPair) return keyPair;
  const stored = await loadKeyPair();
  if (stored) {
    keyPair = stored;
    return keyPair;
  }
  keyPair = await cryptoUtil.generateKeyPair();
  await saveKeyPair(keyPair);
  return keyPair;
}

// Limitation assumée : une clé E2E est liée à ce navigateur/IndexedDB. Se
// reconnecter depuis un autre appareil générerait une clé différente et
// casserait le déchiffrement des messages envoyés vers l'ancienne clé
// (pas de gestion multi-appareil dans ce projet).
async function publishPublicKeyIfNeeded(user) {
  const pair = await ensureKeyPair();
  if (user.public_key) return;
  const publicKeyRaw = await cryptoUtil.exportPublicKeyRaw(pair.publicKey);
  await api.setPublicKey(publicKeyRaw);
}

function showChatView(user) {
  currentUser = user;
  currentUserLabel.textContent = `Connecté en tant que ${user.username}#${user.discriminator}`;
  currentAvatar.src = user.avatar ? user.avatar.url : "";
  hideAllViews();
  chatView.hidden = false;
  loadRooms();
}

function showAuthView() {
  currentUser = null;
  hideAllViews();
  authView.hidden = false;
}

function showTotpView(pendingToken) {
  pendingTotpToken = pendingToken;
  totpError.textContent = "";
  hideAllViews();
  totpView.hidden = false;
}

async function loadRooms() {
  const rooms = await api.listRooms();
  roomList.innerHTML = "";
  for (const room of rooms) {
    // Les salons de groupe arrivent avec la phase 8 (E2E de groupe) : on
    // n'affiche ici que les DM pour ne pas montrer un chat non fonctionnel.
    if (room.type !== "dm") continue;
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.textContent = `${room.peer.username}#${room.peer.discriminator}`;
    button.addEventListener("click", () => openRoom(room));
    item.appendChild(button);
    roomList.appendChild(item);
  }
}

async function openRoom(room) {
  if (socket) socket.close();
  const pair = await ensureKeyPair();

  if (!room.peer.public_key) {
    activeRoomLabel.textContent = `${room.peer.username}#${room.peer.discriminator} n'a pas encore de clé publique (il doit se connecter au moins une fois).`;
    sendForm.hidden = true;
    currentRoom = null;
    return;
  }

  const peerPublicKey = await cryptoUtil.importPeerPublicKey(room.peer.public_key);
  const sharedKey = await cryptoUtil.deriveSharedKey(pair.privateKey, peerPublicKey);
  currentRoom = { id: room.id, sharedKey };

  activeRoomLabel.textContent = `DM avec ${room.peer.username}#${room.peer.discriminator}`;
  sendForm.hidden = false;
  messagesList.innerHTML = "";

  const history = await api.listMessages(room.id);
  for (const message of history) {
    await renderMessage(message);
  }

  socket = connectRoomSocket(room.id, (message) => {
    if (message.sender_id !== currentUser.id) {
      renderMessage(message);
    }
  });
}

async function renderMessage(message) {
  const item = document.createElement("li");
  try {
    const plaintext = await cryptoUtil.decryptMessage(
      currentRoom.sharedKey,
      message.ciphertext,
      message.iv
    );
    item.textContent =
      message.sender_id === currentUser.id ? `Moi : ${plaintext}` : `Eux : ${plaintext}`;
  } catch {
    item.textContent = "[message illisible]";
  }
  messagesList.appendChild(item);
}

document.getElementById("register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  authError.textContent = "";
  const form = new FormData(event.target);
  try {
    const user = await api.register({
      username: form.get("username"),
      email: form.get("email"),
      password: form.get("password"),
    });
    await publishPublicKeyIfNeeded(user);
    showChatView(user);
  } catch (error) {
    authError.textContent = error.message;
  }
});

document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  authError.textContent = "";
  const form = new FormData(event.target);
  try {
    const result = await api.login({
      email: form.get("email"),
      password: form.get("password"),
    });
    if (result.totp_required) {
      showTotpView(result.pending_token);
      return;
    }
    await publishPublicKeyIfNeeded(result.user);
    showChatView(result.user);
  } catch (error) {
    authError.textContent = error.message;
  }
});

document.getElementById("totp-login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  totpError.textContent = "";
  const form = new FormData(event.target);
  try {
    const user = await api.verifyTotp(pendingTotpToken, form.get("code"));
    await publishPublicKeyIfNeeded(user);
    showChatView(user);
  } catch (error) {
    totpError.textContent = error.message;
  }
});

document.getElementById("forgot-password-link").addEventListener("click", () => {
  hideAllViews();
  forgotPasswordView.hidden = false;
});

document.getElementById("forgot-password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  await api.forgotPassword(form.get("email"));
  document.getElementById("forgot-password-message").textContent =
    "Si ce compte existe, un email avec un lien de réinitialisation vient d'être envoyé.";
});

document.getElementById("reset-password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const token = new URLSearchParams(window.location.search).get("reset_token");
  try {
    await api.resetPassword(token, form.get("password"));
    document.getElementById("reset-password-message").textContent =
      "Mot de passe changé. Tu peux te reconnecter.";
    window.history.replaceState({}, "", window.location.pathname);
    showAuthView();
  } catch (error) {
    document.getElementById("reset-password-message").textContent = error.message;
  }
});

document.getElementById("logout-button").addEventListener("click", async () => {
  await api.logout();
  if (socket) socket.close();
  showAuthView();
});

document.getElementById("totp-setup-button").addEventListener("click", async () => {
  const setup = await api.setupTotp();
  document.getElementById("totp-secret").textContent = setup.secret;
  document.getElementById("totp-uri").textContent = setup.uri;
  document.getElementById("totp-setup-details").hidden = false;
});

document.getElementById("totp-confirm-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const message = document.getElementById("totp-setup-message");
  try {
    await api.confirmTotp(form.get("code"));
    document.getElementById("totp-setup-details").hidden = true;
    message.textContent = "2FA activée.";
  } catch (error) {
    message.textContent = error.message;
  }
});

document.getElementById("avatar-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const isUpload = event.submitter?.dataset.action === "upload";

  const updatedUser = isUpload
    ? await api.uploadAvatar(form.get("file"))
    : await api.setDicebearAvatar(form.get("seed"));

  currentUser = updatedUser;
  currentAvatar.src = updatedUser.avatar ? updatedUser.avatar.url : "";
});

document.getElementById("open-dm-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const room = await api.openDm(form.get("username"), form.get("discriminator"));
  await loadRooms();
  await openRoom(room);
});

sendForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!currentRoom) return;
  const form = new FormData(event.target);
  const text = form.get("text");
  event.target.reset();

  const { ciphertext, iv } = await cryptoUtil.encryptMessage(currentRoom.sharedKey, text);
  const message = await api.sendMessage(currentRoom.id, ciphertext, iv);
  await renderMessage(message);
});

(async function init() {
  if (new URLSearchParams(window.location.search).get("reset_token")) {
    hideAllViews();
    resetPasswordView.hidden = false;
    return;
  }
  try {
    const user = await api.me();
    await publishPublicKeyIfNeeded(user);
    showChatView(user);
  } catch {
    showAuthView();
  }
})();
