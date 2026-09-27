import { api } from "./api.js";
import * as cryptoUtil from "./crypto.js";
import { loadKeyPair, saveKeyPair } from "./idb.js";
import { connectNotificationsSocket, connectRoomSocket } from "./ws.js";

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
const notificationsCount = document.getElementById("notifications-count");
const notificationsList = document.getElementById("notifications-list");

let keyPair = null;
let currentUser = null;
let currentRoom = null; // { id, sharedKey }
let socket = null;
let notificationsSocket = null;
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
  loadNotifications();
  notificationsSocket = connectNotificationsSocket((notification) => {
    renderNotification(notification, /* prepend= */ true);
    updateNotificationsCount();
  });
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
  const author = message.sender_id === currentUser.id ? "Moi" : "Eux";
  try {
    const plaintext = message.ciphertext
      ? await cryptoUtil.decryptMessage(currentRoom.sharedKey, message.ciphertext, message.iv)
      : "";
    item.textContent = plaintext ? `${author} : ${plaintext}` : `${author} :`;
  } catch {
    item.textContent = "[message illisible]";
  }

  if (message.attachment) {
    const downloadButton = document.createElement("button");
    downloadButton.textContent = `Pièce jointe chiffrée (${message.attachment.size} octets)`;
    downloadButton.addEventListener("click", () => downloadAndDecryptAttachment(message));
    item.appendChild(downloadButton);
  }

  messagesList.appendChild(item);
}

async function downloadAndDecryptAttachment(message) {
  const ciphertextBuffer = await api.downloadAttachment(currentRoom.id, message.attachment.id);
  const plainBuffer = await cryptoUtil.decryptBytes(
    currentRoom.sharedKey,
    ciphertextBuffer,
    message.attachment.iv
  );
  // Le nom/type d'origine n'est jamais transmis en clair au serveur (limitation assumée) :
  // le fichier est téléchargé sous un nom générique.
  const blob = new Blob([plainBuffer]);
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "piece-jointe";
  link.click();
  URL.revokeObjectURL(url);
}

function renderNotification(notification, prepend) {
  const item = document.createElement("li");
  item.textContent = `[${notification.type}] ${JSON.stringify(notification.payload)}`;
  item.dataset.notificationId = notification.id;
  if (!notification.read) item.style.fontWeight = "bold";
  item.addEventListener("click", async () => {
    await api.markNotificationRead(notification.id);
    item.style.fontWeight = "normal";
    updateNotificationsCount();
  });
  if (prepend) {
    notificationsList.insertBefore(item, notificationsList.firstChild);
  } else {
    notificationsList.appendChild(item);
  }
}

function updateNotificationsCount() {
  const unread = notificationsList.querySelectorAll("li[style*='bold']").length;
  notificationsCount.textContent = String(unread);
}

async function loadNotifications() {
  const notifications = await api.listNotifications();
  notificationsList.innerHTML = "";
  for (const notification of notifications) {
    renderNotification(notification, false);
  }
  updateNotificationsCount();
}

document.getElementById("notifications-toggle").addEventListener("click", () => {
  notificationsList.hidden = !notificationsList.hidden;
});

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
  if (notificationsSocket) notificationsSocket.close();
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
  const text = form.get("text") || "";
  const file = form.get("file");
  event.target.reset();

  let attachmentId = null;
  if (file && file.size > 0) {
    const fileBuffer = await file.arrayBuffer();
    const encryptedFile = await cryptoUtil.encryptBytes(currentRoom.sharedKey, fileBuffer);
    const attachment = await api.uploadAttachment(
      currentRoom.id,
      new Blob([encryptedFile.ciphertext]),
      encryptedFile.iv
    );
    attachmentId = attachment.id;
  }

  const { ciphertext, iv } = await cryptoUtil.encryptMessage(currentRoom.sharedKey, text);
  const message = await api.sendMessage(currentRoom.id, ciphertext, iv, attachmentId);
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
