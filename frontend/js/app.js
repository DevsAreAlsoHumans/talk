import { api } from "./api.js";
import * as cryptoUtil from "./crypto.js";
import { loadKeyPair, saveKeyPair } from "./idb.js";
import { connectRoomSocket } from "./ws.js";

const authView = document.getElementById("auth-view");
const chatView = document.getElementById("chat-view");
const authError = document.getElementById("auth-error");
const currentUserLabel = document.getElementById("current-user");
const roomList = document.getElementById("room-list");
const activeRoomLabel = document.getElementById("active-room-label");
const messagesList = document.getElementById("messages");
const sendForm = document.getElementById("send-form");

let keyPair = null;
let currentUser = null;
let currentRoom = null; // { id, sharedKey }
let socket = null;

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
  authView.hidden = true;
  chatView.hidden = false;
  loadRooms();
}

function showAuthView() {
  currentUser = null;
  authView.hidden = false;
  chatView.hidden = true;
}

async function loadRooms() {
  const rooms = await api.listRooms();
  roomList.innerHTML = "";
  for (const room of rooms) {
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
    const user = await api.login({
      email: form.get("email"),
      password: form.get("password"),
    });
    await publishPublicKeyIfNeeded(user);
    showChatView(user);
  } catch (error) {
    authError.textContent = error.message;
  }
});

document.getElementById("logout-button").addEventListener("click", async () => {
  await api.logout();
  if (socket) socket.close();
  showAuthView();
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
  try {
    const user = await api.me();
    await publishPublicKeyIfNeeded(user);
    showChatView(user);
  } catch {
    showAuthView();
  }
})();
