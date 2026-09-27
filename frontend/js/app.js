import { api } from "./api.js";
import * as cryptoUtil from "./crypto.js";
import { ensureKeyPair, publishPublicKeyIfNeeded } from "./keys.js";
import { connectNotificationsSocket, connectRoomSocket } from "./ws.js";
import { drawQrToCanvas } from "./qrcode.js";

// Découpe un champ unique "pseudo#0000" saisi par l'utilisateur en
// {username, discriminator}, utilisé partout où on cible un autre compte.
function parseTag(value) {
  const separatorIndex = value.lastIndexOf("#");
  return {
    username: value.slice(0, separatorIndex),
    discriminator: value.slice(separatorIndex + 1),
  };
}

const chatView = document.getElementById("chat-view");
const currentUserLabel = document.getElementById("current-user");
const currentAvatar = document.getElementById("current-avatar");
const roomList = document.getElementById("room-list");
const activeRoomLabel = document.getElementById("active-room-label");
const addGroupMemberForm = document.getElementById("add-group-member-form");
const groupMembersList = document.getElementById("group-members-list");
const messagesList = document.getElementById("messages");
const sendForm = document.getElementById("send-form");
const notificationsCount = document.getElementById("notifications-count");
const notificationsList = document.getElementById("notifications-list");

let currentUser = null;
// DM     : { type: "dm", id, sharedKey }
// Groupe : { type: "group", id, room, keysByEpoch: Map<epoch, CryptoKey>, currentEpoch }
let currentRoom = null;
let socket = null;
let notificationsSocket = null;

function goToLogin() {
  window.location.href = "/login";
}

function showChatView(user) {
  currentUser = user;
  currentUserLabel.textContent = `${user.username}#${user.discriminator}`;
  currentAvatar.src = user.avatar ? user.avatar.url : "";
  chatView.hidden = false;
  loadRooms();
  loadNotifications();
  notificationsSocket = connectNotificationsSocket((notification) => {
    renderNotification(notification, /* prepend= */ true);
    updateNotificationsCount();
  });
}

async function loadRooms() {
  const rooms = await api.listRooms();
  roomList.innerHTML = "";
  for (const room of rooms) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.textContent =
      room.type === "dm" ? `${room.peer.username}#${room.peer.discriminator}` : `# ${room.name}`;
    button.addEventListener("click", () => openRoom(room));
    item.appendChild(button);
    roomList.appendChild(item);
  }
}

// Enveloppe une nouvelle clé de salon pour chaque membre actuel (ECDH avec sa clé
// publique) et l'envoie au serveur : c'est la rotation déclenchée à chaque
// création de groupe et à chaque changement de membres.
async function rotateGroupKeyFor(room) {
  const missingKeyMember = room.members.find((member) => !member.user.public_key);
  if (missingKeyMember) {
    throw new Error(
      `${missingKeyMember.user.username}#${missingKeyMember.user.discriminator} n'a pas encore ` +
        "de clé publique (il doit se connecter au moins une fois) : rotation impossible."
    );
  }

  const pair = await ensureKeyPair(currentUser.id);
  const newRoomKey = await cryptoUtil.generateRoomKey();
  const myPublicKeyRaw = await cryptoUtil.exportPublicKeyRaw(pair.publicKey);

  const entries = [];
  for (const member of room.members) {
    const { wrappedKey, wrappedKeyIv } = await cryptoUtil.wrapRoomKeyForMember(
      pair.privateKey,
      member.user.public_key,
      newRoomKey
    );
    entries.push({
      member_id: member.user.id,
      wrapped_key: wrappedKey,
      wrapped_key_iv: wrappedKeyIv,
    });
  }

  const updatedRoom = await api.rotateGroupKey(room.id, myPublicKeyRaw, entries);
  return { updatedRoom, newRoomKey };
}

async function refreshGroupAfterMembershipChange(updatedRoomFromMembershipCall) {
  const { updatedRoom, newRoomKey } = await rotateGroupKeyFor(updatedRoomFromMembershipCall);
  currentRoom.room = updatedRoom;
  currentRoom.currentEpoch = updatedRoom.key_epoch;
  currentRoom.keysByEpoch.set(updatedRoom.key_epoch, newRoomKey);
  renderGroupMembers(updatedRoom);
}

async function loadGroupKeys(room, myPrivateKey) {
  const entries = await api.getGroupKeys(room.id);
  const keysByEpoch = new Map();
  for (const entry of entries) {
    try {
      const key = await cryptoUtil.unwrapRoomKey(
        myPrivateKey,
        entry.wrapper_public_key,
        entry.wrapped_key,
        entry.wrapped_key_iv
      );
      keysByEpoch.set(entry.epoch, key);
    } catch {
      // Une epoch illisible ne bloque pas les autres (ne devrait pas arriver en pratique).
    }
  }
  return keysByEpoch;
}

function renderGroupMembers(room) {
  groupMembersList.innerHTML = "";
  const myRole = room.members.find((member) => member.user.id === currentUser.id)?.role;
  for (const member of room.members) {
    const item = document.createElement("li");
    item.textContent = `${member.user.username}#${member.user.discriminator} (${member.role}) `;
    if ((myRole === "owner" || myRole === "admin") && member.user.id !== currentUser.id) {
      const kickButton = document.createElement("button");
      kickButton.textContent = "Retirer";
      kickButton.addEventListener("click", () => kickMember(member.user.id));
      item.appendChild(kickButton);
    }
    groupMembersList.appendChild(item);
  }
}

async function kickMember(memberId) {
  await api.removeRoomMember(currentRoom.id, memberId);
  const updatedRoom = {
    ...currentRoom.room,
    members: currentRoom.room.members.filter((member) => member.user.id !== memberId),
  };
  await refreshGroupAfterMembershipChange(updatedRoom);
  await loadRooms();
}

async function openRoom(room) {
  if (socket) socket.close();
  const pair = await ensureKeyPair(currentUser.id);

  if (room.type === "dm") {
    addGroupMemberForm.hidden = true;
    groupMembersList.innerHTML = "";

    if (!room.peer.public_key) {
      activeRoomLabel.textContent = `${room.peer.username}#${room.peer.discriminator} n'a pas encore de clé publique (il doit se connecter au moins une fois).`;
      sendForm.hidden = true;
      currentRoom = null;
      return;
    }

    const peerPublicKey = await cryptoUtil.importPeerPublicKey(room.peer.public_key);
    const sharedKey = await cryptoUtil.deriveSharedKey(pair.privateKey, peerPublicKey);
    currentRoom = { type: "dm", id: room.id, sharedKey, peer: room.peer };
    activeRoomLabel.textContent = `DM avec ${room.peer.username}#${room.peer.discriminator}`;
  } else {
    const keysByEpoch = await loadGroupKeys(room, pair.privateKey);
    currentRoom = {
      type: "group",
      id: room.id,
      room,
      keysByEpoch,
      currentEpoch: room.key_epoch,
    };
    activeRoomLabel.textContent = `Groupe : ${room.name}`;
    renderGroupMembers(room);
    addGroupMemberForm.hidden = false;
  }

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

function keyForMessage(message) {
  if (currentRoom.type === "dm") return currentRoom.sharedKey;
  return currentRoom.keysByEpoch.get(message.key_epoch);
}

function authorLabel(senderId) {
  if (senderId === currentUser.id) return "Moi";
  if (currentRoom.type === "dm") {
    return `${currentRoom.peer.username}#${currentRoom.peer.discriminator}`;
  }
  const member = currentRoom.room.members.find((m) => m.user.id === senderId);
  return member ? `${member.user.username}#${member.user.discriminator}` : "Inconnu";
}

async function renderMessage(message) {
  const item = document.createElement("li");
  const author = authorLabel(message.sender_id);
  try {
    const key = keyForMessage(message);
    if (!key) throw new Error("clé manquante pour cette epoch");
    const plaintext = message.ciphertext
      ? await cryptoUtil.decryptMessage(key, message.ciphertext, message.iv)
      : "";
    item.textContent = plaintext ? `${author} : ${plaintext}` : `${author} :`;
  } catch {
    item.textContent = "[message illisible]";
  }

  if (message.attachment) {
    if (message.attachment.content_type?.startsWith("image/")) {
      const img = document.createElement("img");
      img.className = "attachment-image";
      img.alt = "Image envoyée dans le salon";
      decryptAttachmentBlob(message)
        .then((blob) => {
          img.src = URL.createObjectURL(blob);
        })
        .catch(() => {
          img.replaceWith(document.createTextNode("[image illisible]"));
        });
      item.appendChild(img);
    } else {
      const downloadButton = document.createElement("button");
      downloadButton.textContent = `Pièce jointe chiffrée (${message.attachment.size} octets)`;
      downloadButton.addEventListener("click", () => downloadAndDecryptAttachment(message));
      item.appendChild(downloadButton);
    }
  }

  messagesList.appendChild(item);
}

async function decryptAttachmentBlob(message) {
  const key = keyForMessage(message);
  const ciphertextBuffer = await api.downloadAttachment(currentRoom.id, message.attachment.id);
  const plainBuffer = await cryptoUtil.decryptBytes(key, ciphertextBuffer, message.attachment.iv);
  return new Blob([plainBuffer], { type: message.attachment.content_type || "" });
}

async function downloadAndDecryptAttachment(message) {
  const blob = await decryptAttachmentBlob(message);
  // Le nom d'origine n'est jamais transmis en clair au serveur (limitation
  // assumée) : le fichier est téléchargé sous un nom générique.
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "piece-jointe";
  link.click();
  URL.revokeObjectURL(url);
}

function describeNotification({ type, payload }) {
  switch (type) {
    case "message":
      return `💬 Nouveau message de ${payload.sender_label || "quelqu'un"}`;
    case "friend_request":
      return `👤 ${payload.from_label || "Quelqu'un"} t'a envoyé une demande d'ami`;
    case "friend_accepted":
      return `✅ ${payload.peer_label || "Quelqu'un"} a accepté ta demande d'ami`;
    case "room_invite":
      return `📨 ${payload.invited_by_label || "Quelqu'un"} t'a ajouté au salon "${payload.room_name}"`;
    default:
      return `[${type}] ${JSON.stringify(payload)}`;
  }
}

function renderNotification(notification, prepend) {
  const item = document.createElement("li");
  item.textContent = describeNotification(notification);
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

document.getElementById("logout-button").addEventListener("click", async () => {
  await api.logout();
  if (socket) socket.close();
  if (notificationsSocket) notificationsSocket.close();
  goToLogin();
});

let pendingTotpUri = null;

document.getElementById("totp-setup-button").addEventListener("click", async () => {
  const setup = await api.setupTotp();
  pendingTotpUri = setup.uri;
  document.getElementById("totp-secret").textContent = setup.secret;
  drawQrToCanvas(document.getElementById("totp-qr-canvas"), setup.uri);
  document.getElementById("totp-setup-details").hidden = false;
});

document.getElementById("totp-copy-secret").addEventListener("click", async () => {
  await navigator.clipboard.writeText(document.getElementById("totp-secret").textContent);
  document.getElementById("totp-setup-message").textContent = "Secret copié.";
});

document.getElementById("totp-copy-uri").addEventListener("click", async () => {
  if (!pendingTotpUri) return;
  await navigator.clipboard.writeText(pendingTotpUri);
  document.getElementById("totp-setup-message").textContent = "Lien d'import copié.";
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
  const { username, discriminator } = parseTag(form.get("tag"));
  const room = await api.openDm(username, discriminator);
  await loadRooms();
  await openRoom(room);
});

document.getElementById("create-group-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const room = await api.createGroupRoom(form.get("name"));
  event.target.reset();

  const { updatedRoom } = await rotateGroupKeyFor(room);
  await loadRooms();
  await openRoom(updatedRoom);
});

addGroupMemberForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!currentRoom || currentRoom.type !== "group") return;
  const form = new FormData(event.target);
  const { username, discriminator } = parseTag(form.get("tag"));
  const updatedRoomFromAdd = await api.addRoomMember(currentRoom.id, username, discriminator);
  event.target.reset();

  await refreshGroupAfterMembershipChange(updatedRoomFromAdd);
  await loadRooms();
});

sendForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!currentRoom) return;
  const form = new FormData(event.target);
  const text = form.get("text") || "";
  const file = form.get("file");
  event.target.reset();

  const key =
    currentRoom.type === "dm"
      ? currentRoom.sharedKey
      : currentRoom.keysByEpoch.get(currentRoom.currentEpoch);
  const epoch = currentRoom.type === "group" ? currentRoom.currentEpoch : null;

  let attachmentId = null;
  if (file && file.size > 0) {
    const fileBuffer = await file.arrayBuffer();
    const encryptedFile = await cryptoUtil.encryptBytes(key, fileBuffer);
    const attachment = await api.uploadAttachment(
      currentRoom.id,
      new Blob([encryptedFile.ciphertext]),
      encryptedFile.iv,
      file.type
    );
    attachmentId = attachment.id;
  }

  const { ciphertext, iv } = await cryptoUtil.encryptMessage(key, text);
  const message = await api.sendMessage(currentRoom.id, ciphertext, iv, attachmentId, epoch);
  await renderMessage(message);
});

// Rejoint le salon public #général (créé au premier appel) et, si on n'a pas
// encore la clé de l'epoch courante (nouvel arrivant, ou salon qui vient
// d'être créé), fait tourner la clé pour la rendre lisible immédiatement.
async function joinGeneralChannel() {
  const room = await api.joinGeneral();
  const myKeyEntries = await api.getGroupKeys(room.id);
  const hasCurrentEpochKey = myKeyEntries.some((entry) => entry.epoch === room.key_epoch);
  if (room.key_epoch === 0 || !hasCurrentEpochKey) {
    await rotateGroupKeyFor(room);
  }
}

(async function init() {
  let user;
  try {
    user = await api.me();
  } catch {
    // Seul un vrai échec d'authentification doit renvoyer vers /login : les
    // étapes suivantes (clé publique, #général) ne doivent jamais provoquer
    // ce redirect, sous peine de boucle infinie /  <->  /login.
    goToLogin();
    return;
  }

  try {
    await publishPublicKeyIfNeeded(user);
  } catch (error) {
    console.error("Impossible de publier la clé publique :", error);
  }

  try {
    await joinGeneralChannel();
  } catch (error) {
    console.error("Impossible de rejoindre #général :", error);
  }

  showChatView(user);
})();
