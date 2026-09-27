function getCookie(name) {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

async function request(method, path, body) {
  const headers = {};
  let payload;
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  if (method !== "GET") {
    const csrfToken = getCookie("csrf_token");
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  }

  const response = await fetch(path, { method, headers, body: payload, credentials: "include" });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const errorBody = await response.json();
      detail = errorBody.detail || detail;
    } catch {
      // pas de corps JSON exploitable, on garde le statusText
    }
    throw new Error(detail);
  }

  if (response.status === 204) return null;
  return response.json();
}

async function uploadMultipart(path, formData) {
  const csrfToken = getCookie("csrf_token");
  const response = await fetch(path, {
    method: "POST",
    headers: csrfToken ? { "X-CSRF-Token": csrfToken } : {},
    body: formData,
    credentials: "include",
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || response.statusText);
  }
  return response.json();
}

function uploadAvatar(file) {
  const formData = new FormData();
  formData.append("file", file);
  return uploadMultipart("/users/me/avatar/upload", formData);
}

function uploadAttachment(roomId, ciphertextBlob, iv, contentType) {
  const formData = new FormData();
  formData.append("iv", iv);
  if (contentType) formData.append("content_type", contentType);
  formData.append("file", ciphertextBlob, "blob");
  return uploadMultipart(`/rooms/${roomId}/attachments`, formData);
}

async function downloadAttachment(roomId, attachmentId) {
  const response = await fetch(`/rooms/${roomId}/attachments/${attachmentId}`, {
    credentials: "include",
  });
  if (!response.ok) throw new Error("Impossible de télécharger la pièce jointe.");
  return response.arrayBuffer();
}

export const api = {
  register: (data) => request("POST", "/auth/register", data),
  login: (data) => request("POST", "/auth/login", data),
  logout: () => request("POST", "/auth/logout"),
  me: () => request("GET", "/auth/me"),
  verifyTotp: (pendingToken, code) =>
    request("POST", "/auth/2fa/verify", { pending_token: pendingToken, code }),
  setupTotp: () => request("POST", "/auth/2fa/setup"),
  confirmTotp: (code) => request("POST", "/auth/2fa/confirm", { code }),
  disableTotp: (code) => request("POST", "/auth/2fa/disable", { code }),
  forgotPassword: (email) => request("POST", "/auth/forgot-password", { email }),
  resetPassword: (token, newPassword) =>
    request("POST", "/auth/reset-password", { token, new_password: newPassword }),
  setPublicKey: (publicKey) => request("PUT", "/users/me/public-key", { public_key: publicKey }),
  setDicebearAvatar: (seed) => request("PUT", "/users/me/avatar/dicebear", { seed }),
  uploadAvatar,
  openDm: (username, discriminator) => request("POST", "/rooms/dm", { username, discriminator }),
  createGroupRoom: (name) => request("POST", "/rooms/groups", { name }),
  joinGeneral: () => request("POST", "/rooms/general/join"),
  addRoomMember: (roomId, username, discriminator) =>
    request("POST", `/rooms/${roomId}/members`, { username, discriminator }),
  removeRoomMember: (roomId, memberId) =>
    request("DELETE", `/rooms/${roomId}/members/${memberId}`),
  listRooms: () => request("GET", "/rooms"),
  listMessages: (roomId) => request("GET", `/rooms/${roomId}/messages`),
  sendMessage: (roomId, ciphertext, iv, attachmentId, keyEpoch) =>
    request("POST", `/rooms/${roomId}/messages`, {
      ciphertext,
      iv,
      attachment_id: attachmentId || null,
      key_epoch: keyEpoch ?? null,
    }),
  deleteMessage: (roomId, messageId) =>
    request("DELETE", `/rooms/${roomId}/messages/${messageId}`),
  uploadAttachment,
  downloadAttachment,
  rotateGroupKey: (roomId, wrapperPublicKey, entries) =>
    request("POST", `/rooms/${roomId}/keys`, { wrapper_public_key: wrapperPublicKey, entries }),
  getGroupKeys: (roomId) => request("GET", `/rooms/${roomId}/keys`),
  listNotifications: () => request("GET", "/notifications"),
  markNotificationRead: (notificationId) =>
    request("POST", `/notifications/${notificationId}/read`),
  markAllNotificationsRead: () => request("POST", "/notifications/read-all"),
  deleteNotification: (notificationId) => request("DELETE", `/notifications/${notificationId}`),
};
