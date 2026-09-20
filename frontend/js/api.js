/* Accès API : fetch avec cookies de session, CSRF double-submit automatique.
   Toute mutation joint le header X-CSRF-Token (cookie `talk_csrf` côté JS). */

function readCookie(name) {
  const prefix = name + "=";
  for (const part of document.cookie.split("; ")) {
    if (part.startsWith(prefix)) {
      return decodeURIComponent(part.slice(prefix.length));
    }
  }
  return null;
}

async function fetchCsrf() {
  const res = await fetch("/api/auth/csrf", { credentials: "same-origin" });
  if (!res.ok) throw new Error("Impossible d'obtenir le jeton CSRF");
  const data = await res.json();
  return data.csrf_token;
}

async function request(method, path, body) {
  const headers = {};
  const isMutation = method !== "GET";
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (isMutation) {
    let token = readCookie("talk_csrf");
    if (!token) token = await fetchCsrf();
    headers["X-CSRF-Token"] = token;
  }
  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const detail = data && data.detail;
    throw new Error(typeof detail === "string" ? detail : "Erreur HTTP " + res.status);
  }
  return data;
}

export const api = {
  csrf: fetchCsrf,
  register: (username, password) => request("POST", "/api/auth/register", { username, password }),
  login: (username, password) => request("POST", "/api/auth/login", { username, password }),
  logout: () => request("POST", "/api/auth/logout"),
  me: () => request("GET", "/api/auth/me"),
  putKey: (publicKey) => request("PUT", "/api/keys", { public_key: publicKey }),
  rooms: () => request("GET", "/api/rooms"),
  createRoom: (name) => request("POST", "/api/rooms", { name }),
  createDirect: (peer) => request("POST", "/api/rooms/direct", { peer }),
  channels: (roomId) => request("GET", "/api/rooms/" + roomId + "/channels"),
  createChannel: (roomId, name) => request("POST", "/api/rooms/" + roomId + "/channels", { name }),
  members: (roomId) => request("GET", "/api/rooms/" + roomId + "/members"),
  invite: (roomId, username) => request("POST", "/api/rooms/" + roomId + "/invite", { username }),
  leave: (roomId) => request("DELETE", "/api/rooms/" + roomId + "/members/me"),
  transfer: (roomId, to) => request("POST", "/api/rooms/" + roomId + "/transfer", { to }),
  deleteRoom: (roomId) => request("DELETE", "/api/rooms/" + roomId),
  shareKey: (roomId, to, blob) => request("POST", "/api/rooms/" + roomId + "/keys", { to, blob }),
  myKey: (roomId) => request("GET", "/api/rooms/" + roomId + "/keys/me"),
  messages: (roomId, channelId, after) =>
    request("GET", "/api/rooms/" + roomId + "/channels/" + channelId + "/messages?after=" + after),
  friends: () => request("GET", "/api/friends"),
  friendRequests: () => request("GET", "/api/friends/requests"),
  sendFriendRequest: (peer) => request("POST", "/api/friends/requests", { peer }),
  acceptFriend: (username) => request("POST", "/api/friends/requests/" + username + "/accept"),
  reactions: (roomId, channelId) =>
    request("GET", "/api/rooms/" + roomId + "/channels/" + channelId + "/reactions"),
  deleteChannel: (roomId, channelId) =>
    request("DELETE", "/api/rooms/" + roomId + "/channels/" + channelId),
  react: (roomId, channelId, n, blob) =>
    request("POST", "/api/rooms/" + roomId + "/channels/" + channelId + "/reactions", {
      n,
      blob: blob || undefined,
    }),
};