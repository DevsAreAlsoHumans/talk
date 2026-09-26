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

export const api = {
  register: (data) => request("POST", "/auth/register", data),
  login: (data) => request("POST", "/auth/login", data),
  logout: () => request("POST", "/auth/logout"),
  me: () => request("GET", "/auth/me"),
  setPublicKey: (publicKey) => request("PUT", "/users/me/public-key", { public_key: publicKey }),
  openDm: (username, discriminator) => request("POST", "/rooms/dm", { username, discriminator }),
  listRooms: () => request("GET", "/rooms"),
  listMessages: (roomId) => request("GET", `/rooms/${roomId}/messages`),
  sendMessage: (roomId, ciphertext, iv) =>
    request("POST", `/rooms/${roomId}/messages`, { ciphertext, iv }),
};
