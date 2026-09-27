/**
 * Client HTTP.
 *
 * - Le jeton CSRF est lu dans le cookie lisible et renvoyé en en-tête :
 *   c'est la double soumission attendue par le backend.
 * - `credentials: "same-origin"` envoie le cookie de session httpOnly,
 *   qui n'est donc jamais accessible au JavaScript de la page.
 */

export class ApiError extends Error {
  constructor(status, detail) {
    super(
      Array.isArray(detail)
        ? detail.map((item) => item?.msg).filter(Boolean).join(" ; ") || `Erreur ${status}`
        : detail || `Erreur ${status}`,
    );
    this.status = status;
    this.detail = detail;
  }
}

function readCookie(name) {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

async function request(method, path, body) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") {
    const token = readCookie("csrf_token");
    if (token) headers["X-CSRF-Token"] = token;
  }
  const response = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 204) return null;
  const payload = response.headers.get("content-type")?.includes("application/json")
    ? await response.json()
    : null;
  if (!response.ok) {
    throw new ApiError(response.status, payload?.detail || null);
  }
  return payload;
}

export const api = {
  csrf: () => request("GET", "/auth/csrf"),
  me: () => request("GET", "/auth/me"),
  register: (username, password) =>
    request("POST", "/auth/register", { username, password }),
  login: (username, password) => request("POST", "/auth/login", { username, password }),
  logout: () => request("POST", "/auth/logout"),

  listSalons: () => request("GET", "/salons"),
  createSalon: (name) => request("POST", "/salons", { name }),
  listChannels: (salonId) => request("GET", `/salons/${encodeURIComponent(salonId)}/channels`),
  addMember: (salonId, username) =>
    request("POST", `/salons/${encodeURIComponent(salonId)}/members`, { username }),

  publishPublicKey: (publicKey) => request("PUT", "/keys", { public_key: publicKey }),
  readPublicKey: (userId) => request("GET", `/keys/${encodeURIComponent(userId)}`),
  readOwnChannelKey: (channelId) =>
    request("GET", `/channels/${encodeURIComponent(channelId)}/key`),
  publishChannelKey: (channelId, wrappedKey, iv, userId) =>
    request("PUT", `/channels/${encodeURIComponent(channelId)}/key`, {
      wrapped_key: wrappedKey,
      iv,
      ...(userId ? { user_id: userId } : {}),
    }),
  // L'API enveloppe la liste dans { members: [...] } : on renvoie le tableau,
  // sinon les appelants itèrent un objet.
  listMembers: async (salonId) =>
    (await request("GET", `/salons/${encodeURIComponent(salonId)}/members`)).members,
  readChannelKeys: (channelId) =>
    request("GET", `/channels/${encodeURIComponent(channelId)}/keys`),

  sendMessage: (channelId, envelope) =>
    request("POST", `/channels/${encodeURIComponent(channelId)}/messages`, envelope),
  history: (channelId, before) =>
    request(
      "GET",
      `/channels/${encodeURIComponent(channelId)}/messages?limit=50` +
        (before ? `&before=${encodeURIComponent(before)}` : ""),
    ),
  poll: (channelId, after) =>
    request("GET", `/channels/${encodeURIComponent(channelId)}/messages/poll?after=${after}`),
};
