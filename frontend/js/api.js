/* Client de l'API REST. Ajoute automatiquement le jeton CSRF sur toutes les requêtes qui modifient l'état. */

let csrfToken = null;
let unauthorizedHandler = () => {};

export class ApiError extends Error {
  constructor(status, message, fields = []) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.fields = fields;
  }
}

export function setCsrfToken(token) {
  csrfToken = token;
}

/** Appelée quand le serveur répond 401 (session expirée ou invalide). */
export function onUnauthorized(handler) {
  unauthorizedHandler = handler;
}

async function refreshCsrfToken() {
  const data = await request('GET', '/api/csrf');
  csrfToken = data.csrf_token;
}

async function request(method, path, body, { retryOnCsrf = true } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') {
    if (!csrfToken) await refreshCsrfToken();
    headers['X-CSRF-Token'] = csrfToken;
  }

  const response = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
  });
  if (response.status === 204) return null;

  const data = await response.json().catch(() => ({}));
  if (response.ok) return data;

  // Jeton CSRF périmé (ex. après une reconnexion) : on en demande un nouveau et on réessaie une fois.
  if (response.status === 403 && retryOnCsrf && String(data.detail).includes('CSRF')) {
    await refreshCsrfToken();
    return request(method, path, body, { retryOnCsrf: false });
  }
  if (response.status === 401 && !path.startsWith('/api/auth/login')) unauthorizedHandler();
  throw new ApiError(response.status, data.detail ?? 'Erreur', data.fields);
}

export const register = (payload) => request('POST', '/api/auth/register', payload);
export const login = (payload) => request('POST', '/api/auth/login', payload);
export const me = () => request('GET', '/api/auth/me');
export const getUser = (username) => request('GET', `/api/users/${encodeURIComponent(username)}`);

export async function logout() {
  try {
    await request('POST', '/api/auth/logout');
  } finally {
    csrfToken = null;
  }
}

export const listRooms = () => request('GET', '/api/rooms');
export const createRoom = (payload) => request('POST', '/api/rooms', payload);
export const getRoom = (roomId) => request('GET', `/api/rooms/${roomId}`);
export const addMember = (roomId, payload) => request('POST', `/api/rooms/${roomId}/members`, payload);

export function history(roomId, before, limit) {
  const query = new URLSearchParams({ limit: String(limit) });
  if (before !== undefined) query.set('before', String(before));
  return request('GET', `/api/rooms/${roomId}/messages?${query}`);
}

export const sendMessage = (roomId, payload) => request('POST', `/api/rooms/${roomId}/messages`, payload);
export const updateProfile = (payload) => request('PUT', '/api/me/profile', payload);
export const setAvatar = (roomId, payload) => request('PUT', `/api/rooms/${roomId}/avatar`, payload);
