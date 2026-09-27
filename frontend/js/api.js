// Talk — accès à l'API.
//
// Regroupe tout ce qui touche au réseau dans un seul module, pour deux raisons :
// le jeton CSRF ne doit être lu et appliqué qu'ici, et `app.js` comme
// `chat.js` ont besoin des mêmes règles sans s'importer l'un l'autre.

/** En-tête exigé par le serveur sur toute mutation. */
export const CSRF_HEADER = "X-CSRF-Token";

const CSRF_COOKIE = "talk_csrf";

export function readCookie(name) {
  const prefix = `${name}=`;
  const found = document.cookie.split("; ").find((entry) => entry.startsWith(prefix));
  return found ? decodeURIComponent(found.slice(prefix.length)) : "";
}

/**
 * Jeton CSRF courant, en le demandant au serveur s'il manque.
 *
 * Le cookie `talk_csrf` n'est pas `HttpOnly` : le JavaScript doit pouvoir le
 * renvoyer dans l'en-tête exigé sur chaque mutation. C'est le seul moment où une
 * donnée du cookie est lue par le script, et il ne s'agit pas d'un secret.
 */
export async function ensureCsrfToken() {
  const existing = readCookie(CSRF_COOKIE);
  if (existing) {
    return existing;
  }
  const response = await fetch("/auth/csrf", { credentials: "same-origin" });
  if (!response.ok) {
    return "";
  }
  return (await response.json()).csrf_token;
}

async function request(method, path, body) {
  const headers = {};
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (method !== "GET") {
    headers[CSRF_HEADER] = await ensureCsrfToken();
  }
  return fetch(path, {
    method,
    credentials: "same-origin",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export async function getJson(path) {
  return request("GET", path);
}

export async function postJson(path, body) {
  return request("POST", path, body);
}

export async function putJson(path, body) {
  return request("PUT", path, body);
}

export async function deleteJson(path) {
  return request("DELETE", path);
}

/**
 * Traduit une réponse en erreur en message lisible, ou renvoie son JSON.
 *
 * Le serveur répond toujours `{"detail": "..."}` sur un refus, et ce texte est
 * déjà rédigé pour être affiché : il n'y a pas de message à composer ici.
 */
export async function expectJson(response) {
  if (response.ok) {
    return response.status === 204 ? null : response.json();
  }
  let detail = `La requête a échoué (${response.status}).`;
  try {
    const body = await response.json();
    detail = body.detail || detail;
  } catch {
    // Réponse sans corps JSON : on conserve le message générique.
  }
  throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
}

/** Ouvre le WebSocket d'un canal. La session passe par le cookie. */
export function openChannelSocket(channelId) {
  const scheme = globalThis.location.protocol === "https:" ? "wss" : "ws";
  return new WebSocket(`${scheme}://${globalThis.location.host}/channels/${channelId}`);
}
