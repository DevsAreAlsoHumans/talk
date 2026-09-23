/**
 * api.js — Couche réseau (fetch) commune.
 *
 * Règles du contrat (PLAN.md §3) :
 *   - Tout passe par l'origine courante : chemins RELATIFS (`/api/...`).
 *     Le backend FastAPI monte l'API sous `/api`, le frontend à la racine,
 *     donc aucune URL absolue n'est nécessaire (pas de CORS).
 *   - Toute mutation (POST/PUT/PATCH/DELETE) exige :
 *       1. une session anonyme préalable via `GET /api/csrf` →
 *          token conservé dans `localStorage["talk.csrf_token"]` ;
 *       2. l'en-tête `X-CSRF-Token` avec ce token.
 *   - Si une mutation échoue en 403 (token périmé — session anonyme perdue
 *     côté serveur, ex. redémarrage de Redis), `api()` SE RÉPARE : elle jette
 *     le token, récupère une session fraîche puis rejoue la requête une fois.
 *   - Les erreurs sont renvoyées par le serveur sous la forme
 *     `{ "detail": "..." }` (éventuellement une liste pour la validation).
 */

const CSRF_KEY = "talk.csrf_token";

const MUTATIONS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** Erreur applicative enrichie du code HTTP. */
export class ApiError extends Error {
  /**
   * @param {string} message Message destiné à l'utilisateur.
   * @param {number} status  Code HTTP (0 si erreur réseau).
   */
  constructor(message, status) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/** Récupère `talk.csrf_token` s'il n'existe pas encore (session anonyme). */
async function ensureCsrfToken() {
  if (localStorage.getItem(CSRF_KEY)) {
    return;
  }
  const data = await api("/api/csrf", { method: "GET" });
  localStorage.setItem(CSRF_KEY, data.csrf_token);
}

/**
 * Requête HTTP vers l'API (même origine).
 *
 * @param {string} path Ex. : "/api/auth/login"
 * @param {{method?: string, body?: object}} [options]
 * @param {boolean} [alreadyRetried] Interne : vrai après une tentative de
 *   réparation CSRF — évite toute boucle.
 * @returns {Promise<any>} Corps JSON parsé (ou null si 204).
 * @throws {ApiError}
 */
export async function api(path, { method = "GET", body } = {}, alreadyRetried = false) {
  const headers = {};
  let payload = undefined;

  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }

  if (MUTATIONS.has(method)) {
    await ensureCsrfToken();
    headers["X-CSRF-Token"] = localStorage.getItem(CSRF_KEY) || "";
  }

  let response;
  try {
    response = await fetch(path, { method, headers, body: payload });
  } catch {
    throw new ApiError("Serveur injoignable. Vérifiez votre connexion.", 0);
  }

  // Réponse sans contenu.
  if (response.status === 204) {
    return null;
  }

  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  // Auto-réparation CSRF : le token mis en cache peut être périmé (session
  // anonyme perdue côté serveur — ex. redémarrage de Redis, TTL écoulé).
  // On jette le token, on refait GET /api/csrf (nouvelle session + cookie)
  // et on rejoue UNE SEULE fois la mutation.
  if (!alreadyRetried && MUTATIONS.has(method) && response.status === 403) {
    localStorage.removeItem(CSRF_KEY);
    return api(path, { method, body }, true);
  }

  if (!response.ok) {
    throw new ApiError(extractDetail(data, response.status), response.status);
  }
  return data;
}

/**
 * Extrait un message lisible du champ `detail` (string ou tableau de
 * messages de validation Pydantic).
 */
function extractDetail(data, fallbackStatus) {
  if (!data) {
    return "Erreur serveur (" + fallbackStatus + ").";
  }
  const detail = data.detail;
  if (typeof detail === "string") {
    return detail;
  }
  if (Array.isArray(detail)) {
    return detail.map((item) => (item && item.msg) || String(item)).join(" ; ");
  }
  return "Erreur serveur (" + fallbackStatus + ").";
}