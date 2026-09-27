// Talk — stockage local des clés, dans IndexedDB.
//
// Ce magasin ne contient que des objets `CryptoKey`. Jamais de JWK, jamais de
// clé exportée : ce qui est écrit ici est, par construction, inexploitable par
// une simple lecture de la base.
//
// `localStorage` est volontairement écarté, alors qu'il serait plus simple :
// il ne stocke que des chaînes, donc il faudrait y déposer une clé sérialisable
// — c'est-à-dire extractible. IndexedDB accepte les `CryptoKey` directement, et
// l'estimation de leur extractibilité est conservée.
//
// Limite à garder en tête : ce magasin protège contre l'extraction passive et
// contre l'accès à distance, pas contre une XSS. Un script exécuté dans la page
// peut appeler `subtle.decrypt` avec ces clés. C'est la contrepartie assumée du
// fait de déchiffrer côté client, et la raison pour laquelle la CSP refuse
// tout script tiers.

const DB_NAME = "talk";
const DB_VERSION = 1;
const STORE_IDENTITY = "identity";
const STORE_ROOMS = "rooms";

const IDENTITY_ID = "private";

/** Préfixe des clés de salon qui n'ont pas encore reçu d'identifiant de canal. */
export const PENDING_PREFIX = "pending:";

/** Préfixe des clés de salon rattacherées à un canal. */
export const CHANNEL_PREFIX = "channel:";

/** Identifiant local d'une clé de salon en attente d'attribution de canal. */
export function pendingRoomId(clientRef) {
  return `${PENDING_PREFIX}${clientRef}`;
}

/** Identifiant local d'une clé de salon rattachée à un canal connu. */
export function channelRoomId(channelId) {
  return `${CHANNEL_PREFIX}${channelId}`;
}

/** Vrai tant que la clé de salon n'est rattachée à aucun canal. */
export function isPendingRoomId(id) {
  return typeof id === "string" && id.startsWith(PENDING_PREFIX);
}

let connection = null;

function openDatabase() {
  if (connection) {
    return connection;
  }
  connection = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_IDENTITY)) {
        db.createObjectStore(STORE_IDENTITY, { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains(STORE_ROOMS)) {
        db.createObjectStore(STORE_ROOMS, { keyPath: "id" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error("IndexedDB est bloqué par un autre onglet."));
  });
  return connection;
}

/** Exécute `action` dans une transaction et renvoie son résultat. */
async function withStore(name, mode, action) {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(name, mode);
    const store = transaction.objectStore(name);
    let result;
    try {
      result = action(store);
    } catch (error) {
      reject(error);
      return;
    }
    transaction.oncomplete = () => resolve(result);
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error || new Error("Transaction annulée."));
  });
}

/** Enveloppe une requête IndexedDB dans une promesse. */
function promisify(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/* ------------------------------------------------------------------ */
/* Identité                                                            */
/* ------------------------------------------------------------------ */

/**
 * Identité locale : clé privée, clé publique et empreinte.
 *
 * Renvoie `null` si rien n'a encore été généré. C'est l'état normal d'un
 * navigateur neuf, et non une erreur : l'appelant déclenche alors la
 * génération.
 *
 * La clé publique est conservée ici malgré son caractère public : c'est elle
 * qui permet de comparer l'identité locale à celle que le serveur connaît, et
 * donc de signaler un désaccord au lieu de créer silencieusement une nouvelle
 * paire qui ne pourrait plus lire les canaux existants.
 */
export async function loadIdentity() {
  const db = await openDatabase();
  const transaction = db.transaction(STORE_IDENTITY, "readonly");
  return (await promisify(transaction.objectStore(STORE_IDENTITY).get(IDENTITY_ID))) || null;
}

/** Enregistre l'identité locale. */
export async function storeIdentity(identity) {
  await withStore(STORE_IDENTITY, "readwrite", (store) =>
    store.put({ id: IDENTITY_ID, ...identity, savedAt: new Date().toISOString() }),
  );
}

/* ------------------------------------------------------------------ */
/* Clés de salon                                                       */
/* ------------------------------------------------------------------ */

/** Clé de salon locale, ou `null` si elle n'a pas encore été reçue ou créée. */
export async function loadRoomKey(id) {
  const db = await openDatabase();
  const transaction = db.transaction(STORE_ROOMS, "readonly");
  const stored = await promisify(transaction.objectStore(STORE_ROOMS).get(id));
  return stored ? stored.key : null;
}

/** Identifiants des clés de salon encore en attente d'un canal. */
export async function listPendingRoomIds() {
  const db = await openDatabase();
  const transaction = db.transaction(STORE_ROOMS, "readonly");
  const all = await promisify(transaction.objectStore(STORE_ROOMS).getAllKeys());
  return all.filter(isPendingRoomId);
}

/** Enregistre une clé de salon sous un identifiant local. */
export async function storeRoomKey(id, key) {
  await withStore(STORE_ROOMS, "readwrite", (store) =>
    store.put({ id, key, savedAt: new Date().toISOString() }),
  );
}

/** Supprime une clé de salon locale. */
export async function deleteRoomKey(id) {
  await withStore(STORE_ROOMS, "readwrite", (store) => store.delete(id));
}

/**
 * Rattache une clé de salon en attente au canal qui lui a été attribué.
 *
 * C'est l'opération qui rend la création d'un canal reprenable : la clé est
 * d'abord stockée sous une référence locale, connue avant tout appel réseau,
 * puis renommée dès que le serveur a renvoyé un identifiant. Si le navigateur
 * se ferme entre les deux, la référence locale suffit à retrouver le canal.
 *
 * Renommer plutôt que copier : deux entrées pour une même clé doublerait la
 * surface exposée et laisserait un vestige après le renommage.
 */
export async function moveRoomKey(fromId, toId) {
  if (fromId === toId) {
    return;
  }
  const db = await openDatabase();
  await new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_ROOMS, "readwrite");
    const store = transaction.objectStore(STORE_ROOMS);
    const read = store.get(fromId);
    read.onsuccess = () => {
      const stored = read.result;
      if (!stored) {
        // Rien à déplacer : la clé a déjà été rattachée, ou n'a jamais été
        // créée. Ce n'est pas une erreur, l'appelant est déjà dans l'état cible.
        return;
      }
      store.delete(fromId);
      store.put({ ...stored, id: toId });
    };
    read.onerror = () => reject(read.error);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}

/** Efface toutes les clés locales. Déconnexion ou changement d'identité. */
export async function clearKeystore() {
  const db = await openDatabase();
  await new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_IDENTITY, STORE_ROOMS], "readwrite");
    transaction.objectStore(STORE_IDENTITY).clear();
    transaction.objectStore(STORE_ROOMS).clear();
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}
