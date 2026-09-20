/* Chiffrement de bout en bout — Web Crypto API uniquement, zéro dépendance.

   Identité      : paire ECDH P-256 non-extractable, persistée en IndexedDB.
   Clé de salon  : AES-GCM 256, enveloppée par membre via ECDH + HKDF.
   Messages      : AES-GCM avec AAD `roomId|from` — le `from` est attesté par
                   le serveur (session signée), donc authentifie l'expéditeur.
*/

const enc = new TextEncoder();
const dec = new TextDecoder();

export function b64(bytes) {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < u.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function unb64(str) {
  const bin = atob(str);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

function openIndexedDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("talk", 1);
    req.onupgradeneeded = () => req.result.createObjectStore("keys");
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet(key) {
  const db = await openIndexedDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("keys", "readonly").objectStore("keys").get(key);
    tx.onsuccess = () => resolve(tx.result);
    tx.onerror = () => reject(tx.error);
  });
}

async function idbSet(key, value) {
  const db = await openIndexedDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("keys", "readwrite").objectStore("keys").put(value, key);
    tx.onsuccess = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/* Identité persistante : paire ECDH P-256 par pseudo (par navigateur). */
export async function ensureIdentity(username) {
  const stored = await idbGet(username);
  if (stored) return stored;
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits", "deriveKey"],
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const identity = {
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    publicRaw: b64(raw),
  };
  await idbSet(username, identity);
  return identity;
}

function deriveShared(identity, peerPublicRawB64) {
  return crypto.subtle
    .importKey(
      "raw",
      unb64(peerPublicRawB64),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    )
    .then((peer) =>
      crypto.subtle.deriveBits({ name: "ECDH", public: peer }, identity.privateKey, 256),
    );
}

/* KEK = HKDF(ECDH(priv, peerPub), salt=contexte du salon) : partage déterministe. */
function deriveKEK(identity, peerPublicRawB64, roomId) {
  return deriveShared(identity, peerPublicRawB64).then((shared) =>
    crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: enc.encode("talk-room-v1:" + roomId),
        info: enc.encode("talk-ekey-v1"),
      },
      shared,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    ),
  );
}

/* Clé de salon : AES-GCM 256 aléatoire, exportable pour l'enveloppement. */
export async function generateRoomKey() {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  return { key, raw };
}

/* Enveloppe la clé de salon pour un membre (blob opaque, seule forme stockée). */
export async function wrapRoomKey(identity, peerPublicRawB64, roomId, raw) {
  const kek = await deriveKEK(identity, peerPublicRawB64, roomId);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, kek, raw),
  );
  return { v: 1, iv: b64(iv), ct: b64(ct) };
}

/* Déwrape ma clé de salon : copie non-extractable (utilisation seule). */
export async function unwrapRoomKey(identity, ownerPublicRawB64, roomId, blob) {
  if (blob.v !== 1) throw new Error("clé de salon au format inconnu");
  const kek = await deriveKEK(identity, ownerPublicRawB64, roomId);
  const raw = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64(blob.iv), tagLength: 128 },
      kek,
      unb64(blob.ct),
    ),
  );
  const key = await crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
  return { key, raw };
}

/* Chiffre AVANT l'envoi WebSocket : IV neuf + AAD lié au salon et à l'émetteur. */
export async function encryptMessage(roomKey, roomId, from, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = enc.encode(roomId + "|" + from);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
      roomKey,
      enc.encode(text),
    ),
  );
  return JSON.stringify({ v: 1, iv: b64(iv), ct: b64(ct) });
}

/* Déchiffre APRÈS réception. Toute erreur GCM => null (tamper/rejeu rejeté). */
export async function decryptMessage(roomKey, roomId, from, blob) {
  let parsed;
  try {
    parsed = JSON.parse(blob);
  } catch {
    return null;
  }
  if (!parsed || parsed.v !== 1 || typeof parsed.iv !== "string" || typeof parsed.ct !== "string") {
    return null;
  }
  if (unb64(parsed.iv).length !== 12 || unb64(parsed.ct).length > 128 * 1024) {
    return null;
  }
  try {
    const aad = enc.encode(roomId + "|" + from);
    const pt = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: unb64(parsed.iv),
        additionalData: aad,
        tagLength: 128,
      },
      roomKey,
      unb64(parsed.ct),
    );
    return dec.decode(pt);
  } catch {
    return null;
  }
}