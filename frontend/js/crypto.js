/**
 * crypto.js — Tout le chiffrement de bout en bout (WebCrypto).
 *
 * Le serveur ne reçoit jamais de texte clair ni de clé privée.
 * Formats contractuels (PLAN.md §3) :
 *   - Clé publique utilisateur : RSA-OAEP-256 (2048 bits), export SPKI → base64.
 *   - Clé de salon            : 32 octets aléatoires (AES-256-GCM).
 *   - Copie enveloppée de la clé de salon : RSA-OAEP (chiffrée avec la clé
 *     publique du membre cible), encodée en base64.
 *   - Message                 : AES-256-GCM, nonce/IV de 12 octets aléatoire
 *     et unique par message ; le serveur reçoit `{nonce, ciphertext}`.
 *
 * Clé privée utilisateur : stockée en localStorage sous la forme
 * `{alg:"RSA-OAEP-256", salt, iv, data}` où `data` est le JWK de la clé
 * chiffré en AES-256-GCM avec une clé dérivée du mot de passe (PBKDF2,
 * 100 000 itérations, SHA-256). Elle ne quitte jamais le navigateur.
 */

/* ============================================================
   Utilitaires d'encodage
   ============================================================ */

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/** Uint8Array/ArrayBuffer → chaîne base64 (btoa classique). */
export function bytesToBase64(bytes) {
  const view = new Uint8Array(bytes);
  let binary = "";
  for (let i = 0; i < view.length; i += 1) {
    binary += String.fromCharCode(view[i]);
  }
  return btoa(binary);
}

/** Chaîne base64 → Uint8Array. */
export function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Texte UTF-8 → Uint8Array. */
export function encodeText(text) {
  return textEncoder.encode(text);
}

/** Uint8Array/ArrayBuffer → texte UTF-8. */
export function decodeText(bytes) {
  return textDecoder.decode(bytes);
}

/* ============================================================
   État cryptographique dans le navigateur
   ============================================================ */

/** Clé privée RSA-OAEP de l'utilisateur connecté (jamais exportée hors mémoire). */
let userPrivateKey = null;

/** Copie base64 (SPKI) de la clé publique de l'utilisateur courant. */
let userPublicKeyBase64 = null;

/**
 * Clés de salon connues localement : roomId → { key: CryptoKey, raw: Uint8Array }.
 * `raw` (32 octets) est conservé pour le re-wrapping à destination des membres.
 */
const roomKeys = new Map();

/** Mémorise la clé privée RSA de l'utilisateur courant (CryptoKey en mémoire). */
export function setUserPrivateKey(privateKey) {
  userPrivateKey = privateKey;
}

/** @returns {CryptoKey|null} clé privée RSA de l'utilisateur courant. */
export function getUserPrivateKey() {
  return userPrivateKey;
}

/** Mémorise la clé publique (SPKI base64) de l'utilisateur courant. */
export function setUserPublicKeyBase64(b64) {
  userPublicKeyBase64 = b64;
}

/** @returns {string|null} clé publique SPKI base64 de l'utilisateur courant. */
export function getUserPublicKeyBase64() {
  return userPublicKeyBase64;
}

/** Oublie toutes les clés de salon (déconnexion / changement de compte). */
export function clearRoomKeys() {
  roomKeys.clear();
}

/** Déconnecte la session cryptographique locale (clés mémoire). */
export function resetCryptoState() {
  userPrivateKey = null;
  userPublicKeyBase64 = null;
  clearRoomKeys();
}

/* ============================================================
   Paire de clés RSA-OAEP-256 de l'utilisateur
   ============================================================ */

/**
 * Génère une paire RSA-OAEP 2048 bits (SHA-256).
 * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey}>}
 */
export async function generateUserKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true, // extractable : nécessaire pour l'export SPKI (publique) et JWK (privée)
    ["encrypt", "decrypt"],
  );
}

/** Exporte une clé publique RSA au format SPKI puis base64. */
export async function exportPublicKeyBase64(publicKey) {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  return bytesToBase64(spki);
}

/** Importe une clé publique RSA depuis SPKI base64. */
export async function importPublicKeyFromBase64(b64) {
  return crypto.subtle.importKey(
    "spki",
    base64ToBytes(b64),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false, // non extractable : on ne passe que des clés publiques à chiffrer
    ["encrypt"],
  );
}

/** Exporte une clé privée RSA au format JWK (jamais transmise au réseau). */
export async function exportPrivateKeyJwk(privateKey) {
  return crypto.subtle.exportKey("jwk", privateKey);
}

/** Importe une clé privée RSA depuis un JWK (pour déchiffrer les clés de salon). */
export async function importPrivateKeyFromJwk(jwk) {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"],
  );
}

/* ============================================================
   Protection de la clé privée par le mot de passe (PBKDF2 + AES-GCM)
   ============================================================ */

const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 16; // octets
const IV_LENGTH = 12; // octets (AES-GCM)

/** Dérive une clé AES-256-GCM depuis le mot de passe (PBKDF2, SHA-256). */
async function deriveAesKeyFromPassword(password, salt) {
  const material = await crypto.subtle.importKey(
    "raw",
    encodeText(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Chiffre le JWK d'une clé privée avec une clé dérivée du mot de passe.
 * @returns {Promise<{alg: string, salt: string, iv: string, data: string}>}
 *          tous les champs binaires en base64.
 */
export async function encryptPrivateKeyWithPassword(privateKeyJwk, password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const aesKey = await deriveAesKeyFromPassword(password, salt);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encodeText(JSON.stringify(privateKeyJwk)),
  );

  return {
    alg: "RSA-OAEP-256",
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    data: bytesToBase64(ciphertext),
  };
}

/**
 * Déchiffre le JWK d'une clé privée avec le mot de passe.
 * @param {{alg: string, salt: string, iv: string, data: string}} stored
 * @param {string} password
 * @returns {Promise<object>} JWK de la clé privée.
 * @throws {Error} si le mot de passe est incorrect (tag AEAD invalide).
 */
export async function decryptPrivateKeyWithPassword(stored, password) {
  if (stored.alg !== "RSA-OAEP-256") {
    throw new Error("Format de clé privée stockée inconnu.");
  }
  const salt = base64ToBytes(stored.salt);
  const iv = base64ToBytes(stored.iv);
  const aesKey = await deriveAesKeyFromPassword(password, salt);

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      aesKey,
      base64ToBytes(stored.data),
    );
  } catch (error) {
    throw new Error("Mot de passe incorrect ou données locales corrompues.");
  }
  return JSON.parse(decodeText(plaintext));
}

/* ============================================================
   Clé de salon (AES-256-GCM, 32 octets)
   ============================================================ */

const ROOM_KEY_LENGTH = 32; // octets

/**
 * Génère une clé de salon : 32 octets aléatoires + importation AES-GCM.
 * @returns {Promise<{key: CryptoKey, raw: Uint8Array}>}
 */
export async function generateRoomKey() {
  const raw = crypto.getRandomValues(new Uint8Array(ROOM_KEY_LENGTH));
  const key = await importRoomKey(raw);
  return { key, raw };
}

/** Importe 32 octets en clé AES-GCM (usages chiffrement/déchiffrement). */
export async function importRoomKey(rawBytes) {
  return crypto.subtle.importKey(
    "raw",
    rawBytes,
    { name: "AES-GCM" },
    false, // la clé de salon n'a jamais besoin d'être exportée hors mémoire
    ["encrypt", "decrypt"],
  );
}

/** Enregistre une clé de salon pour un salon donné. */
export function storeRoomKey(roomId, roomKey) {
  roomKeys.set(String(roomId), roomKey);
}

/** @returns {CryptoKey|null} clé de salon AES-GCM d'un salon (usage messages). */
export function getRoomKey(roomId) {
  const entry = roomKeys.get(String(roomId));
  return entry ? entry.key : null;
}

/** @returns {Uint8Array|null} octets bruts de la clé de salon (usage wrapping). */
export function getRoomKeyRaw(roomId) {
  const entry = roomKeys.get(String(roomId));
  return entry ? entry.raw : null;
}

/**
 * Enveloppe la clé de salon brute avec la clé publique RSA d'un membre.
 * @returns {Promise<string>} copie enveloppée en base64.
 */
export async function wrapRoomKeyFor(publicKey, roomKeyRaw) {
  const wrapped = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    roomKeyRaw,
  );
  return bytesToBase64(wrapped);
}

/**
 * Dé-enveloppe une copie de clé de salon avec la clé privée RSA.
 * @returns {Promise<{key: CryptoKey, raw: Uint8Array}>}
 */
export async function unwrapRoomKeyFor(wrappedBase64, privateKey) {
  const raw = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      base64ToBytes(wrappedBase64),
    ),
  );
  const key = await importRoomKey(raw);
  return { key, raw };
}

/* ============================================================
   Messages (AES-256-GCM, nonce 12 octets unique par message)
   ============================================================ */

const MESSAGE_NONCE_LENGTH = 12; // octets

/**
 * Chiffre un message avec la clé de salon.
 * @param {CryptoKey} roomKey
 * @param {string} plaintext
 * @returns {Promise<{nonce: string, ciphertext: string}>} (base64)
 *
 * Garantie « nonce unique » : un nonce aléatoire de 96 bits est généré pour
 * chaque message. La probabilité de collision reste négligeable et le tag
 * AEAD (ajouté au ciphertext) détecterait toute réutilisation éventuelle.
 */
export async function encryptMessage(roomKey, plaintext) {
  const nonce = crypto.getRandomValues(new Uint8Array(MESSAGE_NONCE_LENGTH));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    roomKey,
    encodeText(plaintext),
  );
  return {
    nonce: bytesToBase64(nonce),
    ciphertext: bytesToBase64(ciphertext),
  };
}

/**
 * Déchiffre un message avec la clé de salon.
 * @returns {Promise<string>} texte clair.
 * @throws {Error} si l'authentification AEAD échoue (clé/nonce invalides).
 */
export async function decryptMessage(roomKey, nonceBase64, ciphertextBase64) {
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(nonceBase64) },
      roomKey,
      base64ToBytes(ciphertextBase64),
    );
  } catch (error) {
    throw new Error("Déchiffrement impossible (clé de salon invalide ?).");
  }
  return decodeText(plaintext);
}