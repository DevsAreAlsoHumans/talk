/*
 * Chiffrement de bout en bout — tout se passe ici, dans le navigateur (WebCrypto).
 * Ce module n'a aucune dépendance et ne touche pas au DOM : il est testé sous Node
 * (tests/js) et son protocole est vérifié contre l'implémentation Python de référence.
 *
 * Protocole (détaillé dans le README) :
 *  1. deriveKeys        mot de passe → PBKDF2-SHA256 → HKDF → { clé d'enveloppe, secret d'authentification }.
 *                       Le serveur ne reçoit QUE le secret d'authentification, jamais le mot de passe
 *                       ni la clé d'enveloppe.
 *  2. Identité          paire ECDH P-256. La clé privée est chiffrée (AES-GCM) avec la clé d'enveloppe
 *                       avant d'être confiée au serveur : il ne peut pas la lire.
 *  3. Clé de salon      AES-256 aléatoire, enveloppée pour chaque membre : ECDH éphémère → HKDF → AES-GCM.
 *  4. Message           AES-GCM avec la clé du salon, IV aléatoire de 12 octets à chaque message,
 *                       données authentifiées (AAD) = "<id du salon>:<id de l'expéditeur>".
 *  Les messages texte, les médias (images, messages vocaux) et les avatars suivent le même
 *  protocole : octets quelconques (encryptBytes/decryptBytes) contre texte (encryptMessage/decryptMessage).
 */

const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const PBKDF2_ITERATIONS = 600_000;

const ECDH_P256 = { name: 'ECDH', namedCurve: 'P-256' };
const NO_SALT = new Uint8Array(0);
const IV_BYTES = 12;

// ---------- Encodage ----------

export function toBase64(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (let offset = 0; offset < view.length; offset += 0x8000) {
    binary += String.fromCharCode(...view.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

export function fromBase64(text) {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function randomBytes(length) {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

function concat(first, second) {
  const joined = new Uint8Array(first.length + second.length);
  joined.set(first, 0);
  joined.set(second, first.length);
  return joined;
}

function aesGcm(iv, aad) {
  return { name: 'AES-GCM', iv, additionalData: encoder.encode(aad) };
}

async function hkdfBits(inputBits, info) {
  const key = await subtle.importKey('raw', inputBits, 'HKDF', false, ['deriveBits']);
  return subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: NO_SALT, info: encoder.encode(info) }, key, 256);
}

// ---------- 1. Dérivation à partir du mot de passe ----------

export async function deriveKeys(password, username, iterations = PBKDF2_ITERATIONS) {
  const passwordKey = await subtle.importKey('raw', encoder.encode(password.normalize('NFKC')), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const masterBits = await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: encoder.encode(`talk-e2e-v1:${username}`), iterations },
    passwordKey,
    256,
  );
  const [wrapBits, authBits] = await Promise.all([
    hkdfBits(masterBits, 'talk-wrap-key'),
    hkdfBits(masterBits, 'talk-auth-secret'),
  ]);
  const wrapKey = await subtle.importKey('raw', wrapBits, 'AES-GCM', false, ['encrypt', 'decrypt']);
  return { wrapKey, authSecret: toBase64(authBits) };
}

// ---------- 2. Identité (paire de clés ECDH) ----------

export async function generateIdentity() {
  const pair = await subtle.generateKey(ECDH_P256, true, ['deriveBits']);
  return {
    publicKey: toBase64(await subtle.exportKey('raw', pair.publicKey)),
    pkcs8: new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey)),
  };
}

export async function encryptPrivateKey(pkcs8, wrapKey) {
  const iv = randomBytes(IV_BYTES);
  const ciphertext = await subtle.encrypt(aesGcm(iv, 'talk-private-key'), wrapKey, pkcs8);
  return toBase64(concat(iv, new Uint8Array(ciphertext)));
}

/** Déchiffre la clé privée et la réimporte NON extractable : le JavaScript ne pourra plus jamais la relire. */
export async function decryptPrivateKey(encryptedPrivateKey, wrapKey) {
  const blob = fromBase64(encryptedPrivateKey);
  const pkcs8 = await subtle.decrypt(aesGcm(blob.slice(0, IV_BYTES), 'talk-private-key'), wrapKey, blob.slice(IV_BYTES));
  return subtle.importKey('pkcs8', pkcs8, ECDH_P256, false, ['deriveBits']);
}

/** Empreinte courte d'une clé publique, à comparer hors bande pour détecter une substitution de clé. */
export async function fingerprint(publicKey) {
  const digest = new Uint8Array(await subtle.digest('SHA-256', fromBase64(publicKey)));
  const hex = Array.from(digest.slice(0, 8), (byte) => byte.toString(16).padStart(2, '0')).join('');
  return hex.match(/.{4}/g).join(' ');
}

// ---------- 3. Clé de salon ----------

export function generateRoomKey() {
  return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

async function keyEncryptionKey(sharedBits) {
  const bits = await hkdfBits(sharedBits, 'talk-room-key-wrap');
  return subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/** Enveloppe la clé du salon pour un destinataire (sa clé publique) : seul lui pourra la retrouver. */
export async function wrapRoomKey(roomKey, recipientPublicKey) {
  const recipient = await subtle.importKey('raw', fromBase64(recipientPublicKey), ECDH_P256, false, []);
  const ephemeral = await subtle.generateKey(ECDH_P256, true, ['deriveBits']);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: recipient }, ephemeral.privateKey, 256);
  const iv = randomBytes(IV_BYTES);
  const wrapped = await subtle.encrypt(
    aesGcm(iv, 'talk-room-key'),
    await keyEncryptionKey(shared),
    await subtle.exportKey('raw', roomKey),
  );
  return {
    ephemeral_public_key: toBase64(await subtle.exportKey('raw', ephemeral.publicKey)),
    iv: toBase64(iv),
    wrapped_key: toBase64(wrapped),
  };
}

/**
 * Retrouve la clé du salon avec sa clé privée. `extractable` n'est nécessaire que pour le
 * propriétaire, qui doit pouvoir réenvelopper la clé pour les nouveaux membres.
 */
export async function unwrapRoomKey(wrappedKey, privateKey, { extractable = false } = {}) {
  const ephemeral = await subtle.importKey('raw', fromBase64(wrappedKey.ephemeral_public_key), ECDH_P256, false, []);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: ephemeral }, privateKey, 256);
  const raw = await subtle.decrypt(
    aesGcm(fromBase64(wrappedKey.iv), 'talk-room-key'),
    await keyEncryptionKey(shared),
    fromBase64(wrappedKey.wrapped_key),
  );
  return subtle.importKey('raw', raw, 'AES-GCM', extractable, ['encrypt', 'decrypt']);
}

// ---------- 4. Messages ----------

const AAD = (roomId, senderId) => `${roomId}:${senderId}`;

/**
 * Chiffre des octets quelconques (médias, avatars) avec la clé du salon. Le contenu
 * reste illisible pour le serveur, qui ne peut pas déchiffrer — et on peut lier un
 * message à son expéditeur et à son salon (données authentifiées), ce qui empêche de
 * glisser un contenu d'un salon ou d'un autre membre dans le fil.
 */
export async function encryptBytes(roomKey, bytes, roomId, senderId) {
  const iv = randomBytes(IV_BYTES);
  const ciphertext = await subtle.encrypt(aesGcm(iv, AAD(roomId, senderId)), roomKey, bytes);
  return { iv: toBase64(iv), ciphertext: toBase64(ciphertext) };
}

/** `message` est l'objet renvoyé par l'API : { room_id, sender_id, iv, ciphertext, ... }. */
export async function decryptBytes(roomKey, message) {
  return subtle.decrypt(
    aesGcm(fromBase64(message.iv), AAD(message.room_id, message.sender_id)),
    roomKey,
    fromBase64(message.ciphertext),
  );
}

export async function encryptMessage(roomKey, plaintext, roomId, senderId) {
  return encryptBytes(roomKey, encoder.encode(plaintext), roomId, senderId);
}

/** `message` est l'objet renvoyé par l'API : { room_id, sender_id, iv, ciphertext, ... }. */
export async function decryptMessage(roomKey, message) {
  return decoder.decode(await decryptBytes(roomKey, message));
}
