/**
 * Chiffrement de bout en bout, 100 % côté navigateur.
 *
 * Principe : le serveur ne reçoit jamais de texte en clair, seulement une
 * enveloppe { iv, ciphertext } produced par AES-GCM.
 *
 * - Chaque compte possède une paire de clés ECDH P-256. La clé privée vit
 *   dans le localStorage du poste, seule la clé publique est publiée.
 * - Chaque canal possède une clé aléatoire de 256 bits. Elle est chiffrée
 *   pour chaque membre via ECDH + HKDF, puis stockée par le serveur.
 * - AES-GCM est une authentification : l'intégrité du message est garantie
 *   par le tag, une signature d'identité separate n'est donc pas requise.
 */

const KEYSTORE = "talk.identity";
const ECDH = { name: "ECDH", namedCurve: "P-256" };
const AES_GCM = { name: "AES-GCM", length: 256 };

/* ---------- encodage ---------- */

export function toB64(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function fromB64(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function randomIv() {
  return crypto.getRandomValues(new Uint8Array(12));
}

/* ---------- identité ---------- */

/** Crée (ou recharge) la paire de clés ECDH du compte et renvoie la clé publique. */
export async function loadOrCreateIdentity() {
  const stored = localStorage.getItem(KEYSTORE);
  if (stored) {
    const parsed = JSON.parse(stored);
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      parsed.privateKey,
      ECDH,
      false,
      ["deriveKey", "deriveBits"],
    );
    return { privateKey, publicKey: await exportPublic(privateKey) };
  }
  const keyPair = await crypto.subtle.generateKey(ECDH, true, ["deriveKey", "deriveBits"]);
  const privateKey = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  localStorage.setItem(KEYSTORE, JSON.stringify({ privateKey }));
  return { privateKey: keyPair.privateKey, publicKey: await exportPublic(keyPair.privateKey) };
}

async function exportPublic(privateKey) {
  const raw = await crypto.subtle.exportKey("raw", privateKey);
  return toB64(raw);
}

export async function importPeerPublic(publicKeyB64) {
  return crypto.subtle.importKey(
    "raw",
    fromB64(publicKeyB64),
    ECDH,
    false,
    [],
  );
}

/* ---------- clé de canal ---------- */

async function deriveWrappingKey(privateKey, peerPublic) {
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: peerPublic },
    privateKey,
    256,
  );
  const material = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("talk-channel-v1") },
    material,
    AES_GCM,
    false,
    ["encrypt", "decrypt"],
  );
}

export function generateChannelKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

async function importChannelKey(raw) {
  return crypto.subtle.importKey("raw", raw, AES_GCM, false, ["encrypt", "decrypt"]);
}

/** Chiffre la clé de canal pour un destinataire ; la version est geree par l'API. */
export async function wrapChannelKey(privateKey, peerPublicB64, channelKeyRaw) {
  const peer = await importPeerPublic(peerPublicB64);
  const wrapping = await deriveWrappingKey(privateKey, peer);
  const iv = randomIv();
  const wrapped = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    wrapping,
    channelKeyRaw,
  );
  return toB64(wrapped);
}

/** Déchiffre la clé de canal stockée par un membre du canal. */
export async function unwrapChannelKey(privateKey, senderPublicB64, envelope) {
  const peer = await importPeerPublic(senderPublicB64);
  const wrapping = await deriveWrappingKey(privateKey, peer);
  const raw = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(envelope.iv) },
    wrapping,
    fromB64(envelope.wrapped_key),
  );
  return new Uint8Array(raw);
}

/* ---------- messages ---------- */

export async function encryptMessage(channelKeyRaw, plaintext) {
  const key = await importChannelKey(channelKeyRaw);
  const iv = randomIv();
  const data = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  return { ciphertext: toB64(ciphertext), iv: toB64(iv) };
}

export async function decryptMessage(channelKeyRaw, envelope) {
  try {
    const key = await importChannelKey(channelKeyRaw);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromB64(envelope.iv) },
      key,
      fromB64(envelope.ciphertext),
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    // Mauvaise cle de canal ou tag invalide : rien n'est affiche.
    return null;
  }
}
