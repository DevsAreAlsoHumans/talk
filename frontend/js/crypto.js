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

/**
 * Cle de stockage de l'identite, rattachee au compte.
 *
 * Sans ce suffixe, deux comptes ouverts dans le meme navigateur partageaient la
 * meme paire de cles : la seconde session republiait une cle publique deja
 * connue, les enveloppes deposees pour elle ne corresponded plus a aucune cle
 * privee detenue, et le canal devenait illisible. Une identite par compte.
 */
const keystoreKey = (userId) => `talk.identity.${userId}`;
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
export async function loadOrCreateIdentity(userId) {
  const stored = readKeystore(userId);
  if (stored) {
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      stored.privateKey,
      ECDH,
      false,
      ["deriveKey", "deriveBits"],
    );
    // La cle privee est importee non extractible : la relire exigerait un
    // export, que Web Crypto refuse. On lit donc la cle publique conservee, et
    // a defaut les coordonnees x/y que le JWK stocke contient deja.
    const publicKey = stored.publicKey || publicFromJwk(stored.privateKey);
    if (!stored.publicKey) writeKeystore(userId, { privateKey: stored.privateKey, publicKey });
    return { privateKey, publicKey };
  }
  const keyPair = await crypto.subtle.generateKey(ECDH, true, ["deriveKey", "deriveBits"]);
  const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  const publicKey = publicFromJwk(privateJwk);
  writeKeystore(userId, { privateKey: privateJwk, publicKey });
  return { privateKey: keyPair.privateKey, publicKey };
}

/**
 * Relit le keystore du compte. Une entree illisible (ecriture interrompue, format
 * anterieur) est effacee plutot que de bloquer la connexion : une identite de
 * secours vaut mieux qu'une erreur cryptographique muette, au prix des messages
 * deja chiffres avec l'ancienne cle.
 */
function readKeystore(userId) {
  const key = keystoreKey(userId);
  const raw = localStorage.getItem(key);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed?.privateKey?.x && parsed?.privateKey?.y) return parsed;
    console.warn("talk : keystore sans cle exploitable, identite regeneree.");
  } catch {
    console.warn("talk : keystore illisible, identite regeneree.");
  }
  localStorage.removeItem(key);
  return null;
}

function writeKeystore(userId, value) {
  localStorage.setItem(keystoreKey(userId), JSON.stringify(value));
}

/**
 * Point public non compresse (0x04 || x || y) en base64url, reconstruit depuis
 * un JWK ECDH P-256. "raw" n'est defini que pour l'export d'une cle publique :
 * l'equivalent pour une cle privee passe par ses coordonnees.
 */
function publicFromJwk(jwk) {
  const x = fromB64(jwk.x);
  const y = fromB64(jwk.y);
  if (x.length !== 32 || y.length !== 32) {
    throw new Error("Cle ECDH inattendue : P-256 attend x et y sur 32 octets.");
  }
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(x, 1);
  raw.set(y, 33);
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

/**
 * Chiffre la clé de canal pour un destinataire ; la version est geree par l'API.
 *
 * Renvoie l'enveloppe complete : le nonce AES-GCM n'est pas un secret, mais
 * sans lui la clé emballesée reste indéchiffrable pour le destinataire. Il
 * accompagne donc la clé jusqu'au serveur qui le stocke en clair.
 */
export async function wrapChannelKey(privateKey, peerPublicB64, channelKeyRaw) {
  const peer = await importPeerPublic(peerPublicB64);
  const wrapping = await deriveWrappingKey(privateKey, peer);
  const iv = randomIv();
  const wrapped = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    wrapping,
    channelKeyRaw,
  );
  return { iv: toB64(iv), wrapped_key: toB64(wrapped) };
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
