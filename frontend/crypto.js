// Chiffrement, à part pour pouvoir le tester avec Node.
// - chaque utilisateur a une paire de clés RSA : la privée ne quitte jamais le navigateur
// - chaque salon a une clé AES, envoyée au serveur seulement chiffrée avec la clé publique de chaque membre
// - les messages sont chiffrés avec la clé AES du salon

const RSA = { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' };
const RSA_IMPORT = { name: 'RSA-OAEP', hash: 'SHA-256' };

// Base64 version URL (sans + / =) pour envoyer les clés et les messages
function bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function base64ToBytes(value) {
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/'));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

// ---------- Clés de l'utilisateur ----------

// Nouvelle paire de clés RSA pour l'utilisateur
function newUserKeys() {
  return crypto.subtle.generateKey(RSA, true, ['wrapKey', 'unwrapKey']);
}

// En texte pour la garder dans le navigateur (localStorage)
async function exportUserKeys(keys) {
  return {
    publicKey: bytesToBase64(new Uint8Array(await crypto.subtle.exportKey('spki', keys.publicKey))),
    privateKey: bytesToBase64(new Uint8Array(await crypto.subtle.exportKey('pkcs8', keys.privateKey))),
  };
}

async function importUserKeys(saved) {
  return {
    publicKey: await importPublicKey(saved.publicKey),
    privateKey: await crypto.subtle.importKey('pkcs8', base64ToBytes(saved.privateKey), RSA_IMPORT, false, ['unwrapKey']),
  };
}

// Clé publique d'un autre membre, reçue du serveur
function importPublicKey(publicKey) {
  return crypto.subtle.importKey('spki', base64ToBytes(publicKey), RSA_IMPORT, true, ['wrapKey']);
}

// ---------- Clés des salons ----------

// Nouvelle clé de salon : AES-GCM 256 bits
function newRoomKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

// Chiffre la clé du salon pour un membre, avec sa clé publique
async function wrapRoomKey(roomKey, publicKey) {
  const wrapped = await crypto.subtle.wrapKey('raw', roomKey, publicKey, { name: 'RSA-OAEP' });
  return bytesToBase64(new Uint8Array(wrapped));
}

// Récupère la clé du salon avec MA clé privée (gardée exportable pour pouvoir ajouter des membres)
function unwrapRoomKey(wrappedKey, privateKey) {
  return crypto.subtle.unwrapKey(
    'raw', base64ToBytes(wrappedKey), privateKey, { name: 'RSA-OAEP' },
    { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'],
  );
}

// ---------- Messages ----------

// Chiffre un texte (AES-GCM). L'id du canal est lié au message : on peut pas le déplacer ailleurs
async function encryptText(key, channelId, text) {
  // Nouveau nonce à chaque message, sinon AES-GCM n'est plus sûr
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: new TextEncoder().encode(channelId) },
    key, new TextEncoder().encode(text),
  );
  return { version: 1, nonce: bytesToBase64(nonce), ciphertext: bytesToBase64(new Uint8Array(ciphertext)) };
}

// Déchiffre un message, plante si la clé, le canal ou le contenu ne correspondent pas
async function decryptText(key, channelId, message) {
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(message.nonce), additionalData: new TextEncoder().encode(channelId) },
    key, base64ToBytes(message.ciphertext),
  );
  return new TextDecoder().decode(plaintext);
}

// Export seulement pour les tests Node (dans le navigateur, module n'existe pas)
if (typeof module !== 'undefined') {
  module.exports = {
    bytesToBase64, base64ToBytes, newUserKeys, exportUserKeys, importUserKeys, importPublicKey,
    newRoomKey, wrapRoomKey, unwrapRoomKey, encryptText, decryptText,
  };
}
