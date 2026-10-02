// Chiffrement des messages, à part pour pouvoir le tester avec Node

// Base64 version URL (sans + / =) pour stocker la clé et les messages
function bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function base64ToBytes(value) {
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/'));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

// Nouvelle clé de salon : 32 octets aléatoires (AES-256)
function newRoomKey() {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(32)));
}

// Transforme la clé texte en vraie clé AES utilisable par Web Crypto
async function importRoomKey(rawKey) {
  const bytes = base64ToBytes(rawKey);
  if (bytes.length !== 32) throw new Error('Clé du salon invalide.');
  return crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

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
  module.exports = { bytesToBase64, base64ToBytes, newRoomKey, importRoomKey, encryptText, decryptText };
}
