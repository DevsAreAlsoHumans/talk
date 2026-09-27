const CURVE = "P-256";

export async function generateKeyPair() {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: CURVE }, true, ["deriveKey"]);
}

export async function exportPublicKeyRaw(publicKey) {
  const raw = await crypto.subtle.exportKey("raw", publicKey);
  return arrayBufferToBase64(raw);
}

export async function importPeerPublicKey(base64Raw) {
  const raw = base64ToArrayBuffer(base64Raw);
  return crypto.subtle.importKey("raw", raw, { name: "ECDH", namedCurve: CURVE }, [], []);
}

export async function deriveSharedKey(privateKey, peerPublicKey) {
  return crypto.subtle.deriveKey(
    { name: "ECDH", public: peerPublicKey },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptMessage(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertextBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
  return {
    ciphertext: arrayBufferToBase64(ciphertextBuffer),
    iv: arrayBufferToBase64(iv),
  };
}

export async function decryptMessage(key, ciphertextBase64, ivBase64) {
  const ciphertext = base64ToArrayBuffer(ciphertextBase64);
  const iv = base64ToArrayBuffer(ivBase64);
  const plaintextBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new TextDecoder().decode(plaintextBuffer);
}

export async function generateRoomKey() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
}

// "Wrap" = chiffrer la clé de salon avec le secret ECDH partagé entre l'auteur de la
// rotation et un membre précis, pour que seul ce membre puisse la récupérer.
export async function wrapRoomKeyForMember(myPrivateKey, memberPublicKeyRaw, roomKey) {
  const memberPublicKey = await importPeerPublicKey(memberPublicKeyRaw);
  const wrappingKey = await deriveSharedKey(myPrivateKey, memberPublicKey);
  const rawRoomKey = await crypto.subtle.exportKey("raw", roomKey);
  const { ciphertext, iv } = await encryptBytes(wrappingKey, rawRoomKey);
  return { wrappedKey: arrayBufferToBase64(ciphertext), wrappedKeyIv: iv };
}

export async function unwrapRoomKey(
  myPrivateKey,
  wrapperPublicKeyRaw,
  wrappedKeyBase64,
  wrappedKeyIv
) {
  const wrapperPublicKey = await importPeerPublicKey(wrapperPublicKeyRaw);
  const wrappingKey = await deriveSharedKey(myPrivateKey, wrapperPublicKey);
  const wrappedBuffer = base64ToArrayBuffer(wrappedKeyBase64);
  const rawRoomKey = await decryptBytes(wrappingKey, wrappedBuffer, wrappedKeyIv);
  return crypto.subtle.importKey("raw", rawRoomKey, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function encryptBytes(key, plainBuffer) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertextBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plainBuffer);
  return { ciphertext: ciphertextBuffer, iv: arrayBufferToBase64(iv) };
}

export async function decryptBytes(key, ciphertextBuffer, ivBase64) {
  const iv = base64ToArrayBuffer(ivBase64);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertextBuffer);
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
