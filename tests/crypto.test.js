// Tests unitaires du chiffrement (frontend/crypto.js), lancés avec : node --test "tests/*.test.js"
const { test } = require('node:test');
const assert = require('node:assert');
const {
  bytesToBase64, base64ToBytes, newUserKeys, exportUserKeys, importUserKeys, importPublicKey,
  newRoomKey, wrapRoomKey, unwrapRoomKey, encryptText, decryptText,
} = require('../frontend/crypto.js');

// Une paire de clés comme elle est gardée dans le navigateur
async function savedUser() {
  return exportUserKeys(await newUserKeys());
}

test('base64 aller-retour', () => {
  const bytes = Uint8Array.from([0, 1, 250, 251, 255]);
  assert.deepStrictEqual(base64ToBytes(bytesToBase64(bytes)), bytes);
  assert.match(bytesToBase64(bytes), /^[A-Za-z0-9_-]+$/);
});

// ---------- Clés ----------

test('les clés utilisateur s’exportent et se réimportent', async () => {
  const saved = await savedUser();
  assert.match(saved.publicKey, /^[A-Za-z0-9_-]+$/);
  assert.ok(saved.publicKey.length >= 100 && saved.publicKey.length <= 1000);
  const keys = await importUserKeys(saved);
  assert.strictEqual(keys.privateKey.extractable, false);
});

test('la clé du salon passe d’un membre à l’autre sans être lisible en route', async () => {
  const alice = await importUserKeys(await savedUser());
  const bob = await importUserKeys(await savedUser());
  const roomKey = await newRoomKey();
  // Alice chiffre la clé du salon pour Bob avec la clé publique de Bob (reçue du serveur)
  const bobPublic = await importPublicKey(bytesToBase64(new Uint8Array(
    await crypto.subtle.exportKey('spki', bob.publicKey),
  )));
  const wrapped = await wrapRoomKey(roomKey, bobPublic);
  assert.ok(wrapped.length <= 1000);
  // Bob l'ouvre avec sa clé privée et lit un message d'Alice
  const bobRoomKey = await unwrapRoomKey(wrapped, bob.privateKey);
  const message = await encryptText(roomKey, 'canal-1', 'Salut Bob');
  assert.strictEqual(await decryptText(bobRoomKey, 'canal-1', message), 'Salut Bob');
  // Alice ne peut pas ouvrir la copie de Bob
  await assert.rejects(unwrapRoomKey(wrapped, alice.privateKey));
});

test('une copie de clé abîmée est refusée', async () => {
  const user = await importUserKeys(await savedUser());
  const bytes = base64ToBytes(await wrapRoomKey(await newRoomKey(), user.publicKey));
  bytes[0] ^= 1;
  await assert.rejects(unwrapRoomKey(bytesToBase64(bytes), user.privateKey));
});

// ---------- Messages ----------

test('chiffrer puis déchiffrer redonne le texte', async () => {
  const key = await newRoomKey();
  const message = await encryptText(key, 'canal-1', 'Salut 👋');
  assert.strictEqual(await decryptText(key, 'canal-1', message), 'Salut 👋');
});

test('le message chiffré ne contient pas le texte', async () => {
  const message = await encryptText(await newRoomKey(), 'canal-1', 'mot de passe secret');
  assert.strictEqual(message.version, 1);
  assert.strictEqual(message.nonce.length, 16);
  assert.ok(!Buffer.from(base64ToBytes(message.ciphertext)).toString().includes('secret'));
});

test('deux chiffrements du même texte sont différents (nonce unique)', async () => {
  const key = await newRoomKey();
  const first = await encryptText(key, 'canal-1', 'pareil');
  const second = await encryptText(key, 'canal-1', 'pareil');
  assert.notStrictEqual(first.nonce, second.nonce);
  assert.notStrictEqual(first.ciphertext, second.ciphertext);
});

test('mauvaise clé : impossible de déchiffrer', async () => {
  const message = await encryptText(await newRoomKey(), 'canal-1', 'secret');
  await assert.rejects(decryptText(await newRoomKey(), 'canal-1', message));
});

test('message déplacé dans un autre canal : refusé', async () => {
  const key = await newRoomKey();
  const message = await encryptText(key, 'canal-1', 'secret');
  await assert.rejects(decryptText(key, 'canal-2', message));
});

test('message modifié : refusé', async () => {
  const key = await newRoomKey();
  const message = await encryptText(key, 'canal-1', 'secret');
  const bytes = base64ToBytes(message.ciphertext);
  bytes[0] ^= 1;
  await assert.rejects(decryptText(key, 'canal-1', { ...message, ciphertext: bytesToBase64(bytes) }));
});
