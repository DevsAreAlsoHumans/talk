// Tests unitaires du chiffrement (frontend/crypto.js), lancés avec : node --test tests/
const { test } = require('node:test');
const assert = require('node:assert');
const {
  bytesToBase64, base64ToBytes, newRoomKey, importRoomKey, encryptText, decryptText,
} = require('../frontend/crypto.js');

test('base64 aller-retour', () => {
  const bytes = Uint8Array.from([0, 1, 250, 251, 255]);
  assert.deepStrictEqual(base64ToBytes(bytesToBase64(bytes)), bytes);
  assert.match(bytesToBase64(bytes), /^[A-Za-z0-9_-]+$/);
});

test('une clé de salon fait 32 octets et change à chaque fois', () => {
  assert.strictEqual(base64ToBytes(newRoomKey()).length, 32);
  assert.notStrictEqual(newRoomKey(), newRoomKey());
});

test('une clé de mauvaise taille est refusée', async () => {
  await assert.rejects(importRoomKey(bytesToBase64(new Uint8Array(16))));
});

test('chiffrer puis déchiffrer redonne le texte', async () => {
  const key = await importRoomKey(newRoomKey());
  const message = await encryptText(key, 'canal-1', 'Salut 👋');
  assert.strictEqual(await decryptText(key, 'canal-1', message), 'Salut 👋');
});

test('le message chiffré ne contient pas le texte', async () => {
  const key = await importRoomKey(newRoomKey());
  const message = await encryptText(key, 'canal-1', 'mot de passe secret');
  assert.strictEqual(message.version, 1);
  assert.strictEqual(message.nonce.length, 16);
  assert.ok(!Buffer.from(base64ToBytes(message.ciphertext)).toString().includes('secret'));
});

test('deux chiffrements du même texte sont différents (nonce unique)', async () => {
  const key = await importRoomKey(newRoomKey());
  const first = await encryptText(key, 'canal-1', 'pareil');
  const second = await encryptText(key, 'canal-1', 'pareil');
  assert.notStrictEqual(first.nonce, second.nonce);
  assert.notStrictEqual(first.ciphertext, second.ciphertext);
});

test('mauvaise clé : impossible de déchiffrer', async () => {
  const message = await encryptText(await importRoomKey(newRoomKey()), 'canal-1', 'secret');
  await assert.rejects(decryptText(await importRoomKey(newRoomKey()), 'canal-1', message));
});

test('message déplacé dans un autre canal : refusé', async () => {
  const key = await importRoomKey(newRoomKey());
  const message = await encryptText(key, 'canal-1', 'secret');
  await assert.rejects(decryptText(key, 'canal-2', message));
});

test('message modifié : refusé', async () => {
  const key = await importRoomKey(newRoomKey());
  const message = await encryptText(key, 'canal-1', 'secret');
  const bytes = base64ToBytes(message.ciphertext);
  bytes[0] ^= 1;
  await assert.rejects(decryptText(key, 'canal-1', { ...message, ciphertext: bytesToBase64(bytes) }));
});
