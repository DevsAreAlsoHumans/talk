// Tests du module de chiffrement du navigateur, exécutés sous Node : `node --test tests/js`
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  decryptBytes,
  decryptMessage,
  decryptPrivateKey,
  deriveKeys,
  encryptBytes,
  encryptMessage,
  encryptPrivateKey,
  fingerprint,
  fromBase64,
  generateIdentity,
  generateRoomKey,
  toBase64,
  unwrapRoomKey,
  wrapRoomKey,
} from '../../frontend/js/crypto.js';

const ITERATIONS = 1000; // 600 000 en production ; le serveur ignore ce paramètre
const ROOM_ID = 'room-1';
const SENDER_ID = 'user-1';

async function newUser(name = 'alice', password = 'un mot de passe très solide') {
  const { wrapKey, authSecret } = await deriveKeys(password, name, ITERATIONS);
  const identity = await generateIdentity();
  const encryptedPrivateKey = await encryptPrivateKey(identity.pkcs8, wrapKey);
  const privateKey = await decryptPrivateKey(encryptedPrivateKey, wrapKey);
  return { wrapKey, authSecret, publicKey: identity.publicKey, encryptedPrivateKey, privateKey };
}

test('base64 : aller-retour sur des données binaires de toutes tailles', () => {
  for (const size of [0, 1, 2, 3, 100, 70_000]) {
    const bytes = crypto.getRandomValues(new Uint8Array(Math.min(size, 65_536)));
    assert.deepEqual(fromBase64(toBase64(bytes)), bytes);
  }
});

test('deriveKeys : déterministe, sel propre à chaque utilisateur, secret de 32 octets', async () => {
  const first = await deriveKeys('mot de passe', 'alice', ITERATIONS);
  const again = await deriveKeys('mot de passe', 'alice', ITERATIONS);
  const other = await deriveKeys('mot de passe', 'bob', ITERATIONS);
  const different = await deriveKeys('autre mot de passe', 'alice', ITERATIONS);
  assert.equal(first.authSecret, again.authSecret);
  assert.notEqual(first.authSecret, other.authSecret);
  assert.notEqual(first.authSecret, different.authSecret);
  assert.equal(fromBase64(first.authSecret).length, 32);
});

test('la clé d\'enveloppe est non extractable : le JavaScript ne peut pas la lire', async () => {
  const { wrapKey } = await deriveKeys('mot de passe', 'alice', ITERATIONS);
  assert.equal(wrapKey.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('raw', wrapKey));
});

test('clé publique : point non compressé P-256 de 65 octets', async () => {
  const { publicKey } = await generateIdentity();
  const raw = fromBase64(publicKey);
  assert.equal(raw.length, 65);
  assert.equal(raw[0], 4);
});

test('sauvegarde de la clé privée : se déchiffre avec le bon mot de passe, pas avec un autre', async () => {
  const user = await newUser('alice', 'bon mot de passe');
  assert.equal(user.privateKey.extractable, false);
  const wrong = await deriveKeys('mauvais mot de passe', 'alice', ITERATIONS);
  await assert.rejects(decryptPrivateKey(user.encryptedPrivateKey, wrong.wrapKey));
});

test('message : aller-retour, y compris emoji et accents', async () => {
  const roomKey = await generateRoomKey();
  const encrypted = await encryptMessage(roomKey, 'Ça marche ✓ 👋', ROOM_ID, SENDER_ID);
  const decrypted = await decryptMessage(roomKey, { ...encrypted, room_id: ROOM_ID, sender_id: SENDER_ID });
  assert.equal(decrypted, 'Ça marche ✓ 👋');
});

test('message : IV neuf à chaque envoi, texte clair absent du chiffré', async () => {
  const roomKey = await generateRoomKey();
  const ivs = new Set();
  for (let index = 0; index < 100; index += 1) {
    const { iv, ciphertext } = await encryptMessage(roomKey, 'secret', ROOM_ID, SENDER_ID);
    ivs.add(iv);
    assert.equal(fromBase64(iv).length, 12);
    assert.ok(!Buffer.from(fromBase64(ciphertext)).includes('secret'));
  }
  assert.equal(ivs.size, 100);
});

test('message : altération, mauvais salon, mauvais expéditeur et mauvaise clé sont détectés', async () => {
  const roomKey = await generateRoomKey();
  const encrypted = await encryptMessage(roomKey, 'bonjour', ROOM_ID, SENDER_ID);
  const message = { ...encrypted, room_id: ROOM_ID, sender_id: SENDER_ID };

  const bytes = fromBase64(message.ciphertext);
  bytes[0] ^= 1;
  await assert.rejects(decryptMessage(roomKey, { ...message, ciphertext: toBase64(bytes) }));
  await assert.rejects(decryptMessage(roomKey, { ...message, room_id: 'room-2' }));
  await assert.rejects(decryptMessage(roomKey, { ...message, sender_id: 'mallory' }));
  await assert.rejects(decryptMessage(await generateRoomKey(), message));
});

test('médias et avatars (bytes) : aller-retour binaire, altérations détectées', async () => {
  const roomKey = await generateRoomKey();
  const bytes = crypto.getRandomValues(new Uint8Array(32_000));
  const encrypted = await encryptBytes(roomKey, bytes, ROOM_ID, SENDER_ID);
  const message = { ...encrypted, room_id: ROOM_ID, sender_id: SENDER_ID };

  const decrypted = await decryptBytes(roomKey, message);
  assert.deepEqual(new Uint8Array(decrypted), bytes);

  const torn = fromBase64(message.ciphertext);
  torn[0] ^= 1;
  await assert.rejects(decryptBytes(roomKey, { ...message, ciphertext: toBase64(torn) }));
  await assert.rejects(decryptBytes(roomKey, { ...message, sender_id: 'mallory' }));
  await assert.rejects(decryptBytes(await generateRoomKey(), message));
});

test('clé de salon : seul le destinataire peut la retrouver, et elle déchiffre les messages', async () => {
  const alice = await newUser('alice');
  const bob = await newUser('bob');
  const roomKey = await generateRoomKey();
  const wrapped = await wrapRoomKey(roomKey, bob.publicKey);

  const bobKey = await unwrapRoomKey(wrapped, bob.privateKey);
  assert.equal(bobKey.extractable, false);
  await assert.rejects(unwrapRoomKey(wrapped, alice.privateKey));

  const encrypted = await encryptMessage(roomKey, 'pour Bob', ROOM_ID, SENDER_ID);
  const message = { ...encrypted, room_id: ROOM_ID, sender_id: SENDER_ID };
  assert.equal(await decryptMessage(bobKey, message), 'pour Bob');
});

test('clé de salon : le propriétaire la retrouve extractable pour inviter de nouveaux membres', async () => {
  const alice = await newUser('alice');
  const carol = await newUser('carol');
  const roomKey = await generateRoomKey();
  const ownKey = await unwrapRoomKey(await wrapRoomKey(roomKey, alice.publicKey), alice.privateKey, {
    extractable: true,
  });

  const forCarol = await unwrapRoomKey(await wrapRoomKey(ownKey, carol.publicKey), carol.privateKey);
  const encrypted = await encryptMessage(ownKey, 'bienvenue', ROOM_ID, SENDER_ID);
  assert.equal(await decryptMessage(forCarol, { ...encrypted, room_id: ROOM_ID, sender_id: SENDER_ID }), 'bienvenue');
});

test('enveloppe : clé éphémère et IV différents à chaque fois, formats attendus par le serveur', async () => {
  const bob = await newUser('bob');
  const roomKey = await generateRoomKey();
  const first = await wrapRoomKey(roomKey, bob.publicKey);
  const second = await wrapRoomKey(roomKey, bob.publicKey);
  assert.notEqual(first.ephemeral_public_key, second.ephemeral_public_key);
  assert.notEqual(first.iv, second.iv);
  assert.equal(fromBase64(first.ephemeral_public_key).length, 65);
  assert.equal(fromBase64(first.iv).length, 12);
  assert.equal(fromBase64(first.wrapped_key).length, 48);
});

test('empreinte : stable, 4 groupes de 4 caractères hexadécimaux, différente selon la clé', async () => {
  const first = await generateIdentity();
  const second = await generateIdentity();
  const value = await fingerprint(first.publicKey);
  assert.match(value, /^[0-9a-f]{4}( [0-9a-f]{4}){3}$/);
  assert.equal(value, await fingerprint(first.publicKey));
  assert.notEqual(value, await fingerprint(second.publicKey));
});

test('interopérabilité : le navigateur lit ce que produit l\'implémentation Python de référence', async () => {
  const vectors = JSON.parse(await readFile(new URL('./python_vectors.json', import.meta.url), 'utf8'));

  const { wrapKey, authSecret } = await deriveKeys(vectors.password, vectors.username, vectors.iterations);
  assert.equal(authSecret, vectors.auth_secret);

  const privateKey = await decryptPrivateKey(vectors.encrypted_private_key, wrapKey);
  const roomKey = await unwrapRoomKey(vectors.wrapped_room_key, privateKey);
  assert.equal(await decryptMessage(roomKey, vectors.message), vectors.message.plaintext);

  const media = await decryptBytes(roomKey, vectors.media);
  assert.deepEqual(new Uint8Array(media), fromBase64(vectors.media.plaintext_b64));
});
