// Génère tests/js/js_vectors.json avec le VRAI code du navigateur (frontend/js/crypto.js).
// tests/unit/test_js_interop.py les déchiffre ensuite en Python.
// Usage : node tests/js/generate_js_vectors.mjs
import { writeFile } from 'node:fs/promises';

import {
  deriveKeys,
  encryptBytes,
  encryptMessage,
  encryptPrivateKey,
  generateIdentity,
  generateRoomKey,
  toBase64,
  wrapRoomKey,
} from '../../frontend/js/crypto.js';

const iterations = 1000;
const username = 'bob';
const password = 'un autre mot de passe ✓';
const plaintext = 'Bonjour depuis le navigateur 🌐';
const mediaPlaintext = Uint8Array.from({ length: 2048 }, (_, index) => index % 256);
const roomId = '7c1a9f4e-2b5d-4f6a-8e3c-9d0b1a2c3e4f';
const senderId = '3f2e1d0c-9b8a-4c7d-a6e5-f4d3c2b1a098';

const { wrapKey, authSecret } = await deriveKeys(password, username, iterations);
const identity = await generateIdentity();
const roomKey = await generateRoomKey();

const vectors = {
  iterations,
  username,
  password,
  auth_secret: authSecret,
  public_key: identity.publicKey,
  encrypted_private_key: await encryptPrivateKey(identity.pkcs8, wrapKey),
  wrapped_room_key: await wrapRoomKey(roomKey, identity.publicKey),
  message: { room_id: roomId, sender_id: senderId, ...(await encryptMessage(roomKey, plaintext, roomId, senderId)), plaintext },
  media: { room_id: roomId, sender_id: senderId, ...(await encryptBytes(roomKey, mediaPlaintext, roomId, senderId)), plaintext_b64: toBase64(mediaPlaintext) },
};

await writeFile(new URL('./js_vectors.json', import.meta.url), `${JSON.stringify(vectors, null, 2)}\n`);
