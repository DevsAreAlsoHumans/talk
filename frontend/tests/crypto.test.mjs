import assert from "node:assert/strict";
import test from "node:test";

import {
  createRoomKey,
  decryptMessage,
  encryptMessage,
  unwrapRoomKey,
  wrapRoomKey,
} from "../js/crypto.js";

const RSA_ALGORITHM = { name: "RSA-OAEP", hash: "SHA-256" };

async function createIdentity() {
  const keyPair = await crypto.subtle.generateKey(
    {
      ...RSA_ALGORITHM,
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
    },
    false,
    ["encrypt", "decrypt"],
  );
  return {
    privateKey: keyPair.privateKey,
    publicJwk: await crypto.subtle.exportKey("jwk", keyPair.publicKey),
  };
}

function messageMetadata(overrides = {}) {
  return {
    client_id: "64cbad44-295f-4c67-8642-70a0dd862781",
    algorithm: "AES-GCM-256",
    key_version: 1,
    room_id: "09faef65-1a87-46dc-92c7-6681bb15b1e9",
    channel_id: "a378768a-ef42-49da-b435-1f6ac5573d11",
    sender_id: "3afc0254-9a87-4113-b087-e1f5ef5f9725",
    ...overrides,
  };
}

function fromBase64url(value) {
  return Uint8Array.from(Buffer.from(value, "base64url"));
}

function toBase64url(value) {
  return Buffer.from(value).toString("base64url");
}

test("une clé de salon peut être enveloppée puis ouverte", async () => {
  const identity = await createIdentity();
  const rawRoomKey = createRoomKey();
  const wrapped = await wrapRoomKey(rawRoomKey, identity.publicJwk);
  const opened = await unwrapRoomKey(wrapped, identity);

  assert.equal(opened.rawRoomKey.byteLength, 32);
  assert.deepEqual(new Uint8Array(opened.rawRoomKey), rawRoomKey);
  assert.equal(identity.privateKey.extractable, false);
});

test("un message accentué est chiffré et déchiffré avec un nonce aléatoire", async () => {
  const metadata = messageMetadata();
  const rawRoomKey = createRoomKey();
  const roomKey = await crypto.subtle.importKey(
    "raw",
    rawRoomKey,
    "AES-GCM",
    false,
    ["encrypt", "decrypt"],
  );
  const plaintext = "Bonjour Julia 👋\nMessage vraiment secret 🔐";

  const first = await encryptMessage(plaintext, roomKey, metadata);
  const second = await encryptMessage(plaintext, roomKey, metadata);
  assert.notEqual(first.nonce, second.nonce);
  assert.notEqual(first.ciphertext, second.ciphertext);
  assert.equal(await decryptMessage({ ...metadata, ...first }, roomKey), plaintext);
  assert.equal(await decryptMessage({ ...metadata, ...second }, roomKey), plaintext);
});

test("une modification du canal ou du ciphertext invalide le déchiffrement", async () => {
  const metadata = messageMetadata();
  const roomKey = await crypto.subtle.importKey(
    "raw",
    createRoomKey(),
    "AES-GCM",
    false,
    ["encrypt", "decrypt"],
  );
  const encrypted = await encryptMessage("contenu", roomKey, metadata);
  const tampered = fromBase64url(encrypted.ciphertext);
  tampered[tampered.length - 1] ^= 1;

  await assert.rejects(
    () =>
      decryptMessage(
        { ...metadata, ...encrypted, channel_id: crypto.randomUUID() },
        roomKey,
      ),
  );
  await assert.rejects(() =>
    decryptMessage(
      { ...metadata, ...encrypted, ciphertext: toBase64url(tampered) },
      roomKey,
    ),
  );
});
