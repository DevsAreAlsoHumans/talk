/* Non-régression E2EE côté client — Node exécute réellement le code du
   navigateur (WebCrypto global) afin de verrouiller le pipeline
   wrap/unwrap/enveloppes qui n'est PAS couvert par pytest.

   Shim IndexedDB minimal : les clés privées vivent en mémoire, le flux
   ensureIdentity -> stockage -> relecture reste le chemin réellement testé.
*/

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ensureIdentity,
  generateRoomKey,
  wrapRoomKey,
  unwrapRoomKey,
  encryptMessage,
  decryptMessage,
} from "../../frontend/js/crypto.js";

function installIndexedDbShim() {
  const store = new Map();
  const request = {
    result: null,
    onupgradeneeded: null,
    onsuccess: null,
    onerror: null,
  };
  globalThis.indexedDB = {
    open() {
      request.result = {
        transaction() {
          return {
            objectStore() {
              return {
                get(key) {
                  const tx = { result: store.get(key), onsuccess: null, onerror: null };
                  queueMicrotask(() => tx.onsuccess && tx.onsuccess());
                  return tx;
                },
                put(value, key) {
                  store.set(key, value);
                  const tx = { onsuccess: null, onerror: null };
                  queueMicrotask(() => tx.onsuccess && tx.onsuccess());
                  return tx;
                },
              };
            },
          };
        },
      };
      queueMicrotask(() => request.onsuccess && request.onsuccess());
      return request;
    },
  };
}

async function rawOf(key) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

function eqBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

test("ensureIdentity crée et replique la même identité (persistance)", async () => {
  installIndexedDbShim();
  const first = await ensureIdentity("alice");
  assert.ok(first.publicKey && first.privateKey && first.publicRaw);
  const second = await ensureIdentity("alice");
  assert.equal(second.publicRaw, first.publicRaw, "la clé publique doit être stable");
  const bob = await ensureIdentity("bob");
  assert.notEqual(bob.publicRaw, first.publicRaw, "deux pseudos = deux identités");
});

test("wrap de la clé de salon vers SOI-MÊME puis unwrap (régression deriveKey)", async () => {
  installIndexedDbShim();
  const me = await ensureIdentity("alice");
  const roomKey = await generateRoomKey();
  const blob = await wrapRoomKey(me, me.publicRaw, "room-x", roomKey.raw);
  const unwrapped = await unwrapRoomKey(me, me.publicRaw, "room-x", blob);
  assert.ok(eqBytes(unwrapped.raw, roomKey.raw), "la clé déwrappée doit récupérer la clé d'origine");
});

test("wrap vers un pair : seul le pair déchiffre (pas l'expéditeur)", async () => {
  installIndexedDbShim();
  const alice = await ensureIdentity("alice");
  const bob = await ensureIdentity("bob");
  const roomKey = await generateRoomKey();
  const blob = await wrapRoomKey(alice, bob.publicRaw, "room-y", roomKey.raw);

  const bobGot = await unwrapRoomKey(bob, alice.publicRaw, "room-y", blob);
  assert.ok(eqBytes(bobGot.raw, roomKey.raw), "le destinataire récupère la clé");

  await assert.rejects(
    unwrapRoomKey(alice, alice.publicRaw, "room-y", blob),
    "une clé enveloppée pour bob ne doit pas s'ouvrir avec la clé privée d'alice",
  );
});

test("même salon mais contextes différents : le salt du salon sépare les clés", async () => {
  installIndexedDbShim();
  const alice = await ensureIdentity("alice");
  const bob = await ensureIdentity("bob");
  const roomKey = await generateRoomKey();
  const blobRoomA = await wrapRoomKey(alice, bob.publicRaw, "room-a", roomKey.raw);
  await assert.rejects(
    unwrapRoomKey(bob, alice.publicRaw, "room-b", blobRoomA),
    "déwrappage avec un roomId != celui du wrap doit échouer (GCM)",
  );
});

test("chiffrement/déchiffrement d'un message (AAD roomId|from)", async () => {
  installIndexedDbShim();
  const alice = await ensureIdentity("alice");
  const roomKey = await generateRoomKey();
  const blob = await encryptMessage(roomKey.key, "room-z", "alice", "salut, bout en bout !");
  const text = await decryptMessage(roomKey.key, "room-z", "alice", blob);
  assert.equal(text, "salut, bout en bout !");
});

test("message falsifié ou envoyé par un autre : null (pas de clair fuite)", async () => {
  installIndexedDbShim();
  const roomKey = await generateRoomKey();
  const blob = await encryptMessage(roomKey.key, "room-z", "alice", "contenu secret");

  assert.equal(await decryptMessage(roomKey.key, "room-z", "bob", blob), null, "from différent -> rejet");
  assert.equal(await decryptMessage(roomKey.key, "room-other", "alice", blob), null, "roomId différent -> rejet");

  const forged = JSON.stringify({ v: 1, iv: JSON.parse(blob).iv, ct: JSON.parse(blob).ct.slice(0, -4) + "AAAA" });
  assert.equal(await decryptMessage(roomKey.key, "room-z", "alice", forged), null, "ciphertext corrompu -> null");

  assert.equal(await decryptMessage(roomKey.key, "room-z", "alice", "{pas du json"), null, "enveloppe cassée -> null");
  assert.equal(await decryptMessage(roomKey.key, "room-z", "alice", "nimporte quoi"), null);
});