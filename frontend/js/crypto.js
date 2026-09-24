const DATABASE_NAME = "talk-e2ee";
const DATABASE_VERSION = 1;
const IDENTITY_STORE = "identity";
const RSA_ALGORITHM = { name: "RSA-OAEP", hash: "SHA-256" };
const identityPromises = new Map();

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function bytesToBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64ToBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function openDatabase() {
  return new Promise((resolve, reject) => {
    if (!("indexedDB" in globalThis)) {
      reject(new Error("IndexedDB est requis pour protéger la clé de cet appareil"));
      return;
    }
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(IDENTITY_STORE)) {
        database.createObjectStore(IDENTITY_STORE, { keyPath: "id" });
      }
    };
    request.onsuccess = () => {
      request.result.onversionchange = () => request.result.close();
      resolve(request.result);
    };
    request.onerror = () => reject(request.error || new Error("IndexedDB indisponible"));
    request.onblocked = () => reject(new Error("IndexedDB est bloquée par un autre onglet"));
  });
}

function runStoreRequest(mode, operation) {
  return openDatabase().then(
    (database) =>
      new Promise((resolve, reject) => {
        let transaction;
        try {
          transaction = database.transaction(IDENTITY_STORE, mode);
          const store = transaction.objectStore(IDENTITY_STORE);
          const request = operation(store);
          let result;
          request.onsuccess = () => {
            result = request.result;
          };
          request.onerror = () => {
            database.close();
            reject(request.error || new Error("Échec IndexedDB"));
          };
          transaction.oncomplete = () => {
            database.close();
            resolve(result);
          };
          transaction.onabort = () => {
            database.close();
            reject(transaction.error || new Error("Transaction IndexedDB annulée"));
          };
          transaction.onerror = () => {
            database.close();
            reject(transaction.error || new Error("Échec IndexedDB"));
          };
        } catch (error) {
          database.close();
          reject(error);
        }
      }),
  );
}

async function generateIdentityKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      ...RSA_ALGORITHM,
      modulusLength: 3072,
      publicExponent: new Uint8Array([1, 0, 1]),
    },
    false,
    ["encrypt", "decrypt"],
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  publicJwk.alg = "RSA-OAEP-256";
  publicJwk.use = "enc";
  publicJwk.key_ops = ["encrypt"];
  publicJwk.ext = true;
  return { keyPair, publicJwk };
}

async function getOrCreateIdentityRecord(accountId, deviceName) {
  const recordId = `account:${accountId}`;
  let record = await runStoreRequest("readonly", (store) => store.get(recordId));
  if (record) {
    return record;
  }

  const generated = await generateIdentityKeyPair();
  const keyId = crypto.randomUUID();
  record = {
    id: recordId,
    keyId,
    keyPair: generated.keyPair,
    publicJwk: { ...generated.publicJwk, kid: keyId },
    deviceName,
  };
  try {
    await runStoreRequest("readwrite", (store) => store.add(record));
  } catch (error) {
    if (error?.name !== "ConstraintError") {
      throw error;
    }
    record = await runStoreRequest("readonly", (store) => store.get(recordId));
  }
  return record;
}

export function loadOrCreateIdentity(accountId, deviceName) {
  if (identityPromises.has(accountId)) {
    return identityPromises.get(accountId);
  }
  const promise = getOrCreateIdentityRecord(accountId, deviceName)
    .then((record) => ({
      keyId: record.keyId,
      privateKey: record.keyPair.privateKey,
      publicJwk: record.publicJwk,
      deviceName: record.deviceName || deviceName,
    }))
    .finally(() => {
      identityPromises.delete(accountId);
    });
  identityPromises.set(accountId, promise);
  return promise;
}

export function identityPayload(identity) {
  return {
    key_id: identity.keyId,
    device_name: identity.deviceName,
    public_key: identity.publicJwk,
  };
}

export function createRoomKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

async function importRoomKey(rawKey) {
  return crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function wrapRoomKey(rawRoomKey, publicJwk) {
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    publicJwk,
    RSA_ALGORITHM,
    true,
    ["encrypt"],
  );
  const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawRoomKey);
  return bytesToBase64(new Uint8Array(wrapped));
}

export async function unwrapRoomKey(wrappedKey, identity) {
  try {
    const rawKey = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      identity.privateKey,
      base64ToBytes(wrappedKey),
    );
    return {
      roomKey: await importRoomKey(rawKey),
      rawRoomKey: rawKey,
    };
  } catch {
    throw new Error("Cette enveloppe de clé ne peut pas être ouverte sur cet appareil");
  }
}

export function messageContext(message) {
  return [
    "talk",
    "v1",
    message.room_id,
    message.channel_id,
    message.client_id,
    message.sender_id,
    String(message.key_version),
    message.algorithm,
  ].join("|");
}

export async function encryptMessage(plaintext, roomKey, message) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const payload = textEncoder.encode(JSON.stringify({ text: plaintext, version: 1 }));
  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: textEncoder.encode(messageContext(message)),
      tagLength: 128,
    },
    roomKey,
    payload,
  );
  return {
    ciphertext: bytesToBase64(new Uint8Array(encrypted)),
    nonce: bytesToBase64(iv),
  };
}

export async function decryptMessage(message, roomKey) {
  try {
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToBytes(message.nonce),
        additionalData: textEncoder.encode(messageContext(message)),
        tagLength: 128,
      },
      roomKey,
      base64ToBytes(message.ciphertext),
    );
    const payload = JSON.parse(textDecoder.decode(decrypted));
    if (payload.version !== 1 || typeof payload.text !== "string") {
      throw new Error("Format de message non pris en charge");
    }
    return payload.text;
  } catch {
    throw new Error("Le message est altéré ou sa clé est indisponible");
  }
}
