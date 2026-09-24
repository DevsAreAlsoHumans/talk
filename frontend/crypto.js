(function () {
  "use strict";

  const STORAGE_KEY = "talk_identity_v1";

  function bufToB64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    bytes.forEach((b) => {
      bin += String.fromCharCode(b);
    });
    return btoa(bin);
  }

  function b64ToBuf(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function loadIdentity() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (_err) {
      return null;
    }
  }

  async function generateIdentity() {
    const pair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    );
    const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const privateKey = await crypto.subtle.exportKey("jwk", pair.privateKey);
    const identity = { publicKey, privateKey, createdAt: Date.now() };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(identity));
    return identity;
  }

  async function getIdentity() {
    const identity = loadIdentity();
    return identity || generateIdentity();
  }

  async function importPublicKey(jwk) {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt"]
    );
  }

  async function importPrivateKey(jwk) {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"]
    );
  }

  async function generateChannelKey() {
    return crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }

  async function wrapChannelKey(aesKey, rsaPublicJwk) {
    const publicKey = await importPublicKey(rsaPublicJwk);
    const raw = await crypto.subtle.exportKey("raw", aesKey);
    const wrapped = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      raw
    );
    return bufToB64(wrapped);
  }

  async function unwrapChannelKey(wrappedB64, rsaPrivateJwk) {
    const privateKey = await importPrivateKey(rsaPrivateJwk);
    const raw = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      b64ToBuf(wrappedB64)
    );
    return crypto.subtle.importKey(
      "raw",
      raw,
      { name: "AES-GCM" },
      true,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptMessage(plaintext, aesKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode(plaintext);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      aesKey,
      data
    );
    return { iv: bufToB64(iv), ciphertext: bufToB64(ciphertext) };
  }

  async function decryptMessage(ivB64, ciphertextB64, aesKey) {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64ToBuf(ivB64) },
      aesKey,
      b64ToBuf(ciphertextB64)
    );
    return new TextDecoder().decode(plaintext);
  }

  window.talkCrypto = {
    getIdentity,
    generateChannelKey,
    wrapChannelKey,
    unwrapChannelKey,
    encryptMessage,
    decryptMessage,
  };
})();