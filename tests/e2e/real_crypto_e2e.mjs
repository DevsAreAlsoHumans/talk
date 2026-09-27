// Test de bout en bout contre l'app reelle, qui importe le VRAI
// frontend/js/crypto.js pour prouver que le chiffrement E2E fonctionne
// (pas seulement l'API REST autour) : le serveur ne voit et ne relaie
// jamais que du ciphertext opaque, pour les messages, les pieces jointes
// et le secret 2FA.
//
// Pas dans la CI (a besoin d'un serveur qui tourne). A executer manuellement :
//   docker compose up -d
//   node tests/e2e/real_crypto_e2e.mjs
import crypto from "node:crypto";
import * as cryptoUtil from "../../frontend/js/crypto.js";

const BASE_URL = process.env.TALK_BASE_URL ?? "http://localhost:8000";

function makeClient() {
  const cookies = new Map();

  function cookieHeader() {
    return [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  function storeCookies(res) {
    for (const line of res.headers.getSetCookie()) {
      const pair = line.split(";")[0];
      const idx = pair.indexOf("=");
      cookies.set(pair.slice(0, idx), pair.slice(idx + 1));
    }
  }

  async function request(method, path, { json, form, headers = {} } = {}) {
    const finalHeaders = { ...headers, Cookie: cookieHeader() };
    let body;
    if (json !== undefined) {
      finalHeaders["Content-Type"] = "application/json";
      body = JSON.stringify(json);
    } else if (form !== undefined) {
      body = form;
    }
    const res = await fetch(`${BASE_URL}${path}`, { method, headers: finalHeaders, body });
    storeCookies(res);
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`${method} ${path} -> ${res.status}: ${text}`);
    }
    return res;
  }

  return {
    get: (path) => request("GET", path),
    post: (path, opts) => request("POST", path, opts),
    put: (path, opts) => request("PUT", path, opts),
    csrfHeaders: () => ({ "X-CSRF-Token": cookies.get("csrf_token") }),
  };
}

// ---------- TOTP (RFC 6238 : HMAC-SHA1, pas de 30s, 6 chiffres) ----------
function base32Decode(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of base32.replace(/=+$/, "").toUpperCase()) {
    const val = alphabet.indexOf(char);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function totpCode(secretBase32, when = Date.now()) {
  const counter = Math.floor(when / 1000 / 30);
  const key = base32Decode(secretBase32);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", key).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binCode % 1000000).padStart(6, "0");
}

// ---------- Utilitaires ----------
const STRONG_PASSWORD = "Sup3r$ecretPass!";

function uniqueEmail(label) {
  return `e2e-${label}-${crypto.randomBytes(4).toString("hex")}@example.com`;
}

async function registerUser(client, label) {
  const username = `e2e${label}${crypto.randomBytes(3).toString("hex")}`;
  const res = await client.post("/auth/register", {
    json: { username, email: uniqueEmail(label), password: STRONG_PASSWORD },
  });
  const user = await res.json();
  const keyPair = await cryptoUtil.generateKeyPair();
  const publicKeyRaw = await cryptoUtil.exportPublicKeyRaw(keyPair.publicKey);
  await client.put("/users/me/public-key", {
    json: { public_key: publicKeyRaw },
    headers: client.csrfHeaders(),
  });
  return { user, keyPair, publicKeyRaw };
}

function assert(condition, message) {
  if (!condition) throw new Error(`ECHEC : ${message}`);
  console.log(`  OK - ${message}`);
}

async function main() {
  console.log("== Inscription d'Alice et Bob + publication des cles publiques ==");
  const aliceClient = makeClient();
  const bobClient = makeClient();
  const alice = await registerUser(aliceClient, "alice");
  const bob = await registerUser(bobClient, "bob");
  assert(alice.user.username && bob.user.username, "comptes crees");

  console.log("\n== Envoi de message chiffre en DM (vrai ECDH + AES-GCM) ==");
  const dmRes = await aliceClient.post("/rooms/dm", {
    json: { username: bob.user.username, discriminator: bob.user.discriminator },
  });
  const room = await dmRes.json();
  const bobPeerPublicKey = await cryptoUtil.importPeerPublicKey(room.peer.public_key);
  const aliceSharedKey = await cryptoUtil.deriveSharedKey(alice.keyPair.privateKey, bobPeerPublicKey);

  const plaintext = "Bonjour Bob, ceci est un message secret pour toi uniquement.";
  const { ciphertext, iv } = await cryptoUtil.encryptMessage(aliceSharedKey, plaintext);
  assert(!ciphertext.includes(plaintext), "le ciphertext ne contient pas le texte en clair");

  await aliceClient.post(`/rooms/${room.id}/messages`, {
    json: { ciphertext, iv },
    headers: aliceClient.csrfHeaders(),
  });

  const bobRoomsRes = await bobClient.get("/rooms");
  const bobRoom = (await bobRoomsRes.json()).find((r) => r.id === room.id);
  const alicePeerPublicKey = await cryptoUtil.importPeerPublicKey(bobRoom.peer.public_key);
  const bobSharedKey = await cryptoUtil.deriveSharedKey(bob.keyPair.privateKey, alicePeerPublicKey);

  const historyRes = await bobClient.get(`/rooms/${room.id}/messages`);
  const history = await historyRes.json();
  const lastMessage = history[history.length - 1];
  const decrypted = await cryptoUtil.decryptMessage(bobSharedKey, lastMessage.ciphertext, lastMessage.iv);
  assert(decrypted === plaintext, "Bob dechiffre exactement le message envoye par Alice");

  console.log("\n== Ajout d'ami par pseudo#tag ==");
  await aliceClient.post("/friends/requests", {
    json: { username: bob.user.username, discriminator: bob.user.discriminator },
    headers: aliceClient.csrfHeaders(),
  });
  const bobRequestsRes = await bobClient.get("/friends/requests");
  const incoming = (await bobRequestsRes.json()).find((r) => r.direction === "incoming");
  assert(incoming && incoming.peer.username === alice.user.username, "Bob voit la demande d'Alice");
  await bobClient.post(`/friends/requests/${incoming.id}/accept`, { headers: bobClient.csrfHeaders() });
  const aliceFriendsRes = await aliceClient.get("/friends");
  const aliceFriends = await aliceFriendsRes.json();
  assert(
    aliceFriends.some((f) => f.peer.username === bob.user.username),
    "Alice et Bob sont bien amis apres acceptation"
  );

  console.log("\n== Piece jointe chiffree (image simulee) ==");
  const fakeImageBytes = crypto.randomBytes(2048);
  const { ciphertext: attachmentCiphertext, iv: attachmentIv } = await cryptoUtil.encryptBytes(
    aliceSharedKey,
    fakeImageBytes
  );
  const form = new FormData();
  form.append("file", new Blob([attachmentCiphertext]), "blob");
  form.append("iv", attachmentIv);
  form.append("content_type", "image/png");
  const uploadRes = await aliceClient.post(`/rooms/${room.id}/attachments`, {
    form,
    headers: aliceClient.csrfHeaders(),
  });
  const attachment = await uploadRes.json();
  assert(attachment.content_type === "image/png", "le content_type declaratif est bien stocke");

  await aliceClient.post(`/rooms/${room.id}/messages`, {
    json: { ciphertext: "cover", iv: "cover", attachment_id: attachment.id },
    headers: aliceClient.csrfHeaders(),
  });

  const downloadRes = await bobClient.get(`/rooms/${room.id}/attachments/${attachment.id}`);
  const downloadedCiphertext = await downloadRes.arrayBuffer();
  const decryptedBytes = Buffer.from(
    await cryptoUtil.decryptBytes(bobSharedKey, downloadedCiphertext, attachment.iv)
  );
  assert(decryptedBytes.equals(fakeImageBytes), "Bob dechiffre exactement les octets de l'image envoyee");

  console.log("\n== 2FA (TOTP reel, RFC 6238) ==");
  const setupRes = await aliceClient.post("/auth/2fa/setup", { headers: aliceClient.csrfHeaders() });
  const setup = await setupRes.json();
  const confirmCode = totpCode(setup.secret);
  await aliceClient.post("/auth/2fa/confirm", {
    json: { code: confirmCode },
    headers: aliceClient.csrfHeaders(),
  });

  await aliceClient.post("/auth/logout", { headers: aliceClient.csrfHeaders() });
  const loginRes = await aliceClient.post("/auth/login", {
    json: { email: alice.user.email, password: STRONG_PASSWORD },
  });
  const loginResult = await loginRes.json();
  assert(loginResult.totp_required === true, "la 2FA est bien exigee au login apres activation");

  const loginCode = totpCode(setup.secret);
  await aliceClient.post("/auth/2fa/verify", {
    json: { pending_token: loginResult.pending_token, code: loginCode },
  });
  const meRes = await aliceClient.get("/auth/me");
  const me = await meRes.json();
  assert(me.username === alice.user.username, "session ouverte apres verification du code TOTP reel");

  console.log("\nTOUT PASSE — chiffrement E2E, amis, pieces jointes et 2FA verifies avec le vrai code client.");
}

main().catch((error) => {
  console.error("\nECHEC :", error);
  process.exit(1);
});
