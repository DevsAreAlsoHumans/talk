import { api } from "./api.js";
import * as cryptoUtil from "./crypto.js";
import { loadKeyPair, saveKeyPair } from "./idb.js";

// Un compte = une paire de clés, mise en cache ici par userId pour la session
// en cours (IndexedDB reste la source persistante, voir idb.js).
const keyPairCache = new Map();

export async function ensureKeyPair(userId) {
  if (keyPairCache.has(userId)) return keyPairCache.get(userId);

  const stored = await loadKeyPair(userId);
  if (stored) {
    keyPairCache.set(userId, stored);
    return stored;
  }

  const pair = await cryptoUtil.generateKeyPair();
  await saveKeyPair(userId, pair);
  keyPairCache.set(userId, pair);
  return pair;
}

// Limitation assumée : une clé E2E est liée à ce navigateur/IndexedDB. Se
// reconnecter depuis un autre appareil générerait une clé différente et
// casserait le déchiffrement des messages envoyés vers l'ancienne clé
// (pas de gestion multi-appareil dans ce projet).
export async function publishPublicKeyIfNeeded(user) {
  const pair = await ensureKeyPair(user.id);
  if (user.public_key) return;
  const publicKeyRaw = await cryptoUtil.exportPublicKeyRaw(pair.publicKey);
  await api.setPublicKey(publicKeyRaw);
}
