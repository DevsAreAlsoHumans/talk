const DB_NAME = "talk-crypto";
const STORE_NAME = "keys";

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// Un CryptoKey (extractable ou non) peut être stocké tel quel en IndexedDB :
// on garde donc la paire de clés ECDH en local sans jamais l'exporter en clair.
// Clé indexée par userId : IndexedDB est partagée par origine (pas par compte),
// donc plusieurs comptes dans le même navigateur doivent avoir chacun leur
// propre paire (sinon le 2e compte réutiliserait celle du 1er par erreur).
export async function loadKeyPair(userId) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, "readonly");
    const request = transaction.objectStore(STORE_NAME).get(userId);
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
  });
}

export async function saveKeyPair(userId, keyPair) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, "readwrite");
    transaction.objectStore(STORE_NAME).put(keyPair, userId);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}
