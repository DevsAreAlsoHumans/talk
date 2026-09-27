// Talk — cryptographie de bout en bout, entièrement dans le navigateur.
//
// Ce module ne contient aucun secret en dur et n'envoie jamais rien au serveur
// qui ne soit public ou déjà chiffré. Il ne dépend d'aucune bibliothèque
// externe : l'API Web Crypto du navigateur suffit, et `node --test` peut
// exécuter les mêmes fonctions.
//
// La règle structurante est simple : la clé privée RSA et les clés de salon
// n'existent que sous forme d'objets `CryptoKey` non extractibles, stockés
// dans IndexedDB. Le serveur ne voit jamais que des clés publiques, des
// enveloppes et des ciphertexts.

/** Paramètres RSA du MVP : OAEP avec SHA-256, conformément au serveur. */
export const RSA_PARAMS = Object.freeze({
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
});

/** Algorithme attendu par le serveur. Toute autre valeur doit être refusée. */
export const RSA_ALG = "RSA-OAEP-256";

/** Paramètres du chiffrement de salon : AES-256-GCM. */
export const AES_PARAMS = Object.freeze({ name: "AES-GCM", length: 256 });

/** Taille d'IV recommandée par NIST SP 800-38D, et imposée par le serveur. */
export const IV_BYTES = 12;

/** Taille de la balise d'authentification GCM, en bits. */
const GCM_TAG_BITS = 128;

/**
 * Version du format des données authentifiées additional.
 *
 * Ce n'est pas une version de protocole, mais une valeur liée à AAD : la
 * changer invalide les messages déjà chiffrés. Un changement doit donc
 * s'accompagner d'une migration, pas d'un simple déploiement.
 */
export const AAD_VERSION = 1;

/** Longueur maximale d'un message en clair, avant chiffrement. */
export const MAX_PLAINTEXT_LENGTH = 4000;

const subtle = () => {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error(
      "Web Crypto est indisponible. Un contexte sécurisé (HTTPS ou localhost) est requis.",
    );
  }
  return globalThis.crypto.subtle;
};

const utf8 = new TextEncoder();
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

/* ------------------------------------------------------------------ */
/* Encodage                                                            */
/* ------------------------------------------------------------------ */

export function toBase64(bytes) {
  const view = toUint8(bytes);
  let binary = "";
  // Par blocs de 0x8000 : `String.fromCharCode` sature sur de très longues
  // chaînes, un message de 4 000 caractères peut être bien au-delà.
  for (let offset = 0; offset < view.length; offset += 0x8000) {
    binary += String.fromCharCode(...view.subarray(offset, offset + 0x8000));
  }
  return globalThis.btoa(binary);
}

export function fromBase64(text) {
  const binary = globalThis.atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function toUint8(value) {
  if (value instanceof Uint8Array) {
    return value;
  }
  return new Uint8Array(value);
}

/* ------------------------------------------------------------------ */
/* Empreinte de clé publique (RFC 7638)                                */
/* ------------------------------------------------------------------ */

/**
 * Sérialisation canonique du RFC 7638 : membres obligatoires, triés
 * lexicographiquement, sans espace.
 *
 * Cette fonction doit rester identique à `PublicJwk.canonical_json` côté
 * serveur, sinon les deux empreintes divergent et la comparaison hors bande
 * devient impossible. Le test Python `test_publier_une_cle_publique` vérifie
 * que les deux implémentations coïncident sur une même clé.
 */
export function canonicalJwk(jwk) {
  return `{"e":"${jwk.e}","kty":"${jwk.kty}","n":"${jwk.n}"}`;
}

/** Empreinte d'une clé publique, base64url sans remplissage. */
export async function thumbprint(jwk) {
  const digest = await subtle().digest("SHA-256", utf8.encode(canonicalJwk(jwk)));
  return base64Url(digest);
}

function base64Url(bytes) {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/* ------------------------------------------------------------------ */
/* Identité RSA                                                        */
/* ------------------------------------------------------------------ */

/**
 * Génère une paire RSA et renvoie la clé privée **non extractible**.
 *
 * La génération directe ne permet pas de produire une clé privée
 * non extractible tout en gardant la paire utilisable : `generateKey` exige
 * `extractable: true` dès que la paire est destinée à être exportée, et
 * `extractKey` refuse ensuite une clé privée marquée non extractible. Le
 * contournement est donc le suivant :
 *
 * 1. générer la paire en extractible ;
 * 2. exporter les deux JWK ;
 * 3. réimporter la clé privée avec `extractable: false`.
 *
 * Le JWK privé n'existe que dans des chaînes JavaScript, que le ramasse-miettes
 * collectera à un moment indéterminé. On ne peut pas l'effacer soi-même — c'est
 * la limite du langage. Ce qui compte est qu'il ne soit jamais stocké ni
 * transmis.
 */
export async function generateIdentity() {
  const generated = await subtle().generateKey(RSA_PARAMS, true, ["encrypt", "decrypt"]);
  const privateJwk = await subtle().exportKey("jwk", generated.privateKey);
  const sealed = await subtle().importKey("jwk", privateJwk, RSA_PARAMS, false, ["decrypt"]);

  return {
    publicJwk: sanitizePublicJwk(await subtle().exportKey("jwk", generated.publicKey)),
    privateKey: sealed,
  };
}

/**
 * Ne conserve que les membres que le serveur sait valider.
 *
 * Les navigateurs n'exportent pas tous exactement les mêmes membres. Le serveur
 * refusant tout champ inattendu, on projette ici sur `{kty, n, e, alg}` plutôt
 * que de dépendre du navigateur. L'empreinte, elle, ne retient que `e`, `kty`
 * et `n` : la projection ne change donc rien à la valeur de comparaison.
 */
export function sanitizePublicJwk(jwk) {
  if (jwk.alg && jwk.alg !== RSA_ALG) {
    throw new Error(`Algorithme inattendu : ${jwk.alg}. ${RSA_ALG} est requis.`);
  }
  if (jwk.kty !== "RSA") {
    throw new Error("Seules les clés RSA sont prises en charge.");
  }
  return { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: RSA_ALG };
}

/** Importe une clé publique reçue du serveur, prête à emballer une clé de salon. */
export async function importPublicKey(jwk) {
  return subtle().importKey("jwk", sanitizePublicJwk(jwk), RSA_PARAMS, true, ["encrypt"]);
}

/** Vrai si la clé privée stockée est encore utilisable pour déchiffrer. */
export function isUsablePrivateKey(key) {
  return Boolean(key) && key.type === "private" && !key.extractable;
}

/* ------------------------------------------------------------------ */
/* Clé de salon                                                        */
/* ------------------------------------------------------------------ */

/**
 * Efface un tampon de données sensibles.
 *
 * Efficace sur un `Uint8Array` : sa mémoire nous appartient et peut être
 * réécrite. Inefficace sur une chaîne, que le moteur a pu copier ou
 *(compiler en dur) à l'insu du programmeur — c'est pourquoi ce module évite
 * autant que possible de faire transiter des octets de clé par du texte.
 */
export function wipe(bytes) {
  if (bytes instanceof Uint8Array) {
    bytes.fill(0);
  }
  return bytes;
}

/**
 * Génère une clé de salon, sous ses deux formes.
 *
 * - `key`, celle qui est stockée dans le navigateur et qui chiffre les messages ;
 * - `raw`, les 32 octets, destinés à être emballés puis effacés.
 *
 * **La clé stockée est extractible, délibérément.** C'est une contrainte, pas un
 * oubli : emballer une clé de salon pour un membre qui rejoint le canal exige les
 * octets bruts de cette clé, or l'API `wrapKey` refuse une clé non extractible
 * et `exportKey` refuse de lire une clé AES non extractible. Sans rotation de clé
 * de salon — hors périmètre du MVP — il n'existe donc aucun moyen d'ajouter un
 * membre si la clé locale est non extractible.
 *
 * La clé privée RSA, elle, reste non extractible : c'est la clé d'identité, la
 * plus longue durée de vie, et celle dont la protection a le plus de sens. Voir
 * `generateIdentity`.
 *
 * Conséquence assumée : un script exécuté dans l'origine peut lire la clé de
 * salon. Il pouvait déjà l'utiliser pour déchiffrer les messages ; il peut en
 * outre l'exfiltrer pour un déchiffrement ultérieur. C'est la contrepartie du
 * fait de ne pas prévoir de rotation.
 */
export async function generateRoomKey() {
  const key = await subtle().generateKey(AES_PARAMS, true, ["encrypt", "decrypt"]);
  const raw = new Uint8Array(await subtle().exportKey("raw", key));
  return { key, raw };
}

/**
 * Importe une clé de salon brute.
 *
 * La taille est vérifiée ici et non laissée au moteur : `importKey` accepte
 * silencieusement 16 octets pour une clé AES-256, et produirait une clé 128 bits
 * sans rien signaler. Une enveloppe dont la taille ne correspond pas doit donc
 * être refusée explicitement, pas transformée en clé plus faible.
 */
export async function importRoomKey(raw) {
  if (raw.length !== AES_PARAMS.length / 8) {
    throw new RangeError(
      `Une clé de salon AES-256 fait ${AES_PARAMS.length / 8} octets, reçu : ${raw.length}.`,
    );
  }
  return subtle().importKey("raw", raw, AES_PARAMS, true, ["encrypt", "decrypt"]);
}

/**
 * Emballe les octets d'une clé de salon pour une clé publique destinataire.
 *
 * `encrypt` et non `wrapKey` : l'API `wrapKey` refuse une clé non extractible,
 * ce qui la rend inutilisable ici. Le résultat fait 256 octets pour une clé
 * RSA-2048, et c'est cette taille que le serveur valide.
 */
export async function wrapRoomKey(rawRoomKey, recipientPublicKey) {
  return subtle().encrypt({ name: RSA_PARAMS.name }, recipientPublicKey, rawRoomKey);
}

/**
 * Déballe une clé de salon.
 *
 * Les octets intermédiaires sont effacés dès que possible, y compris en cas
 * d'échec : RSA peut refuser l'enveloppe reçue, et l'octet ne doit pas rester
 * en mémoire dans ce cas.
 */
export async function unwrapRoomKey(wrapped, privateKey) {
  let raw = null;
  try {
    raw = new Uint8Array(
      await subtle().decrypt({ name: RSA_PARAMS.name }, privateKey, wrapped),
    );
    return await importRoomKey(raw);
  } finally {
    wipe(raw);
  }
}

/* ------------------------------------------------------------------ */
/* Messages                                                            */
/* ------------------------------------------------------------------ */

/**
 * Données authentifiées additional d'un message.
 *
 * Elles lient le ciphertext à trois éléments : la version du format, le canal et
 * l'expéditeur. Sans cela, un message pourrait être rejoué dans un autre canal
 * ou attribué à quelqu'un d'autre par un intermédiaire qui rejoue un
 * ciphertext intact. Cela ne remplace pas une signature : AES-GCM avec
 * une clé partagée n'authentifie pas l'expéditeur, il empêche seulement la
 * substitution et la réutilisation.
 *
 * Le format est exactement `talk:v1:{channel_id}:{sender_id}`, la version
 * venant de `AAD_VERSION`. Ce littéral fait partie de l'architecture décidée :
 * il n'est pas libre, et un test le vérifie de l'extérieur, en redéchiffrant un
 * message avec un AAD reconstruit à la main. Le modifier sans migration invalide
 * tous les messages déjà chiffrés.
 */
function additionalData(channelId, senderId) {
  return utf8.encode(`talk:v${AAD_VERSION}:${channelId}:${senderId}`);
}

/** Chiffre un message. L'IV est tiré au hasard à chaque appel. */
export async function encryptMessage(roomKey, plaintext, channelId, senderId) {
  if (typeof plaintext !== "string") {
    throw new TypeError("Le message doit être une chaîne.");
  }
  if (plaintext.length > MAX_PLAINTEXT_LENGTH) {
    throw new RangeError(
      `Message trop long : ${plaintext.length} caractères, maximum ${MAX_PLAINTEXT_LENGTH}.`,
    );
  }
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = await subtle().encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: additionalData(channelId, senderId),
      tagLength: GCM_TAG_BITS,
    },
    roomKey,
    utf8.encode(plaintext),
  );
  return { iv: toBase64(iv), ciphertext: toBase64(ciphertext) };
}

/**
 * Déchiffre un message.
 *
 * Léchec de l'authentification GCM — clé erronée, canal ou expéditeur falsifié,
 * ciphertext altéré — se traduit par une exception, jamais par un texte
 * silencieusement corrompu.
 */
export async function decryptMessage(roomKey, payload, channelId, senderId) {
  const plaintext = await subtle().decrypt(
    {
      name: "AES-GCM",
      iv: fromBase64(payload.iv),
      additionalData: additionalData(channelId, senderId),
      tagLength: GCM_TAG_BITS,
    },
    roomKey,
    fromBase64(payload.ciphertext),
  );
  return utf8Decoder.decode(plaintext);
}
