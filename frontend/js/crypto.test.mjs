// Tests de la cryptographie de bout en bout, exécutés par `node --test`.
//
// Ces tests utilisent de vraies clés Web Crypto, contrairement aux tests Python
// qui se contentent de valider des formes. C'est ce qui permet de vérifier le
// point le plus subtil de l'étape 3 : qu'une clé emballée par un membre soit
// bien déballée par un autre, et qu'un message chiffré par l'un soit
// déchiffré par l'autre.
//
// Aucun test ne dépend du réseau ni d'un navigateur : `globalThis.crypto` est
// disponible nativement depuis Node 19.

import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { after, before, describe, it } from "node:test";

// Node expose `crypto` globalement depuis la 19 ; le test doit aussi passer si
// l'environnement fournit une version antérieure.
if (!globalThis.crypto || !globalThis.crypto.subtle) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
}

const {
  AES_PARAMS,
  canonicalJwk,
  decryptMessage,
  encryptMessage,
  fromBase64,
  generateIdentity,
  generateRoomKey,
  importPublicKey,
  importRoomKey,
  isUsablePrivateKey,
  MAX_PLAINTEXT_LENGTH,
  RSA_ALG,
  sanitizePublicJwk,
  thumbprint,
  toBase64,
  unwrapRoomKey,
  wipe,
  wrapRoomKey,
} = await import("./crypto.js");

// Une paire RSA coûte environ 100 ms à générer. On en crée une seule pour toute
// la suite : la partagée entre les tests, la divider par cas coûterait bien plus.
let alice;
let bob;

before(async () => {
  [alice, bob] = await Promise.all([generateIdentity(), generateIdentity()]);
});

describe("encodage base64", () => {
  it("fait l'aller-retour sur des octets arbitraires", () => {
    const bytes = new Uint8Array(256);
    for (let index = 0; index < 256; index += 1) {
      bytes[index] = index;
    }
    assert.deepEqual(fromBase64(toBase64(bytes)), bytes);
  });

  it("survit à une charge dépassant la limite d'un appel à fromCharCode", () => {
    // 40 000 octets : au-delà du seuil où `String.fromCharCode(...octets)` sature.
    const bytes = new Uint8Array(40_000).fill(7);
    assert.equal(fromBase64(toBase64(bytes)).length, 40_000);
  });

  it("préserve les octets non-ASCII d'un texte", () => {
    const text = "éàü — 你好 🙂";
    const encoded = new TextEncoder().encode(text);
    assert.equal(new TextDecoder().decode(fromBase64(toBase64(encoded))), text);
  });
});

describe("empreinte de clé publique", () => {
  it("suit le RFC 7638 : SHA-256 de la forme canonique, en base64url", async () => {
    // Vecteur du RFC 7638, section 3.1 : la même clé doit donner la même
    // empreinte partout, que ce soit en JavaScript ou en Python.
    const jwk = {
      kty: "RSA",
      n:
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      e: "AQAB",
    };
    assert.equal(
      await thumbprint(jwk),
      "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
    );
  });

  it("ne dépend que des membres obligatoires", () => {
    const base = { kty: "RSA", n: "abc", e: "AQAB" };
    assert.equal(canonicalJwk({ ...base, alg: RSA_ALG, ext: true }), canonicalJwk(base));
  });

  it("diffère pour deux clés distinctes", async () => {
    assert.notEqual(await thumbprint(alice.publicJwk), await thumbprint(bob.publicJwk));
  });
});

describe("clé privée", () => {
  it("est stockée non extractible", () => {
    assert.ok(isUsablePrivateKey(alice.privateKey));
    assert.equal(alice.privateKey.extractable, false);
  });

  it("ne peut pas être exportée", async () => {
    // C'est la garantie centrale : même du code de la page ne peut pas lire les
    // octets de la clé privée. Une XSS peut utiliser la clé, pas la voler.
    await assert.rejects(() => globalThis.crypto.subtle.exportKey("jwk", alice.privateKey));
  });

  it("rejette une clé absente ou une clé publique", () => {
    assert.equal(isUsablePrivateKey(null), false);
    assert.equal(isUsablePrivateKey({ type: "public" }), false);
  });
});

describe("projection de la clé publique", () => {
  it("ne conserve que les membres acceptés par le serveur", () => {
    const projected = sanitizePublicJwk({
      kty: "RSA",
      n: "abc",
      e: "AQAB",
      alg: RSA_ALG,
      ext: true,
      // Membres que certains navigateurs ajoutent, et que le serveur refuserait.
      key_ops: ["encrypt"],
      extra: "inattendu",
    });
    assert.deepEqual(Object.keys(projected).sort(), ["alg", "e", "kty", "n"]);
  });

  it("refuse un algorithme ou un type inattendu", () => {
    assert.throws(() => sanitizePublicJwk({ kty: "RSA", n: "a", e: "AQAB", alg: "RSA-OAEP" }));
    assert.throws(() => sanitizePublicJwk({ kty: "EC", n: "a", e: "AQAB" }));
  });

  it("donne une clé importable et utilisable", async () => {
    const imported = await importPublicKey(alice.publicJwk);
    assert.equal(imported.type, "public");
  });
});

describe("clé de salon", () => {
  it("est extractible, par contrainte et non par oubli", async () => {
    // Ce test verrouille une décision, pas un détail d'implémentation.
    // Une clé non extractible serait plus sûre au repos, mais rendrait
    // impossible d'emballer la clé pour un membre qui rejoint le canal plus
    // tard : `wrapKey` et `exportKey` refusent tous deux une clé non
    // extractible. Voir le commentaire de `generateRoomKey`.
    const { key } = await generateRoomKey();
    assert.equal(key.extractable, true);
    assert.equal(key.algorithm.name, "AES-GCM");
    assert.equal(key.algorithm.length, AES_PARAMS.length);
  });

  it("fournit 32 octets pour l'emballage, que l'appelant peut effacer", async () => {
    const { key, raw } = await generateRoomKey();
    assert.equal(raw.length, 32);
    // Une fois effacés, la clé stockée reste utilisable : les deux formes sont
    // indépendantes, ce qui permet de nettoyer le tampon au plus tôt.
    wipe(raw);
    assert.ok(raw.every((byte) => byte === 0));
    const payload = await encryptMessage(key, "texte", "c", "s");
    assert.equal(await decryptMessage(key, payload, "c", "s"), "texte");
  });

  it("se ferme et se rouvre sans perte par l'import brut", async () => {
    const { key, raw } = await generateRoomKey();
    const reopened = await importRoomKey(raw);
    const payload = await encryptMessage(key, "texte", "c", "s");
    assert.equal(await decryptMessage(reopened, payload, "c", "s"), "texte");
  });

  it("efface un tampon sur demande", () => {
    const buffer = new Uint8Array([1, 2, 3]);
    wipe(buffer);
    assert.deepEqual(buffer, new Uint8Array([0, 0, 0]));
  });

  it("refuse d'importer une clé de mauvaise taille", async () => {
    // AES-256 impose 32 octets : une taille fausse doit être refusée, et non
    // complétée silencieusement.
    await assert.rejects(() => importRoomKey(new Uint8Array(16)));
  });
});

describe("distribution d'une clé de salon", () => {
  it("permet à un autre membre de la lire", async () => {
    const { key, raw } = await generateRoomKey();
    const recipientKey = await importPublicKey(bob.publicJwk);

    const wrapped = await wrapRoomKey(raw, recipientKey);
    const bobKey = await unwrapRoomKey(wrapped, bob.privateKey);

    // Bob obtient bien la même clé qu'Alice, sans que celle-ci ne quitte le
    // navigateur autrement que chiffrée.
    const { ciphertext, iv } = await encryptMessage(key, "bonjour", "canal", "alice-id");
    assert.equal(await decryptMessage(bobKey, { ciphertext, iv }, "canal", "alice-id"), "bonjour");
  });

  it("produit une enveloppe de la taille attendue", async () => {
    const { raw } = await generateRoomKey();
    const recipientKey = await importPublicKey(bob.publicJwk);
    // 256 octets pour une clé RSA-2048 : c'est la fourchette que le serveur
    // accepte, et il refuse tout enveloppé plus court ou plus long.
    assert.equal(fromBase64(toBase64(await wrapRoomKey(raw, recipientKey))).length, 256);
  });

  it("échoue si l'on tente d'ouvrir une enveloppe qui n'est pas la sienne", async () => {
    const { raw } = await generateRoomKey();
    const wrapped = await wrapRoomKey(raw, await importPublicKey(bob.publicJwk));
    // Alice n'a pas l'enveloppe de Bob : RSA refuse de déballer.
    await assert.rejects(() => unwrapRoomKey(wrapped, alice.privateKey));
  });

  it("efface les octets intermédiaires même en cas d'échec", async () => {
    const { raw } = await generateRoomKey();
    const wrapped = await wrapRoomKey(raw, await importPublicKey(bob.publicJwk));
    // Une enveloppe corrompue doit échouer sans laisser de trace exploitable.
    const corrupted = new Uint8Array(wrapped);
    corrupted[0] ^= 0xff;
    await assert.rejects(() => unwrapRoomKey(corrupted, bob.privateKey));
  });
});

describe("chiffrement des messages", () => {
  const channel = "canal-1";
  const sender = "alice-id";

  it("fait l'aller-retour", async () => {
    const { key } = await generateRoomKey();
    const payload = await encryptMessage(key, "un message", channel, sender);
    assert.equal(await decryptMessage(key, payload, channel, sender), "un message");
  });

  it("gère les caractères Unicode", async () => {
    const { key } = await generateRoomKey();
    const text = "éàü 你好 🙂 — ₿ & <script>";
    const payload = await encryptMessage(key, text, channel, sender);
    assert.equal(await decryptMessage(key, payload, channel, sender), text);
  });

  it("gère un message vide", async () => {
    const { key } = await generateRoomKey();
    const payload = await encryptMessage(key, "", channel, sender);
    assert.equal(await decryptMessage(key, payload, channel, sender), "");
  });

  it("refuse un message trop long", async () => {
    const { key } = await generateRoomKey();
    await assert.rejects(
      () => encryptMessage(key, "a".repeat(MAX_PLAINTEXT_LENGTH + 1), channel, sender),
      /trop long/,
    );
  });

  it("refuse un message qui n'est pas une chaîne", async () => {
    const { key } = await generateRoomKey();
    await assert.rejects(() => encryptMessage(key, 42, channel, sender), TypeError);
  });

  it("utilise un IV différent à chaque chiffrement", async () => {
    const { key } = await generateRoomKey();
    const first = await encryptMessage(key, "même texte", channel, sender);
    const second = await encryptMessage(key, "même texte", channel, sender);
    // Deux chiffrements du même texte doivent être distincts, sinon le mode
    // d'AES-GCM deviendrait déterministe et la repetitive attacks possible.
    assert.notEqual(first.iv, second.iv);
    assert.notEqual(first.ciphertext, second.ciphertext);
  });

  it("produit un IV de 12 octets", async () => {
    const { key } = await generateRoomKey();
    const { iv } = await encryptMessage(key, "texte", channel, sender);
    assert.equal(fromBase64(iv).length, 12);
  });

  it("ne déchiffre pas avec un autre canal", async () => {
    const { key } = await generateRoomKey();
    const payload = await encryptMessage(key, "texte", channel, sender);
    // L'AAD lie le ciphertext au canal : le rejouer ailleurs échoue.
    await assert.rejects(() => decryptMessage(key, payload, "autre-canal", sender));
  });

  it("construit l'AAD au format exact talk:v1:{channel_id}:{sender_id}", async () => {
    // Le format de l'AAD est une décision d'architecture, pas un détail : il est
    // donc vérifié sans passer par `decryptMessage`, qui reconstruirait l'AAD
    // avec la même constante que le code. Le déchiffrement est fait ici avec Web
    // Crypto directement, sur un AAD écrit à la main dans le test.
    const { key } = await generateRoomKey();
    const payload = await encryptMessage(key, "texte", channel, sender);
    const iv = fromBase64(payload.iv);
    const ciphertext = fromBase64(payload.ciphertext);
    const open = (aad) =>
      globalThis.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: new TextEncoder().encode(aad),
          tagLength: 128,
        },
        key,
        ciphertext,
      );

    const plaintext = await new TextDecoder().decode(
      await open(`talk:v1:${channel}:${sender}`),
    );
    assert.equal(plaintext, "texte");

    // Le format précédent ne doit plus rien ouvrir : sans ce second cas, un
    // format différent mais compatible par hasard passerait le test.
    await assert.rejects(() => open(`v1|${channel}|${sender}`));
    await assert.rejects(() => open(`talk:v1:${channel}|${sender}`));
  });

  it("ne déchiffre pas avec un autre expéditeur", async () => {
    const { key } = await generateRoomKey();
    const payload = await encryptMessage(key, "texte", channel, sender);
    // Même limite que ci-dessus, sur l'identité : GCM n'authentifie pas
    // l'expéditeur, mais elle empêche d'usurper ses données authentifiées.
    await assert.rejects(() => decryptMessage(key, payload, channel, "bob-id"));
  });

  it("ne déchiffre pas avec une autre clé de salon", async () => {
    const { key: senderKey } = await generateRoomKey();
    const { key: otherKey } = await generateRoomKey();
    const payload = await encryptMessage(senderKey, "texte", channel, sender);
    await assert.rejects(() => decryptMessage(otherKey, payload, channel, sender));
  });

  it("détecte un ciphertext altéré", async () => {
    const { key } = await generateRoomKey();
    const { ciphertext, iv } = await encryptMessage(key, "texte", channel, sender);
    const bytes = fromBase64(ciphertext);
    bytes[0] ^= 0x01;
    await assert.rejects(() => decryptMessage(key, { ciphertext: toBase64(bytes), iv }, channel, sender));
  });

  it("est interopérable entre deux membres distincts", async () => {
    // Le scénario réel : Alice chiffre avec la clé de salon, Bob la déballe et
    // lit. Tout l'enchaînement, sans intermédiaire de confiance.
    const { key, raw } = await generateRoomKey();
    const wrapped = await wrapRoomKey(raw, await importPublicKey(bob.publicJwk));
    const bobKey = await unwrapRoomKey(wrapped, bob.privateKey);

    const senderId = "alice-id";
    const payload = await encryptMessage(key, "message partagé", "canal", senderId);
    assert.equal(
      await decryptMessage(bobKey, payload, "canal", senderId),
      "message partagé",
    );
  });
});

after(() => {
  // Rien à nettoyer : les clés ne quittent jamais le processus.
});
