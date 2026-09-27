// Test de bout en bout du protocole, exécuté par `node --test` contre le vrai
// serveur (`docker compose --profile e2e run --rm e2e`).
//
// C'est le seul test qui emploie la *vraie* implémentation cliente — le même
// `crypto.js` que le navigateur — pour parler au vrai serveur. Les tests Python
// valident des formes synthétiques ; ceux du navigateur ne sont pas automatisés.
// Ce fichier comble l'écart et attrape les désaccords d'interface : un nom de
// champ, une forme de réponse, un code d'erreur.
//
// Deux parties ne sont pas couvertes ici, volontairement :
//
// * l'envoi par WebSocket, que le `WebSocket` de Node ne peut pas utiliser — il
//   n'accepte pas d'en-tête `Origin`, que le serveur exige. Un navigateur
//   l'envoie toujours. L'envoi reste couvert par `tests/test_realtime.py`, côté
//   serveur, avec une trame de la forme exacte que le client produit ;
// * le magasin IndexedDB et le rendu, qui exigent un navigateur.
//
// Aucun paquet npm n'est requis : uniquement `node --test` et Web Crypto.

import assert from "node:assert/strict";
import { before, describe, it } from "node:test";

import {
  decryptMessage,
  encryptMessage,
  fromBase64,
  generateIdentity,
  generateRoomKey,
  importPublicKey,
  thumbprint,
  toBase64,
  unwrapRoomKey,
  wipe,
  wrapRoomKey,
} from "../frontend/js/crypto.js";

const BASE_URL = process.env.TALK_E2E_URL || "http://localhost:8000";
const PASSWORD = "mot-de-passe-solide-42";

/**
 * Un client HTTP minimal, avec un cookie jar.
 *
 * Le serveur authentifie par cookie et exige un jeton CSRF sur les mutations,
 * exactement comme un navigateur. Ce client reproduit ce comportement : c'est la
 * raison pour laquelle ce test peut échouer sur un détail que la seule lecture
 * du code ne révélerait pas.
 */
class Browser {
  constructor() {
    this.cookies = new Map();
  }

  cookieHeader() {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  }

  capture(response) {
    for (const raw of response.headers.getSetCookie?.() || []) {
      const [pair] = raw.split(";");
      const separator = pair.indexOf("=");
      this.cookies.set(pair.slice(0, separator).trim(), pair.slice(separator + 1).trim());
    }
  }

  async request(method, path, body) {
    const headers = {};
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (method !== "GET") {
      // Le serveur valide l'en-tête CSRF contre la *session*, identifiée par le
      // cookie `talk_session`. Les deux doivent donc être présents, et dans le
      // bon ordre : l'en-tête `Cookie` est calculé après la récupération.
      const warmup = await fetch(`${BASE_URL}/auth/csrf`, {
        headers: { Cookie: this.cookieHeader() },
      });
      this.capture(warmup);
      headers.Cookie = this.cookieHeader();
      headers["X-CSRF-Token"] = this.cookies.get("talk_csrf") || "";
    } else {
      const cookie = this.cookieHeader();
      if (cookie) {
        headers.Cookie = cookie;
      }
    }
    const response = await fetch(`${BASE_URL}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    this.capture(response);
    return response;
  }

  async getJson(path) {
    const response = await this.request("GET", path);
    return { status: response.status, body: await response.json() };
  }

  async postJson(path, body, expected = 200) {
    const response = await this.request("POST", path, body);
    const payload = await response.json();
    assert.equal(
      response.status,
      expected,
      `${path} : statut ${response.status} au lieu de ${expected} — ${JSON.stringify(payload)}`,
    );
    return payload;
  }

  async putJson(path, body, expected = 200) {
    const response = await this.request("PUT", path, body);
    const payload = await response.json();
    assert.equal(
      response.status,
      expected,
      `${path} : statut ${response.status} au lieu de ${expected} — ${JSON.stringify(payload)}`,
    );
    return payload;
  }

  async register(username) {
    await this.postJson("/auth/register", { username, password: PASSWORD }, 201);
    const me = await this.getJson("/auth/me");
    assert.equal(me.status, 200);
    this.user = me.body;
    return me.body;
  }

  /** Génère une identité, la publie, et vérifie l'empreinte calculée par le serveur. */
  async publishIdentity() {
    const generated = await generateIdentity();
    const fingerprint = await thumbprint(generated.publicJwk);
    const stored = await this.putJson("/keys/me", { public_key_jwk: generated.publicJwk });
    // Le serveur doit calculer exactement la même empreinte : c'est ce qui rend
    // possible une comparaison hors bande entre deux participants.
    assert.equal(stored.fingerprint, fingerprint);
    this.identity = { ...generated, fingerprint };
    return this.identity;
  }
}

let alice;
let bob;
let channel;
let roomKey;

before(async () => {
  const response = await fetch(`${BASE_URL}/health`);
  assert.equal(response.status, 200, "Le serveur doit être démarré pour ce test.");
});

describe("identité publiée", () => {
  it("publie une clé et retrouve la même empreinte que le serveur", async () => {
    alice = new Browser();
    await alice.register(`e2e_alice_${Date.now()}`);
    const identity = await alice.publishIdentity();

    const stored = await alice.getJson("/keys/me");
    assert.equal(stored.body.public_key_jwk.n, identity.publicJwk.n);
    assert.equal(stored.body.key_version, 1);
  });

  it("refuse de remplacer la clé déjà publiée", async () => {
    // C'est la protection qui empêche un navigateur de créer une nouvelle paire
    // et de se retrouver incapable de lire ses canaux existants.
    const other = await generateIdentity();
    await alice.putJson("/keys/me", { public_key_jwk: other.publicJwk }, 409);
  });

  it("refuse une clé privée déguisée en clé publique", async () => {
    const { publicJwk } = await generateIdentity();
    const withPrivate = { ...publicJwk, d: "AQAB" };
    await alice.putJson("/keys/me", { public_key_jwk: withPrivate }, 422);
  });
});

describe("canal et adhésion", () => {
  it("crée un canal, y adhère, et expose la clé publique du membre", async () => {
    channel = await alice.postJson(
      "/channels",
      { name: "e2e", client_ref: globalThis.crypto.randomUUID() },
      201,
    );
    assert.equal(channel.members.length, 1);
    assert.equal(channel.members[0].id, alice.user.id);

    bob = new Browser();
    await bob.register(`e2e_bob_${Date.now()}`);
    await bob.publishIdentity();

    const updated = await alice.postJson(`/channels/${channel.id}/members`, {
      user_id: bob.user.id,
    });
    assert.equal(updated.members.length, 2);
    // La clé publique du membre est exposée : sans elle, le navigateur ne
    // pourrait pas emballer la clé de salon.
    const invited = updated.members.find((member) => member.id === bob.user.id);
    assert.ok(invited.public_key_jwk, "La clé publique du membre doit être exposée.");
    assert.equal(invited.public_key_fingerprint, bob.identity.fingerprint);
  });

  it("empêche un non-membre de lire le canal", async () => {
    const stranger = new Browser();
    await stranger.register(`e2e_stranger_${Date.now()}`);
    const response = await stranger.getJson(`/channels/${channel.id}`);
    assert.equal(response.status, 403);
  });
});

describe("distribution de la clé de salon", () => {
  it("emballe la clé pour l'invité avec RSA-OAEP", async () => {
    const generated = await generateRoomKey();
    roomKey = generated.key;
    try {
      const view = await bob.getJson(`/channels/${channel.id}`);
      const member = view.body.members.find((entry) => entry.id === bob.user.id);
      const wrapped = await wrapRoomKey(generated.raw, await importPublicKey(member.public_key_jwk));
      // 256 octets : la taille que le serveur impose pour RSA-2048.
      assert.equal(wrapped.byteLength, 256);
      await alice.postJson(
        `/channels/${channel.id}/keys`,
        { user_id: bob.user.id, wrapped_key: toBase64(wrapped) },
        201,
      );
    } finally {
      // La clé en clair ne doit pas survivre à son emballage.
      wipe(generated.raw);
    }
  });

  it("permet à l'invité de retrouver la clé de salon", async () => {
    const envelope = await bob.getJson(`/channels/${channel.id}/keys/me`);
    assert.equal(envelope.status, 200);
    assert.equal(envelope.body.key_version, 1);
    const key = await unwrapRoomKey(fromBase64(envelope.body.wrapped_key), bob.identity.privateKey);
    const payload = await encryptMessage(key, "essai", channel.id, bob.user.id);
    assert.equal(await decryptMessage(key, payload, channel.id, bob.user.id), "essai");
  });

  it("refuse le dépôt d'une enveloppe par un membre ordinaire", async () => {
    // Le dépôt étant « premier arrivé, premier servi » et jamais écrasé, un
    // membre qui pourrait déposer ici imposerait sa clé de salon au destinataire.
    // Le scénario est joué pour de vrai : le membre tente de déposer une
    // enveloppe pour un tiers, se voit refuser, et l'enveloppe légitime reste
    // celle que le créateur a déposée.
    const carol = new Browser();
    await carol.register(`e2e_carol_${Date.now()}`);
    await carol.publishIdentity();
    await alice.postJson(`/channels/${channel.id}/members`, { user_id: carol.user.id });

    const rogue = await generateRoomKey();
    try {
      const member = (await carol.getJson(`/channels/${channel.id}`)).body.members.find(
        (entry) => entry.id === bob.user.id,
      );
      const wrapped = await wrapRoomKey(rogue.raw, await importPublicKey(member.public_key_jwk));
      await carol.postJson(
        `/channels/${channel.id}/keys`,
        { user_id: bob.user.id, wrapped_key: toBase64(wrapped) },
        403,
      );
    } finally {
      wipe(rogue.raw);
    }

    // L'enveloppe du créateur est intacte, et l'invité en déballe toujours la
    // bonne clé : octet pour octet, elle est bien celle du créateur.
    const envelope = await bob.getJson(`/channels/${channel.id}/keys/me`);
    const key = await unwrapRoomKey(fromBase64(envelope.body.wrapped_key), bob.identity.privateKey);
    const exported = (await crypto.subtle.exportKey("raw", key)).buffer;
    const expected = (await crypto.subtle.exportKey("raw", roomKey)).buffer;
    assert.deepEqual(new Uint8Array(exported), new Uint8Array(expected));
  });

  it("refuse le dépôt d'une enveloppe par un non-membre", async () => {
    const stranger = new Browser();
    await stranger.register(`e2e_outside_${Date.now()}`);
    await stranger.publishIdentity();
    await stranger.postJson(
      `/channels/${channel.id}/keys`,
      { user_id: bob.user.id, wrapped_key: toBase64(new Uint8Array(256)) },
      403,
    );
  });
});

describe("chiffrement des messages", () => {
  const message = "bonjour depuis le test é2e — accents et émoji 🙂";

  it("chiffre puis déchiffre un message", async () => {
    const payload = await encryptMessage(roomKey, message, channel.id, alice.user.id);
    assert.equal(typeof payload.iv, "string");
    assert.equal(typeof payload.ciphertext, "string");
    // Le texte clair ne doit pas apparaître dans le ciphertext.
    assert.ok(!payload.ciphertext.includes("bonjour"));
    assert.equal(await decryptMessage(roomKey, payload, channel.id, alice.user.id), message);
  });

  it("produit un IV différent à chaque chiffrement", async () => {
    const first = await encryptMessage(roomKey, message, channel.id, alice.user.id);
    const second = await encryptMessage(roomKey, message, channel.id, alice.user.id);
    assert.notEqual(first.iv, second.iv);
    assert.notEqual(first.ciphertext, second.ciphertext);
  });

  it("refuse de déchiffrer depuis un autre canal", async () => {
    // L'AAD lie le ciphertext au canal : impossible de le relire ailleurs.
    const payload = await encryptMessage(roomKey, message, channel.id, alice.user.id);
    await assert.rejects(() =>
      decryptMessage(roomKey, payload, "000000000000000000000000", alice.user.id),
    );
  });

  it("refuse de déchiffrer un message d'un autre expéditeur", async () => {
    const payload = await encryptMessage(roomKey, message, channel.id, alice.user.id);
    await assert.rejects(() =>
      decryptMessage(roomKey, payload, channel.id, bob.user.id),
    );
  });

  it("refuse un texte trop long", async () => {
    await assert.rejects(() => encryptMessage(roomKey, "x".repeat(4001), channel.id, alice.user.id));
  });
});
