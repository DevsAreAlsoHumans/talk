// Tests des fonctions pures du magasin de clés.
//
// Le magasin lui-même s'appuie sur IndexedDB, qui n'existe pas sous Node. Plutôt
// que d'écrire un IndexedDB de poche — qui testerait sa propre imitation plutôt
// que le code — ces tests se concentrent sur les conventions d'identifiants,
// qui portent la logique réelle : savoir qu'une clé est en attente, et la
// rattacher au bon identifiant.
//
// Le comportement IndexedDB réel est vérifié par l'application dans le
// navigateur, pas ici.

import assert from "node:assert/strict";
import { describe, it } from "node:test";

const {
  CHANNEL_PREFIX,
  PENDING_PREFIX,
  channelRoomId,
  isPendingRoomId,
  pendingRoomId,
} = await import("./keystore.js");

describe("conventions d'identifiants de clé de salon", () => {
  it("distingue une clé en attente d'une clé rattachée", () => {
    const pending = pendingRoomId("ref-1");
    const attached = channelRoomId("65f000000000000000000001");

    assert.ok(pending.startsWith(PENDING_PREFIX));
    assert.ok(attached.startsWith(CHANNEL_PREFIX));
    assert.equal(isPendingRoomId(pending), true);
    assert.equal(isPendingRoomId(attached), false);
  });

  it("conserve la référence locale telle quelle", () => {
    // La référence est celle générée par le client avant tout appel réseau :
    // elle doit survivre au renommage pour permmettre la reprise.
    assert.equal(pendingRoomId("abc-123"), `${PENDING_PREFIX}abc-123`);
    assert.equal(channelRoomId("507f1"), `${CHANNEL_PREFIX}507f1`);
  });

  it("ne confond pas un préfixe inconnu avec un état d'attente", () => {
    assert.equal(isPendingRoomId(""), false);
    assert.equal(isPendingRoomId("channel:x"), false);
    assert.equal(isPendingRoomId("pending"), false);
    assert.equal(isPendingRoomId(null), false);
    assert.equal(isPendingRoomId(undefined), false);
    assert.equal(isPendingRoomId(42), false);
    assert.equal(isPendingRoomId({}), false);
  });

  it("produit des identifiants distincts pour des références distinctes", () => {
    assert.notEqual(pendingRoomId("a"), pendingRoomId("b"));
  });
});
