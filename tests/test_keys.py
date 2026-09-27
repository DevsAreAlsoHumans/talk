"""Publication et remplacement de la clé publique.

La règle centrale de l'étape 3 est asymétrique et vaut d'être testée
explicitement : le serveur doit accepter qu'on lui redonne la clé qu'il
connaît déjà, et refuser toute autre clé. Ce refus n'est pas de la prudenterie
apparente, il protège un invariant qu'aucune autre règle ne pourrait rétablir —
toute enveloppe déjà déposée doit rester déchiffrable par son destinataire.

Il tient aussi sous concurrence, ce qui suppose de remonter au routeur l'issue
de l'écriture atomique plutôt que de se fier à une lecture préalable. Et le
refus d'une clé privée ne doit pas se transformer en fuite : une 422 n'a jamais
le droit de rendre la valeur qu'elle vient de rejeter.
"""

from __future__ import annotations

import asyncio
import base64
import threading

import pytest
from fastapi.testclient import TestClient
from pymongo import AsyncMongoClient

from app.config import get_settings
from app.security import public_key_thumbprint
from app.store import MongoUserStore
from tests.conftest import (
    csrf_headers,
    public_jwk,
    register_user,
    sync_database,
    unique_username,
)

# Composantes de clé privée entièrement factices, et distinctes les unes des
# autres pour que chacune soit traçable dans une réponse. Aucune clé réelle
# n'est utilisée dans ce fichier : le serveur ne manipule que des formes.
PRIVATE_VALUES = {
    name: base64.urlsafe_b64encode(f"FAKE-PRIVATE-{name}-DO-NOT-USE".encode()).rstrip(b"=").decode()
    for name in ("d", "p", "q", "dp", "dq", "qi")
}
SYMMETRIC_SECRET = (
    base64.urlsafe_b64encode(b"FAKE-SYMMETRIC-SECRET-DO-NOT-USE").rstrip(b"=").decode()
)

# Nombre d'essais du test de concurrence réelle. La fenêtre TOCTOU se mesure en
# quelques centaines de microsecondes : un essai unique, sur un pool de connexions
# encore froid, ne l'atteindrait pas de façon fiable.
CONCURRENCY_TRIALS = 10


def test_publier_une_cle_publique(client: TestClient) -> None:
    register_user(client)
    jwk = public_jwk()
    response = client.put("/keys/me", json={"public_key_jwk": jwk}, headers=csrf_headers(client))

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["public_key_jwk"] == jwk
    assert body["key_version"] == 1
    # L'empreinte est celle du client, calculée localement : les deux doivent
    # coïncider sans qu'aucun échange supplémentaire soit nécessaire.
    assert body["fingerprint"] == _thumbprint(jwk)


def test_republier_la_meme_cle_est_idempotent(client: TestClient) -> None:
    register_user(client)
    jwk = public_jwk()

    first = client.put("/keys/me", json={"public_key_jwk": jwk}, headers=csrf_headers(client))
    second = client.put("/keys/me", json={"public_key_jwk": jwk}, headers=csrf_headers(client))

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json() == second.json()


def test_remplacer_une_cle_par_une_autre_est_refuse(client: TestClient) -> None:
    register_user(client)
    client.put("/keys/me", json={"public_key_jwk": public_jwk(0)}, headers=csrf_headers(client))

    response = client.put(
        "/keys/me", json={"public_key_jwk": public_jwk(5)}, headers=csrf_headers(client)
    )

    assert response.status_code == 409, response.text
    # L'originale doit être intacte : un refus ne doit rien laisser en suspens.
    stored = client.get("/keys/me")
    assert stored.status_code == 200
    assert stored.json()["public_key_jwk"]["n"] == public_jwk(0)["n"]


def test_une_cle_privee_est_refusee(client: TestClient) -> None:
    register_user(client)
    jwk = public_jwk()
    # Ajout d'une composante privée : le refus doit être explicite, pas un
    # simple « champ inconnu », pour que le client comprenne ce qu'il a fait.
    jwk["d"] = "Y2FwdHVyZS1kLWF2YW50"

    response = client.put("/keys/me", json={"public_key_jwk": jwk}, headers=csrf_headers(client))

    assert response.status_code == 422, response.text
    assert "privée" in response.text


# --------------------------------------------------------------------- B1
# Le refus d'une clé privée ne doit pas se transformer en fuite. Par défaut,
# FastAPI sérialise `exc.errors()` en entier, et Pydantic y place dans `input`
# la valeur rejetée : la réponse 422 rendait la clé privée au client, qui la
# recopiait ensuite dans le DOM via `api.js` puis `chat.js`.


def _assert_no_echo(response: object, secrets: dict[str, str]) -> None:
    """Vérifie qu'aucune des valeurs fournies ne se retrouve dans la réponse.

    Le contrôle porte sur le corps brut, et non sur le JSON analysé : c'est
    exactement ce que le navigateur reçoit, et donc ce que `expectJson` recopie
    dans son message d'erreur.
    """
    text = response.text  # type: ignore[attr-defined]
    for name, value in secrets.items():
        assert value not in text, f"La composante {name} a été réinjectée dans la réponse."

    detail = response.json()["detail"]  # type: ignore[attr-defined]
    assert detail, "Le refus doit porter au moins une explication."
    for error in detail:
        assert set(error) <= {"type", "loc", "msg"}, (
            f"Champ d'erreur inattendu, donc potentiellement une valeur d'entrée : "
            f"{sorted(set(error) - {'type', 'loc', 'msg'})}"
        )
        assert error["msg"], "Chaque erreur doit rester compréhensible."


def test_une_cle_privee_complete_n_est_pas_rejouee_dans_la_reponse(client: TestClient) -> None:
    register_user(client)
    jwk = public_jwk() | PRIVATE_VALUES

    response = client.put("/keys/me", json={"public_key_jwk": jwk}, headers=csrf_headers(client))

    assert response.status_code == 422, response.text
    # Le refus reste explicite : le client sait qu'il a transmis une clé privée.
    assert "privée" in response.text
    assert "d" in response.text and "qi" in response.text
    _assert_no_echo(response, PRIVATE_VALUES)


def test_un_membre_prive_isole_n_est_pas_rejoue_dans_la_reponse(client: TestClient) -> None:
    register_user(client)
    jwk = public_jwk() | {"d": PRIVATE_VALUES["d"]}

    response = client.put("/keys/me", json={"public_key_jwk": jwk}, headers=csrf_headers(client))

    assert response.status_code == 422, response.text
    assert "privée" in response.text
    _assert_no_echo(response, {"d": PRIVATE_VALUES["d"]})


def test_un_secret_symetrique_n_est_pas_rejoue_dans_la_reponse(client: TestClient) -> None:
    """Un JWK symétrique est un secret équivalent : il ne doit pas être renvoyé non plus.

    Le refus est motivé par `kty`, mais la valeur `k` porte le même genre de
    secret que `d` pour une clé RSA, et le même mécanisme de réflexion la
    réinjecterait.
    """
    register_user(client)
    jwk = {"kty": "oct", "k": SYMMETRIC_SECRET, "alg": "A256GCM"}

    response = client.put("/keys/me", json={"public_key_jwk": jwk}, headers=csrf_headers(client))

    assert response.status_code == 422, response.text
    assert "RSA" in response.text
    _assert_no_echo(response, {"k": SYMMETRIC_SECRET})


def _marker(label: str, size: int = 0) -> str:
    """Valeur factice et reconnaissable, de la taille demandée en octets."""
    raw = f"FAKE-MARKER-{label}-DO-NOT-USE".encode()
    return (
        base64.urlsafe_b64encode(raw.ljust(size, b"!")[:size] if size else raw)
        .rstrip(b"=")
        .decode()
    )


@pytest.mark.parametrize(
    ("mutation", "expected_in_message"),
    [
        ({"kty": _marker("KTY")}, "RSA"),
        ({"alg": _marker("ALG")}, "RSA-OAEP-256"),
        ({"n": _marker("MODULUS", 8)}, "256"),
        ({"e": _marker("EXPONENT", 9)}, "cohérente"),
    ],
    ids=["kty", "alg", "module-court", "exposant-trop-long"],
)
def test_aucune_validation_ne_reflechit_sa_entree(
    client: TestClient, mutation: dict[str, str], expected_in_message: str
) -> None:
    """Invariant global : une 422 ne contient jamais la valeur fournie.

    Chaque cas porte une valeur distinctive, mutée dans un champ PUBLIC : c'est
    donc le refus d'un validateur ordinaire qui est exercé, pas celui du
    détecteur de clé privée, déjà couvert plus haut. Le refus doit rester
    informatif, mais aucune valeur d'entrée ne doit sortir du serveur.
    """
    register_user(client)
    submitted = public_jwk() | mutation

    response = client.put(
        "/keys/me", json={"public_key_jwk": submitted}, headers=csrf_headers(client)
    )

    assert response.status_code == 422, response.text
    assert expected_in_message in response.text
    # La valeur mutée, mais aussi le module public de la clé : rien de ce que le
    # client a envoyé ne doit être réinjecté.
    _assert_no_echo(
        response,
        {"valeur-mutee": submitted[next(iter(mutation))], "n": public_jwk()["n"]},
    )


def test_une_cle_privee_ne_parvient_jamais_a_la_base(client: TestClient) -> None:
    """Invariant de régression : la clé privée ne doit jamais être stockée.

    Un test d'invariant, pas une fonctionnalité : le jour où une dépendance
    cryptographique apparaît côté serveur, ce test doit rester vert.
    """
    username = register_user(client)
    client.put(
        "/keys/me",
        json={"public_key_jwk": public_jwk()},
        headers=csrf_headers(client),
    )

    mongo = sync_database()
    try:
        users = list(mongo[get_settings().mongo_db_name].users.find({"username": username}))
    finally:
        mongo.close()

    assert users, "L'utilisateur inscrit a disparu."
    serialised = str(users[0])
    for component in ('"d"', '"p"', '"q"', '"dp"', '"dq"', '"qi"'):
        assert component not in serialised


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ({"kty": "EC"}, "RSA"),
        ({"alg": "RSA-OAEP"}, "RSA-OAEP-256"),
    ],
)
def test_les_parametres_incompatibles_sont_refuses(
    client: TestClient, mutation: dict[str, str], expected: str
) -> None:
    register_user(client)
    jwk = public_jwk() | mutation

    response = client.put("/keys/me", json={"public_key_jwk": jwk}, headers=csrf_headers(client))

    assert response.status_code == 422, response.text
    assert expected in response.text


def test_un_module_rsa_trop_court_est_refuse(client: TestClient) -> None:
    register_user(client)
    jwk = public_jwk()
    jwk["n"] = base64.urlsafe_b64encode(b"trop-court").rstrip(b"=").decode("ascii")

    response = client.put("/keys/me", json={"public_key_jwk": jwk}, headers=csrf_headers(client))

    assert response.status_code == 422, response.text
    assert "256" in response.text


# --------------------------------------------------- Canonicalité de l'encodage
# `base64.urlsafe_b64decode` absorbe le remplissage, tolère l'alphabet standard
# et ignore les caractères hors alphabet. Or l'empreinte du RFC 7638 hache les
# CHAÎNES `e`, `kty` et `n`, pas les entiers qu'elles représentent : une clé
# unique présentée de deux façons obtenait deux empreintes, et la clé déjà
# enregistrée était refusée comme si elle en était une autre — sans recours,
# le MVP n'ayant aucune rotation de clé.
#
# Ces tests portent sur la propriété générale, pas sur une liste de caractères
# interdets : chaque variante est vérifiée décoder vers les octets de l'original,
# et le refus porte sur la comparison au réencodage canonique.

# Le vecteur du RFC 7638, section 3.1 : la même clé que
# `frontend/js/crypto.test.mjs`, afin que serveur et navigateur continuent de
# produire exactement la même empreinte.
RFC_7638_VECTOR = {
    "kty": "RSA",
    "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L"
        "6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5"
        "v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08"
        "qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8aw"
        "apJzKnqDKgw"
    ),
    "e": "AQAB",
    "alg": "RSA-OAEP-256",
}
RFC_7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

# 64537 est un exposant plausible ; il sérialise en `-_8`, dont la forme base64
# standard est `+/8=`. L'exposant réel d'un navigateur, 65537, sérialise en
# `AQAB` et ne peut structurellement contenir ni `+` ni `/` : le cas de
# l'alphabet standard ne se construit donc pas avec la valeur de production.
EXPONENT_CANONICAL = "-_8"
EXPONENT_STANDARD = "+/8="


def _decodes_to(value: str, reference: bytes) -> bool:
    """Vrai si `value` se décode vers `reference` malgré une écriture non canonique."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)) == reference


def test_une_cle_canonique_est_acceptee(client: TestClient) -> None:
    """A + E : un `n` et un `e` canoniques passent, et l'empreinte ne bouge pas.

    Le vecteur officiel du RFC 7638 est accepté tel quel et redonne son empreinte
    documentée. C'est la régression qui compte : la correction porte sur la
    validation, jamais sur le calcul de l'empreinte. Les clés réellement produites
    par `exportKey("jwk")` sont couvertes par le test E2E du protocole, qui
    publie une clé Web Crypto authentique.
    """
    register_user(client)
    # Une clé réelle, dont le module fait bien 256 octets et s'écrit canoniquement.
    vector_modulus = RFC_7638_VECTOR["n"]
    assert _decodes_to(
        vector_modulus, base64.urlsafe_b64decode(vector_modulus + "=" * (-len(vector_modulus) % 4))
    )
    assert len(base64.urlsafe_b64decode(vector_modulus + "=" * (-len(vector_modulus) % 4))) == 256

    response = client.put(
        "/keys/me", json={"public_key_jwk": RFC_7638_VECTOR}, headers=csrf_headers(client)
    )

    assert response.status_code == 200, response.text
    assert response.json()["fingerprint"] == RFC_7638_THUMBPRINT


def test_un_exposant_canonique_est_accepte(client: TestClient) -> None:
    """A : l'exposant de production, `AQAB`, reste accepté."""
    register_user(client)
    jwk = public_jwk()
    assert jwk["e"] == "AQAB"

    response = client.put("/keys/me", json={"public_key_jwk": jwk}, headers=csrf_headers(client))

    assert response.status_code == 200, response.text


@pytest.mark.parametrize("field", ["n", "e"], ids=["module", "exposant"])
def test_un_remplissage_est_refuse(client: TestClient, field: str) -> None:
    """B : le `=` de remplissage est refusé, pour `n` comme pour `e`."""
    register_user(client)
    jwk = public_jwk()
    jwk[field] = jwk[field] + "="

    response = client.put("/keys/me", json={"public_key_jwk": jwk}, headers=csrf_headers(client))

    assert response.status_code == 422, response.text
    assert "canonique" in response.text
    # Le refus ne doit pas non plus réinjecter la valeur : c'est une clé publique,
    # mais le handler de validation ne distingue pas et ne doit rien laisser passer.
    _assert_no_echo(response, {field: jwk[field], "n": public_jwk()["n"]})


def test_un_module_en_alphabet_standard_est_refuse(client: TestClient) -> None:
    """C : `+` et `/` à la place de `-` et `_` sont refusés sur le module.

    Le module de `public_jwk()` contient réellement ces caractères : l'alphabet
    standard est donc une réécriture possible, et non une valeur fabriquée.
    """
    register_user(client)
    jwk = public_jwk()
    standard = jwk["n"].replace("-", "+").replace("_", "/")
    assert standard != jwk["n"], "le module doit contenir '-' ou '_' pour ce test"
    assert _decodes_to(standard, base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4)))
    jwk["n"] = standard

    response = client.put("/keys/me", json={"public_key_jwk": jwk}, headers=csrf_headers(client))

    assert response.status_code == 422, response.text
    assert "canonique" in response.text
    _assert_no_echo(response, {"n": standard})


def test_un_exposant_en_alphabet_standard_est_refuse(client: TestClient) -> None:
    """C : même refus sur `e`, avec un exposant où `+` et `/` sont possibles.

    `AQAB`, l'exposant qu'un navigateur produit, ne peut pas contenir `+` ni `/` :
    sa valeur est figée. La propriété est donc testée sur un autre exposant que le
    serveur accepte (1 à 8 octets), et dont l'écriture base64url canonique
    `-_8` contient bien les deux caractères.
    """
    register_user(client)
    jwk = public_jwk()
    exponent = base64.urlsafe_b64decode(EXPONENT_CANONICAL + "=")
    jwk["e"] = EXPONENT_STANDARD
    assert _decodes_to(EXPONENT_STANDARD, exponent)
    assert EXPONENT_CANONICAL != EXPONENT_STANDARD

    response = client.put("/keys/me", json={"public_key_jwk": jwk}, headers=csrf_headers(client))

    assert response.status_code == 422, response.text
    assert "canonique" in response.text
    # Et l'écriture canonique du même exposant est acceptée, ce qui prouve que le
    # refus tient à l'alphabet et non à la valeur.
    jwk["e"] = EXPONENT_CANONICAL
    accepted = client.put("/keys/me", json={"public_key_jwk": jwk}, headers=csrf_headers(client))
    assert accepted.status_code == 200, accepted.text


@pytest.mark.parametrize(
    "variant",
    ["remplissage", "alphabet-standard", "espaces", "caracteres-interdits", "sauts-de-ligne"],
)
def test_seule_la_forme_canonique_d_un_module_est_acceptee(
    client: TestClient, variant: str
) -> None:
    """D : toute autre écriture des mêmes octets est refusée.

    Chaque variante décode vers exactement les octets du module de référence —
    l'assertion le vérifie avant la requête — et n'est rejetée que parce qu'elle
    diffère du réencodage canonique.
    """
    register_user(client)
    canonical = public_jwk()["n"]
    reference = base64.urlsafe_b64decode(canonical + "=" * (-len(canonical) % 4))
    rewritten = {
        "remplissage": canonical + "=",
        "alphabet-standard": canonical.replace("-", "+").replace("_", "/"),
        # Quatre caractères ignorés : c'est le seul multiple qui préserve
        # l'alignement sur quatre, donc les octets décodés.
        "espaces": canonical[:20] + "    " + canonical[20:],
        "caracteres-interdits": canonical[:20] + "%%%%" + canonical[20:],
        "sauts-de-ligne": canonical[:20] + "\n\n\n\n" + canonical[20:],
    }[variant]
    assert _decodes_to(rewritten, reference), "la variante doit décoder vers les mêmes octets"
    assert rewritten != canonical

    response = client.put(
        "/keys/me",
        json={"public_key_jwk": public_jwk() | {"n": rewritten}},
        headers=csrf_headers(client),
    )

    assert response.status_code == 422, response.text
    assert "canonique" in response.text


@pytest.mark.parametrize(
    ("field", "value"),
    [("n", ""), ("e", ""), ("n", "A"), ("n", "!!!!"), ("e", "AQ AB")],
    ids=["module-vide", "exposant-vide", "longueur-impossible", "caracteres-interdits", "espace"],
)
def test_une_ecriture_base64url_illisible_est_refusee(
    client: TestClient, field: str, value: str
) -> None:
    """Longueur impossible, caractères interdits, chaîne vide : refus immédiat.

    Ces formes ne passent pas par la comparaison au réencodage — le décodeur
    échoue, ou la valeur est vide — mais le résultat doit être le même : une 422
    de validation, jamais une 500.
    """
    register_user(client)

    response = client.put(
        "/keys/me",
        json={"public_key_jwk": public_jwk() | {field: value}},
        headers=csrf_headers(client),
    )

    assert response.status_code == 422, response.text
    # Une valeur vide n'est pas une chaîne traçable : la recherche d'écho
    # porterait sur le module canonique, qui est la seule donnée réellement
    # transmise dans ce cas.
    _assert_no_echo(response, {"n": public_jwk()["n"]})


def test_la_cle_refusee_n_est_pas_changee_en_base(client: TestClient) -> None:
    """Une forme non canonique ne doit ni être enregistrée, ni faire échouer la suite.

    Le compte doit rester publiable ensuite : le refus porte sur la requête, pas
    sur l'état du compte.
    """
    register_user(client)
    rejected = public_jwk()
    rejected["n"] = rejected["n"].replace("-", "+").replace("_", "/")
    first = client.put("/keys/me", json={"public_key_jwk": rejected}, headers=csrf_headers(client))
    assert first.status_code == 422, first.text

    accepted = client.put(
        "/keys/me", json={"public_key_jwk": public_jwk()}, headers=csrf_headers(client)
    )

    assert accepted.status_code == 200, accepted.text
    assert client.get("/keys/me").json()["public_key_jwk"] == public_jwk()


def test_lire_une_cle_publique_avant_publication_renvoie_404(client: TestClient) -> None:
    register_user(client, unique_username())
    response = client.get("/keys/me")
    assert response.status_code == 404, response.text


def test_publier_une_cle_exige_le_csrf(client: TestClient) -> None:
    register_user(client)
    response = client.put("/keys/me", json={"public_key_jwk": public_jwk()})
    assert response.status_code == 403, response.text


def test_les_routes_de_cles_exigent_une_session(client: TestClient) -> None:
    client.cookies.clear()
    assert client.get("/keys/me").status_code == 401
    # Une mutation sans session ne peut pas non plus valider son jeton CSRF,
    # qui est lié à la session : c'est le CSRF qui répond en premier.
    assert client.put("/keys/me", json={"public_key_jwk": public_jwk()}).status_code == 403


def test_deux_utilisateurs_ont_des_empreintes_differentes(client: TestClient) -> None:
    first_name = register_user(client, unique_username())
    first_key = _publish_and_read(client, 0)

    # Purge du cookie jar : le second utilisateur est une session distincte,
    # et la purge automatique des tests n'a lieu qu'entre deux tests.
    client.cookies.clear()
    second_name = register_user(client, unique_username())
    second_key = _publish_and_read(client, 1)

    assert first_name != second_name
    assert first_key["fingerprint"] != second_key["fingerprint"]


def _publish_and_read(client: TestClient, seed: int) -> dict[str, object]:
    client.put(
        "/keys/me",
        json={"public_key_jwk": public_jwk(seed)},
        headers=csrf_headers(client),
    )
    response = client.get("/keys/me")
    assert response.status_code == 200, response.text
    return response.json()


def _thumbprint(jwk: dict[str, str]) -> str:
    from app.chat_schemas import PublicJwk

    return public_key_thumbprint(PublicJwk.model_validate(jwk).canonical_json())


# --------------------------------------------------------------------- B2
# Le refus de remplacement ne tient que si l'issue de l'écriture atomique est
# remontée au routeur. Lire avant d'écrire ne suffit pas : deux publications
# simultanées peuvent toutes deux constater qu'aucune clé n'existe encore.


def test_save_public_key_signale_qui_a_ecrit(client: TestClient) -> None:
    """Contrat du magasin : `save_public_key` dit si c'est lui qui a écrit.

    C'est `matched_count` qui porte cette information, et le routeur en a besoin
    pour ne pas confirmer un enregistrement qui n'a pas eu lieu. Un client
    MongoDB et une boucle asyncio dédiés sont utilisés : le client global de
    `app.db` est lié à la boucle du `TestClient` et ne peut pas être réutilisé
    ici.
    """
    username = register_user(client)

    async def scenario() -> tuple[bool, bool, bool]:
        mongo = AsyncMongoClient(get_settings().mongo_url, tz_aware=True)
        try:
            store = MongoUserStore(mongo[get_settings().mongo_db_name])
            document = await mongo[get_settings().mongo_db_name].users.find_one(
                {"username": username}
            )
            assert document is not None
            user_id = document["_id"]

            first = await store.save_public_key(user_id, public_jwk(0), "empreinte-0")
            # Une seconde clé sur un compte qui en possède déjà une : le filtre
            # `$exists: false` ne doit rien écraser, et le magasin le dit.
            second = await store.save_public_key(user_id, public_jwk(1), "empreinte-1")
            # La même clé, de nouveau : idempotence du magasin, pas re-écriture.
            third = await store.save_public_key(user_id, public_jwk(0), "empreinte-0")
            return first, second, third
        finally:
            await mongo.close()

    first, second, third = asyncio.run(scenario())

    assert first is True, "La première publication doit être signalée comme écrite."
    assert second is False, "Une clé existante ne doit pas être écrasée."
    assert third is False, "Réécrire la même clé ne doit pas être une écriture."

    # La clé restée en base est bien la première.
    stored = client.get("/keys/me").json()["public_key_jwk"]["n"]
    assert stored == public_jwk(0)["n"]


def test_une_publication_concurrente_perdante_obtient_un_conflit(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Une écriture refusée par MongoDB doit produire un 409, jamais un 200.

    La concurrence est injectée de façon déterministe : le perdant de la course
    est simulé en écrivant la clé adverse entre la lecture du routeur et son
    propre `save_public_key`. Le test est donc reproductible là où une vraie
    course ne l'est pas, et il exerce exactement la fenêtre qui avait été
    comblée en silence.
    """
    register_user(client)
    contender = public_jwk(3)
    original = MongoUserStore.get_public_key
    calls = 0

    async def racing_get_public_key(self: MongoUserStore, user_id: object) -> dict:
        nonlocal calls
        calls += 1
        document = await original(self, user_id)
        if calls == 1:
            # Simule la requête concurrente victorieuse : elle passe par le même
            # chemin que le routeur, donc par la même opération atomique.
            assert await self.save_public_key(user_id, contender, _thumbprint(contender)) is True
        return document

    monkeypatch.setattr(MongoUserStore, "get_public_key", racing_get_public_key)

    response = client.put(
        "/keys/me", json={"public_key_jwk": public_jwk(4)}, headers=csrf_headers(client)
    )

    assert response.status_code == 409, response.text
    assert calls == 2, "La relure après écriture concurrente doit avoir eu lieu."
    # La clé réellement enregistrée est celle du concurrent, et le perdant n'a
    # reçu ni son statut ni son empreinte.
    stored = client.get("/keys/me").json()["public_key_jwk"]["n"]
    assert stored == contender["n"]


def test_deux_publications_simultanees_ne_peuvent_pas_toutes_deux_reussir(
    client: TestClient,
) -> None:
    """Deux `PUT /keys/me` réellement concurrents : un 200, un 409, une seule clé.

    L'invariant est vrai que la course ait lieu ou non : si le second `PUT` lit
    la clé après l'écriture du premier, il est déjà refusé par le chemin
    séquentiel. Ce test ne peut donc pas échouer par intermittence.

    Il reste probabilistic, et c'est pourquoi il répète l'essai. La fenêtre
    entre la lecture et l'écriture se mesure en quelques centaines de
    microsecondes, et les tous premiers essais ne l'atteignent pas : le pool de
    connexions MongoDB est encore froid et la première requête attend son
    établissement. Un essai unique passerait donc presque toujours, y compris
    sur le code bogué ; c'est la répétition, dans un même processus, qui rend la
    course observable. Le test déterministe ci-dessus reste la garantie, celui-ci
    couvre le cas réel.
    """
    for trial in range(CONCURRENCY_TRIALS):
        client.cookies.clear()
        register_user(client)
        headers = csrf_headers(client)
        start = threading.Barrier(2)
        responses: dict[int, object] = {}

        def publish(
            slot: int,
            seed: int,
            start: threading.Barrier = start,
            headers: dict[str, str] = headers,
            responses: dict[int, object] = responses,
        ) -> None:
            # `TestClient` sérialise les requêtes sur un unique portal asyncio :
            # deux fils distincts suffisent donc à les rendre réellement
            # concurrentes côté serveur.
            start.wait()
            responses[slot] = client.put(
                "/keys/me", json={"public_key_jwk": public_jwk(seed)}, headers=headers
            )

        threads = [
            threading.Thread(target=publish, args=(slot, seed)) for slot, seed in ((0, 5), (1, 6))
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert len(responses) == 2, f"Essai {trial} : les deux requêtes ont abouti."

        statuses = sorted(response.status_code for response in responses.values())
        assert statuses == [200, 409], (
            f"Essai {trial} : une seule publication peut aboutir, {statuses}"
        )

        # La clé enregistrée est celle du client qui a reçu son 200 : aucun 200
        # ne peut annoncer une clé qui n'est pas celle en base.
        winner = next(r for r in responses.values() if r.status_code == 200)
        stored = client.get("/keys/me").json()
        assert stored["public_key_jwk"]["n"] == winner.json()["public_key_jwk"]["n"]
        assert stored["fingerprint"] == winner.json()["fingerprint"]
