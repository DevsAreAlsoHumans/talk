"""Socle des serveurs : création, lecture, isolation, ancienneté d'adhésion.

Les tests passent par l'API HTTP, sauf quand il faut constater ce qui est
réellement écrit dans Mongo. Le type BSON de `joined_at` ne s'observe pas depuis
une réponse JSON, et c'est pourtant lui qui décide de l'ordre de succession.

Deux points de ce fichier méritent d'être situés, parce qu'ils expliquent pourquoi
certains tests ne passent pas par l'API.

L'adhésion dispose d'une route, `POST /servers/{id}/members`. Le magasin reste
malgré tout appelé directement dans deux tests : l'un pour l'idempotence du filtre
sur `members.user_id`, que la route ne laisse pas observer aussi directement ;
l'autre pour vérifier qu'un membre ainsi ajouté s'articule bien avec le chemin de
lecture. Ce ne sont donc pas des tests d'une fonction sans issue.

Une seule fonction de magasin n'a volontairement aucune route : la lecture du
plus ancien membre, qui ne sert qu'au transfert de propriété à venir. Elle est
testée directement, pour être vérifiée *avant* que cette fonctionnalité existe.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import pytest
from bson import ObjectId
from fastapi.testclient import TestClient
from pymongo import AsyncMongoClient

from app.chat_store import MongoChatStore
from app.config import get_settings
from tests.conftest import (
    add_server_member,
    create_channel,
    create_server,
    csrf_headers,
    dummy_object_id,
    login_user,
    register_user,
    remove_server_member,
    server_document,
    sync_database,
    user_id_of,
    wrapped_key_b64,
)

AVANT = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)


async def avec_un_store[T](action: Callable[[MongoChatStore], Awaitable[T]]) -> T:
    """Exécute une opération de magasin dans une boucle qui lui est propre.

    `AsyncMongoClient` se lie à la boucle qui l'a créé (voir la note en tête de
    `app/db.py`) : le client de l'application appartient à la boucle du
    `TestClient`, et l'emprunter depuis `asyncio.run` échouerait. Un client
    éphémère est donc créé ici, et refermé dans tous les cas.
    """
    client = AsyncMongoClient(get_settings().mongo_url, tz_aware=True)
    try:
        return await action(MongoChatStore(client[get_settings().mongo_db_name]))
    finally:
        await client.close()


def store_de_test[T](action: Callable[[MongoChatStore], Awaitable[T]]) -> T:
    return asyncio.run(avec_un_store(action))


def inserer_un_serveur_brut(members: list[dict[str, object]], created_by: ObjectId) -> str:
    """Insère un serveur sans passer par l'API et renvoie son identifiant.

    Permet de fabriquer un document dont l'ordre des membres est indépendant de
    l'ancienneté, ce que l'API ne permet pas encore de produire.
    """
    mongo = sync_database()
    try:
        database = mongo[get_settings().mongo_db_name]
        return str(
            database.servers.insert_one(
                {
                    "name": "equipe",
                    "created_by": created_by,
                    "created_at": AVANT,
                    "members": members,
                }
            ).inserted_id
        )
    finally:
        mongo.close()


# --------------------------------------------------------------------------
# Création
# --------------------------------------------------------------------------


def test_un_utilisateur_peut_creer_un_serveur(client: TestClient) -> None:
    register_user(client, "alice")
    response = client.post("/servers", json={"name": "general"}, headers=csrf_headers(client))
    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["name"] == "general"
    assert payload["created_by"] == user_id_of(client, "alice")
    assert ObjectId.is_valid(payload["id"])


def test_creer_un_serveur_exige_une_session(client: TestClient) -> None:
    """Sans session, la création est refusée — même avec un jeton CSRF valide.

    `/auth/csrf` crée sa session si besoin, donc le jeton est ici authentique :
    le refus ne vient pas du CSRF mais bien de l'absence de session.
    """
    response = client.post("/servers", json={"name": "general"}, headers=csrf_headers(client))
    assert response.status_code == 401, response.text


def test_creer_un_serveur_exige_le_csrf(client: TestClient) -> None:
    register_user(client, "alice")
    response = client.post("/servers", json={"name": "general"})
    assert response.status_code == 403, response.text


def test_le_createur_est_automatiquement_membre(client: TestClient) -> None:
    register_user(client, "alice")
    payload = create_server(client)
    assert [membre["user_id"] for membre in payload["members"]] == [user_id_of(client, "alice")]
    assert payload["members"][0]["username"] == "alice"
    assert payload["members"][0]["joined_at"]


def test_le_corps_ne_peut_pas_fournir_created_by(client: TestClient) -> None:
    """Un `created_by` falsifié est refusé, et rien n'est créé.

    `created_by` décide de la propriété et, avec elle, du droit de transférer le
    rôle plus tard. L'accepter depuis le corps rendrait l'identité du serveur
    falsifiable. Le refus est vérifié aussi sur la base : une route qui
    répondrait 422 en ayant quand même écrit le document serait bien plus grave.
    """
    register_user(client, "alice")
    alice_id = user_id_of(client, "alice")
    response = client.post(
        "/servers",
        json={"name": "general", "created_by": alice_id},
        headers=csrf_headers(client),
    )
    assert response.status_code == 422, response.text
    assert client.get("/servers").json() == []


def test_le_corps_ne_peut_pas_fournir_joined_at(client: TestClient) -> None:
    """Un `joined_at` fourni par le client est refusé.

    L'ancienneté d'adhésion décide du membre le plus ancien, donc du successeur
    du créateur. Un client qui pourrait la fixer pourrait se déclarer plus ancien
    qu'un membre réel, ou effacer son propre temps de présence.
    """
    register_user(client, "alice")
    response = client.post(
        "/servers",
        json={"name": "general", "joined_at": "2000-01-01T00:00:00+00:00"},
        headers=csrf_headers(client),
    )
    assert response.status_code == 422, response.text
    assert client.get("/servers").json() == []


def test_created_by_provient_de_la_session(client: TestClient) -> None:
    """Le créateur enregistré est l'utilisateur connecté, et lui seul.

    Deux utilisateurs sont inscrits dans la même base ; le serveur créé par le
    second ne doit porter que son identité. Sans cela, une fuite d'état entre
    requests — une session réutilisée, une variable capturée — passerait
    inaperçue.
    """
    register_user(client, "alice")
    alice_id = user_id_of(client, "alice")
    client.cookies.clear()
    register_user(client, "bob")
    bob_id = user_id_of(client, "bob")

    cree_bob = create_server(client, "travail")
    document = server_document(str(cree_bob["id"]))
    assert document["created_by"] == ObjectId(bob_id)
    assert document["created_by"] != ObjectId(alice_id)
    assert cree_bob["created_by"] == bob_id


@pytest.mark.parametrize(
    "name",
    ["", "   ", "-commence-par-un-tiret", "trop" * 30, "<script>alert(1)</script>", "a" * 65],
)
def test_les_noms_de_serveur_invalides_sont_refuses(client: TestClient, name: str) -> None:
    """Un serveur applique les mêmes règles de nom qu'un canal.

    Les cas sont volontairement les mêmes que ceux du canal : la règle est
    partagée, donc les refus aussi.
    """
    register_user(client, "alice")
    response = client.post("/servers", json={"name": name}, headers=csrf_headers(client))
    assert response.status_code == 422, response.text


def test_le_nom_dun_serveur_est_normalise(client: TestClient) -> None:
    register_user(client, "alice")
    assert create_server(client, name="  general  ")["name"] == "general"


def test_un_serveur_n_exige_pas_de_client_ref(client: TestClient) -> None:
    """Un serveur se crée avec un nom seul, sans `client_ref`.

    Contrairement à un canal : un serveur ne détient aucune clé, il n'a donc rien
    à référencer localement. Ce test verrouille l'absence du champ, pour qu'un
    ajout de `client_ref` au schéma soit un choix explicite.
    """
    register_user(client, "alice")
    response = client.post(
        "/servers",
        json={"name": "general", "client_ref": str(uuid.uuid4())},
        headers=csrf_headers(client),
    )
    assert response.status_code == 422, response.text


# --------------------------------------------------------------------------
# Lecture
# --------------------------------------------------------------------------


def test_un_membre_peut_lire_son_serveur(client: TestClient) -> None:
    register_user(client, "alice")
    cree = create_server(client)
    response = client.get(f"/servers/{cree['id']}")
    assert response.status_code == 200, response.text
    assert response.json()["id"] == cree["id"]


def test_un_membre_voit_son_serveur_dans_la_liste(client: TestClient) -> None:
    register_user(client, "alice")
    cree = create_server(client, "general")
    response = client.get("/servers")
    assert response.status_code == 200, response.text
    assert [serveur["id"] for serveur in response.json()] == [cree["id"]]


def test_lire_la_liste_sans_session_renvoie_401(client: TestClient) -> None:
    response = client.get("/servers")
    assert response.status_code == 401, response.text


def test_un_utilisateur_exterieur_ne_voit_pas_le_serveur(client: TestClient) -> None:
    register_user(client, "alice")
    cree = create_server(client)
    client.cookies.clear()
    register_user(client, "bob")
    response = client.get("/servers")
    assert response.status_code == 200, response.text
    assert cree["id"] not in [serveur["id"] for serveur in response.json()]


def test_un_non_membre_recoit_403(client: TestClient) -> None:
    register_user(client, "alice")
    cree = create_server(client)
    client.cookies.clear()
    register_user(client, "bob")
    response = client.get(f"/servers/{cree['id']}")
    assert response.status_code == 403, response.text


def test_un_serveur_inexistant_renvoie_404(client: TestClient) -> None:
    register_user(client, "alice")
    response = client.get(f"/servers/{dummy_object_id()}")
    assert response.status_code == 404, response.text


def test_un_objectid_invalide_renvoie_404(client: TestClient) -> None:
    """Un identifiant mal formé suit la convention du projet : 404, pas 422.

    Une 422 dirait au client que le format est en cause, donc qu'il peut corriger
    sa requête ; or il n'y a rien à corriger, l'identifiant ne désigne aucun
    serveur. Le projet répond déjà 404 pour un `ObjectId` mal formé sur un canal,
    et le serveur suit cette règle.
    """
    register_user(client, "alice")
    for invalide in ("pas-un-objectid", str(uuid.uuid4()), "0" * 25):
        response = client.get(f"/servers/{invalide}")
        assert response.status_code == 404, f"{invalide} : {response.text}"


# --------------------------------------------------------------------------
# Isolation
# --------------------------------------------------------------------------


def test_les_serveurs_sont_isoles_par_utilisateur(client: TestClient) -> None:
    """Chaque utilisateur ne voit que ses serveurs, et ne lit que les siens.

    Alice a `perso`, Bob a `travail`. Ni l'un ni l'autre ne doit voir le serveur
    de l'autre dans la liste, et la lecture directe doit être refusée pour un
    tiers mais réussie pour le propriétaire.
    """
    register_user(client, "alice")
    perso = create_server(client, "perso")
    client.cookies.clear()
    register_user(client, "bob")
    travail = create_server(client, "travail")

    liste_bob = client.get("/servers")
    assert liste_bob.status_code == 200, liste_bob.text
    assert [s["id"] for s in liste_bob.json()] == [travail["id"]]
    assert client.get(f"/servers/{perso['id']}").status_code == 403

    client.cookies.clear()
    login_user(client, "alice")
    liste_alice = client.get("/servers")
    assert [s["id"] for s in liste_alice.json()] == [perso["id"]]
    detail = client.get(f"/servers/{perso['id']}")
    assert detail.status_code == 200
    assert [membre["username"] for membre in detail.json()["members"]] == ["alice"]


# --------------------------------------------------------------------------
# Ancienneté d'adhésion
# --------------------------------------------------------------------------


def test_joined_at_est_stocke_comme_datetime(client: TestClient) -> None:
    """`joined_at` est un datetime BSON, pas une chaîne.

    Un horodatage textuel ne se compare pas de façon fiable entre documents, et
    l'ordre de succession repose sur cette comparaison. Le test observe le type
    stocké, pas la chaîne rendue par l'API : c'est le type en base qui détermine
    le comportement.
    """
    register_user(client, "alice")
    cree = create_server(client)
    document = server_document(str(cree["id"]))
    membre = document["members"][0]
    horodatage = membre["joined_at"]
    assert isinstance(horodatage, datetime), f"Type BSON inattendu : {type(horodatage)}"
    # Le premier membre est admis à la création : son `joined_at` vaut `created_at`.
    assert horodatage == document["created_at"]


def test_joined_at_est_proche_de_l_heure_de_creation(client: TestClient) -> None:
    """`joined_at` vient bien du serveur, et non d'une valeur figée.

    La fenêtre est large (une heure) : le test ne cherche pas à mesurer une
    vitesse, mais à vérifier que l'horodatage est produit au moment de la
    création. Un `joined_at` câblé à une constante, ou antérieur de plusieurs
    jours, échouerait.
    """
    register_user(client, "alice")
    debut = datetime.now(UTC)
    cree = create_server(client)
    membre = server_document(str(cree["id"]))["members"][0]
    assert debut - timedelta(minutes=1) <= membre["joined_at"]
    assert membre["joined_at"] <= datetime.now(UTC) + timedelta(minutes=1)


def test_le_plus_ancien_membre_est_determine_par_joined_at() -> None:
    """Le membre le plus ancien est le plus petit `joined_at`, pas `members[0]`.

    Le serveur est écrit à la main avec l'ordre du tableau *inversé* par rapport
    à l'ancienneté. C'est ce qui distingue une vraie lecture de `joined_at` d'un
    raccourci sur l'ordre d'insertion — un raccourci qui donnerait la bonne
    réponse tant que les insertions suivent le temps.
    """
    alice_id, bob_id = ObjectId(), ObjectId()
    server_id = inserer_un_serveur_brut(
        members=[
            {"user_id": alice_id, "joined_at": datetime(2024, 6, 1, 12, 0, tzinfo=UTC)},
            {"user_id": bob_id, "joined_at": datetime(2023, 1, 1, 8, 0, tzinfo=UTC)},
        ],
        created_by=alice_id,
    )
    resultat = store_de_test(lambda store: store.oldest_server_member(ObjectId(server_id)))
    assert resultat is not None, "Un serveur qui a des membres a un membre le plus ancien."
    assert resultat["user_id"] == bob_id


def test_un_serveur_sans_membre_n_a_pas_de_plus_ancien(client: TestClient) -> None:
    """Un serveur vide n'a pas de membre le plus ancien, et le code le dit.

    Le cas n'est pas atteignable par l'API — la création admet toujours le
    créateur — mais il le sera le jour où un départ existera. Le code doit donc
    renvoyer `None` plutôt qu'échouer sur un `min()` sur une liste vide.
    """
    server_id = inserer_un_serveur_brut(members=[], created_by=ObjectId())
    assert store_de_test(lambda store: store.oldest_server_member(ObjectId(server_id))) is None


def test_ajouter_un_membre_est_idempotent() -> None:
    """Un second ajout du même membre ne le duplique pas.

    C'est la raison pour laquelle `$addToSet` ne convient pas : l'identité d'un
    membre est `members.user_id`, alors que le sous-document poussé contient
    aussi `joined_at`. Les deux sous-documents seraient différents, donc tous
    deux acceptés. Le test observe le nombre de membres après deux ajouts, et le
    retour du magasin, qui distingue « déjà là » de « serveur absent ».
    """
    alice_id, bob_id = ObjectId(), ObjectId()
    server_id = ObjectId(
        inserer_un_serveur_brut(
            members=[{"user_id": alice_id, "joined_at": datetime(2024, 1, 1, tzinfo=UTC)}],
            created_by=alice_id,
        )
    )
    assert store_de_test(lambda store: store.add_server_member(server_id, bob_id)) is True, (
        "Le premier ajout doit avoir lieu."
    )
    assert store_de_test(lambda store: store.add_server_member(server_id, bob_id)) is False, (
        "Un membre déjà présent doit être signalé comme tel."
    )

    document = server_document(str(server_id))
    assert len(document["members"]) == 2, "Le membre ne doit pas être dupliqué."


def test_un_membre_ajoute_accede_au_serveur(client: TestClient) -> None:
    """Un membre ajouté par le magasin trouve le serveur, et le voit apparaître.

    L'adhésion passe normalement par `POST /servers/{id}/members`, mais le
    magasin est appelé ici directement pour isoler le lien entre l'écriture et la
    lecture : le nouvel arrivant doit voir le serveur dans sa liste, pouvoir le
    lire, et y figurer avec son nom. C'est ce que vérifie aussi la route, mais en
    traversant toute la couche HTTP.
    """
    register_user(client, "alice")
    cree = create_server(client)
    client.cookies.clear()
    register_user(client, "bob")
    bob_id = user_id_of(client, "bob")

    store_de_test(lambda store: store.add_server_member(ObjectId(cree["id"]), ObjectId(bob_id)))

    liste = client.get("/servers")
    assert liste.status_code == 200, liste.text
    assert [s["id"] for s in liste.json()] == [cree["id"]]
    detail = client.get(f"/servers/{cree['id']}")
    assert detail.status_code == 200, detail.text
    assert [membre["username"] for membre in detail.json()["members"]] == ["alice", "bob"]


# --------------------------------------------------------------------------
# Sécurité
# --------------------------------------------------------------------------


def test_une_reponse_ne_contient_aucune_donnee_sensible(client: TestClient) -> None:
    """Ni mot de passe, ni clé privée, ni texte chiffré dans une réponse.

    Le haché du mot de passe est exclu par la projection de `users_by_ids`, et
    une clé privée ne quitte jamais le navigateur — il n'y en a donc pas en base
    à exposer. Ce test échouerait si une projection était élargie par mégarde.
    """
    register_user(client, "alice")
    cree = create_server(client)
    brut = client.get(f"/servers/{cree['id']}").text
    for interdit in ("password_hash", "private", "ciphertext", "clé privée", "text_chiffré"):
        assert interdit not in brut, (
            f"{interdit} ne doit jamais apparaître dans une réponse de serveur."
        )


def test_le_document_mongo_ne_contient_que_les_champs_prevus(client: TestClient) -> None:
    """Les champs stockés sont énumérés, pas cherchés par sous-chaîne.

    Un serveur ne détient aucun secret : ni clé de salon, ni texte chiffré, ni
    haché. Énumérer les champs fait échouer le test dès qu'un champ *supplémentaire*
    apparaît, ce qu'une recherche par sous-chaîne ne verrait pas.
    """
    register_user(client, "alice")
    cree = create_server(client)
    document = server_document(str(cree["id"]))
    assert set(document) == {"_id", "name", "created_by", "created_at", "members"}
    assert set(document["members"][0]) == {"user_id", "joined_at"}


def test_chaque_membre_decrit_un_profil_reel(client: TestClient) -> None:
    """`username` vient bien du profil, et non d'une valeur fabriquée.

    Le nom est résolu par le `user_id` du sous-document : un `user_id` fantôme
    donnerait un nom vide plutôt qu'un nom emprunté. Le test verrouille aussi la
    forme exacte du membre, clé publique comprise, pour qu'un champ ajouté soit
    visible à la révision.
    """
    register_user(client, "alice")
    cree = create_server(client)
    membres = cree["members"]
    assert len(membres) == 1
    assert membres[0]["user_id"] == user_id_of(client, "alice")
    assert membres[0]["username"] == "alice"
    assert set(membres[0]) == {
        "user_id",
        "username",
        "joined_at",
        "public_key_fingerprint",
        "public_key_jwk",
    }


# --------------------------------------------------------------------------
# Adhésion et retrait
#
# Ces tests vivaient dans `test_channels.py`, où l'appartenance était celle d'un
# canal. Ils suivent le déplacement : la route est celle du serveur, la règle
# est celle du créateur, et ce qui est retiré est l'accès à *tous* les canaux.
# --------------------------------------------------------------------------


def test_ajouter_un_membre(client: TestClient) -> None:
    owner = register_user(client, "alice")
    cree = create_server(client)
    client.cookies.clear()
    invitee = register_user(client, "bob")
    invitee_id = user_id_of(client, "bob")

    client.cookies.clear()
    login_user(client, owner)
    response = client.post(
        f"/servers/{cree['id']}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )

    assert response.status_code == 200, response.text
    membres = {membre["username"] for membre in response.json()["members"]}
    assert membres == {owner, invitee}
    # Un membre ajouté n'a pas encore de clé : l'échange se fait dans son
    # navigateur, jamais depuis le serveur. La clé est donc absente, et
    # l'interface peut le signaler au lieu d'échouer plus tard sans motif.
    added = [m for m in response.json()["members"] if m["username"] == invitee]
    assert added[0]["public_key_fingerprint"] is None
    assert added[0]["public_key_jwk"] is None


def test_le_membre_ajoute_est_ecrit_dans_la_une_des_documents(client: TestClient) -> None:
    """L'adhésion se lit dans `members`, avec son horodatage d'adhésion."""
    register_user(client, "alice")
    cree = create_server(client)
    client.cookies.clear()
    register_user(client, "bob")
    bob_id = user_id_of(client, "bob")
    client.cookies.clear()
    login_user(client, "alice")

    client.post(
        f"/servers/{cree['id']}/members",
        json={"user_id": bob_id},
        headers=csrf_headers(client),
    )

    document = server_document(str(cree["id"]))
    assert [str(m["user_id"]) for m in document["members"]] == [
        user_id_of(client, "alice"),
        bob_id,
    ]
    assert all(m["joined_at"] for m in document["members"])


def test_reinviter_un_membre_ne_le_duplique_pas(client: TestClient) -> None:
    """Réinviter quelqu'un est un état déjà atteint, pas une erreur.

    `add_server_member` filtre sur `members.user_id`, et le sous-document poussé
    contient un `joined_at` différent à chaque appel : sans ce filtre, une seconde
    invitation ajouterait un doublon.
    """
    owner = register_user(client, "alice")
    cree = create_server(client)
    client.cookies.clear()
    register_user(client, "bob")
    bob_id = user_id_of(client, "bob")
    client.cookies.clear()
    login_user(client, owner)

    for _ in range(2):
        response = client.post(
            f"/servers/{cree['id']}/members",
            json={"user_id": bob_id},
            headers=csrf_headers(client),
        )
        assert response.status_code == 200, response.text

    assert len(server_document(str(cree["id"]))["members"]) == 2
    assert owner == "alice"


def test_un_membre_ordinaire_ne_peut_pas_ajouter_de_membre(client: TestClient) -> None:
    """Seul le créateur administre la composition du serveur."""
    owner = register_user(client, "alice")
    cree = create_server(client)
    client.cookies.clear()
    invitee = register_user(client, "bob")
    invitee_id = user_id_of(client, "bob")
    client.cookies.clear()
    login_user(client, owner)
    add_server_member(client, str(cree["id"]), invitee_id)

    # Un membre ordinaire qui essaie d'inviter de son propre chef : composer le
    # serveur ne lui appartient pas.
    client.cookies.clear()
    register_user(client, "carol")
    intruder_id = user_id_of(client, "carol")
    client.cookies.clear()
    login_user(client, invitee)
    response = client.post(
        f"/servers/{cree['id']}/members",
        json={"user_id": intruder_id},
        headers=csrf_headers(client),
    )

    # 403, et non 404 : le membre appartient bien au serveur, c'est l'acte qui est
    # refusé. Sans la règle, n'importe quel membre convierait un inconnu.
    assert response.status_code == 403, response.text
    # La composition attendue est énoncée en entier, et non par une alternative :
    # « intruder absent » ne prouverait rien, puisque l'intrus serait absent
    # aussi si l'adhésion de l'invité avait échoué en amont. C'est le helper
    # d'adhésion ci-dessus qui garantit cet état, en vérifiant le statut HTTP.
    noms = {membre["username"] for membre in client.get(f"/servers/{cree['id']}").json()["members"]}
    assert noms == {owner, invitee}


def test_un_non_membre_ne_peut_pas_ajouter_de_membre(client: TestClient) -> None:
    register_user(client, "alice")
    cree = create_server(client)
    client.cookies.clear()
    register_user(client, "bob")
    bob_id = user_id_of(client, "bob")

    response = client.post(
        f"/servers/{cree['id']}/members",
        json={"user_id": bob_id},
        headers=csrf_headers(client),
    )
    assert response.status_code == 403, response.text


def test_ajouter_un_utilisateur_inexistant_renvoie_404(client: TestClient) -> None:
    register_user(client)
    cree = create_server(client)
    response = client.post(
        f"/servers/{cree['id']}/members",
        json={"user_id": dummy_object_id()},
        headers=csrf_headers(client),
    )
    assert response.status_code == 404, response.text


def test_un_membre_ne_peut_pas_se_ajouter_lui_meme(client: TestClient) -> None:
    """Le créateur est déjà membre : l'auto-adhésion n'aurait rien ajouté."""
    owner = register_user(client, "alice")
    cree = create_server(client)
    response = client.post(
        f"/servers/{cree['id']}/members",
        json={"user_id": user_id_of(client, owner)},
        headers=csrf_headers(client),
    )
    assert response.status_code == 409, response.text
    assert len(server_document(str(cree["id"]))["members"]) == 1


def test_le_corps_ne_peut_pas_fournir_le_createur(client: TestClient) -> None:
    """Un `created_by` glissé dans le corps est refusé, et rien n'est créé.

    Le champ décide de qui administre, et il ne se négocie pas dans un corps de
    requête : il vient de la session, comme à la création.
    """
    register_user(client, "alice")
    alice_id = user_id_of(client, "alice")
    cree = create_server(client)
    client.cookies.clear()
    register_user(client, "bob")
    bob_id = user_id_of(client, "bob")
    client.cookies.clear()
    login_user(client, "bob")

    forged = client.post(
        f"/servers/{cree['id']}/members",
        json={"user_id": bob_id, "created_by": alice_id},
        headers=csrf_headers(client),
    )

    assert forged.status_code in (403, 422), forged.text
    # Le refus n'a rien changé : `bob` n'est pas devenu membre.
    assert len(server_document(str(cree["id"]))["members"]) == 1


def test_retirer_un_membre(client: TestClient) -> None:
    owner = register_user(client, "alice")
    cree = create_server(client)
    client.cookies.clear()
    register_user(client, "bob")
    invitee_id = user_id_of(client, "bob")
    client.cookies.clear()
    login_user(client, owner)
    client.post(
        f"/servers/{cree['id']}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )

    response = client.request(
        "DELETE",
        f"/servers/{cree['id']}/members/{invitee_id}",
        headers=csrf_headers(client),
    )

    assert response.status_code == 200, response.text
    assert [membre["username"] for membre in response.json()["members"]] == [owner]


def test_un_membre_ordinaire_ne_peut_pas_retirer_de_membre(client: TestClient) -> None:
    """Retirer un membre est un acte du créateur, pas du membre concerné."""
    owner = register_user(client, "alice")
    cree = create_server(client)
    client.cookies.clear()
    invitee = register_user(client, "bob")
    invitee_id = user_id_of(client, "bob")
    client.cookies.clear()
    login_user(client, owner)
    client.post(
        f"/servers/{cree['id']}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )

    # Le membre essaie de s'exclure lui-même, en espérant que la règle ne
    # regarde que le créateur :
    client.cookies.clear()
    login_user(client, invitee)
    response = client.request(
        "DELETE",
        f"/servers/{cree['id']}/members/{invitee_id}",
        headers=csrf_headers(client),
    )

    assert response.status_code == 403, response.text
    noms = {m["username"] for m in client.get(f"/servers/{cree['id']}").json()["members"]}
    assert noms == {owner, invitee}


def test_le_createur_ne_peut_pas_se_retirer_lui_meme(client: TestClient) -> None:
    """Un serveur sans créateur n'aurait plus personne pour l'administrer.

    Le refus ne dépend pas du nombre de membres : même au milieu d'autres, un
    créateur qui s'absente laisserait un serveur que plus personne ne peut
    composer, ni dont plus personne ne peut distribuer les clés de salon.
    """
    owner = register_user(client, "alice")
    cree = create_server(client)
    client.cookies.clear()
    register_user(client, "bob")
    bob_id = user_id_of(client, "bob")
    client.cookies.clear()
    login_user(client, owner)
    client.post(
        f"/servers/{cree['id']}/members",
        json={"user_id": bob_id},
        headers=csrf_headers(client),
    )

    # Deux membres coexistent, et le retrait est malgré tout refusé.
    response = client.request(
        "DELETE",
        f"/servers/{cree['id']}/members/{user_id_of(client, owner)}",
        headers=csrf_headers(client),
    )

    assert response.status_code == 409, response.text
    detail = client.get(f"/servers/{cree['id']}").json()
    assert {m["username"] for m in detail["members"]} == {owner, "bob"}
    assert detail["created_by"] == user_id_of(client, owner)


def test_un_serveur_conserve_au_moins_un_membre(client: TestClient) -> None:
    """Le créateur seul membre ne peut pas se retirer.

    Refus dans tous les cas, pas seulement quand il est le dernier : c'est
    l'absence de créateur, plus encore que le nombre de membres, qui rendrait
    l'état inutilisable.
    """
    register_user(client, "alice")
    cree = create_server(client)
    response = client.request(
        "DELETE",
        f"/servers/{cree['id']}/members/{user_id_of(client, 'alice')}",
        headers=csrf_headers(client),
    )
    assert response.status_code == 409, response.text


def test_retirer_un_membre_supprime_ses_envelopes(client: TestClient) -> None:
    """Le retrait emporte les enveloppes de clé de salon.

    Le membre garde ce qu'il a déjà en local — le serveur ne peut pas le lui
    reprendre — mais il ne doit plus retrouver d'enveloppe par l'API, ni en
    laisser une orpheline qu'il récupérerait s'il réintégrait le serveur.
    """
    owner = register_user(client, "alice")
    cree = create_server(client)
    canal = create_channel(client, "general", server_id=str(cree["id"]))
    client.cookies.clear()
    invitee = register_user(client, "bob")
    invitee_id = user_id_of(client, "bob")
    client.cookies.clear()
    login_user(client, owner)
    client.post(
        f"/servers/{cree['id']}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )
    depose = client.post(
        f"/channels/{canal['id']}/keys",
        json={"user_id": invitee_id, "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )
    assert depose.status_code == 201, depose.text

    client.cookies.clear()
    login_user(client, invitee)
    assert client.get(f"/channels/{canal['id']}/keys/me").status_code == 200

    client.cookies.clear()
    login_user(client, owner)
    retrait = client.request(
        "DELETE",
        f"/servers/{cree['id']}/members/{invitee_id}",
        headers=csrf_headers(client),
    )
    assert retrait.status_code == 200, retrait.text

    mongo = sync_database()
    try:
        restantes = list(mongo[get_settings().mongo_db_name].channel_keys.find({}))
    finally:
        mongo.close()
    assert restantes == [], "Les enveloppes du membre retiré auraient dû disparaître."

    client.cookies.clear()
    login_user(client, invitee)
    # 403, et non 404 : le refus vient de l'appartenance au serveur, qui est
    # consultée avant d'atteindre les enveloppes.
    assert client.get(f"/channels/{canal['id']}/keys/me").status_code == 403


def test_un_membre_retire_ne_recouvre_aucun_acces(client: TestClient) -> None:
    """Un retrait suffit : le membre ne rachète rien en appelant l'API.

    Toutes les requêtes ci-dessous sont faites **par l'ancien membre lui-même**,
    avec un jeton CSRF valide pour sa propre session. C'était le défaut de la
    version précédente : le jeton était capturé avant l'inscription d'un tiers, or
    `/auth/register` supprime la session courante et en ouvre une nouvelle
    (`app/routers/auth.py`). Le jeton capturé appartenait donc à une session
    morte, et chaque mutation se faisait refuser par `require_csrf` — un 403 de
    jeton, pas un 403 d'autorisation. Les lectures, elles, n'exigent pas de jeton
    et tournaient au compte du tiers inscrit entre-temps. Le test passait donc
    aussi bien avec ou sans le retrait : il ne prouvait rien.

    Le test est encadré par deux contrôles positifs. Avant le retrait, l'invité
    accède à tout, ce qui établit qu'il était bien membre et que ces routes ne
    répondent pas 403 par défaut. Après le retrait, il n'accède plus à rien. Sans
    le contrôle initial, un 403 ne prouverait rien : il pourrait venir d'une
    route cassée, d'un jeton périmé ou d'une erreur de mise en scène.

    Une limite à connaître, qui vient de la migration : les mutations restent
    gardées par `require_channel_server_creator`, plus strict que
    `require_channel_server`, et ne consultent donc pas l'appartenance. Un membre
    ordinaire y serait refusé de la même façon, retrait ou non. Elles prouvent que
    l'ancien membre ne récupère aucun pouvoir, pas que le retrait est la cause du
    refus. Les trois lectures, elles, ne sont gardées que par l'appartenance au
    serveur : leur 403 vient bien du retrait. Aucune route HTTP mutante n'est
    ouverte à un simple membre — l'envoi de message passe par le WebSocket, hors
    de portée de ce test — donc l'isoler davantage demanderait un changement de
    routes, expressément exclu ici.
    """
    owner = register_user(client, "alice")
    cree = create_server(client)
    canal = create_channel(client, "general", server_id=str(cree["id"]))
    canal_id = canal["id"]
    client.cookies.clear()
    invitee = register_user(client, "bob")
    invitee_id = user_id_of(client, "bob")
    # Le tiers est inscrit tout de suite : son inscription fait tourner la session,
    # elle ne doit donc pas se produire au milieu des vérifications.
    register_user(client, "carol")
    third_id = user_id_of(client, "carol")
    client.cookies.clear()
    login_user(client, owner)
    client.post(
        f"/servers/{cree['id']}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )
    client.post(
        f"/channels/{canal_id}/keys",
        json={"user_id": invitee_id, "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )

    # Contrôle positif, avant le retrait : l'invité est bien membre, et chacune de
    # ces trois routes lui répond 200. C'est ce qui rend le 403 de la seconde
    # moitié discriminant.
    client.cookies.clear()
    login_user(client, invitee)
    assert client.get(f"/channels/{canal_id}").status_code == 200
    assert client.get(f"/channels/{canal_id}/keys/me").status_code == 200
    assert client.get(f"/channels/{canal_id}/messages").status_code == 200

    # Le retrait, effectué par le créateur, seul habilité à le faire.
    client.cookies.clear()
    login_user(client, owner)
    retrait = client.request(
        "DELETE",
        f"/servers/{cree['id']}/members/{invitee_id}",
        headers=csrf_headers(client),
    )
    assert retrait.status_code == 200, retrait.text

    # Tout ce qui suit est joué par l'ancien membre, sur sa session toute neuve.
    client.cookies.clear()
    login_user(client, invitee)
    headers = csrf_headers(client)

    lectures = {
        "canal": client.get(f"/channels/{canal_id}"),
        "historique": client.get(f"/channels/{canal_id}/messages"),
        "enveloppe": client.get(f"/channels/{canal_id}/keys/me"),
    }
    for nom, reponse in lectures.items():
        assert reponse.status_code == 403, f"{nom} : {reponse.text}"

    mutations = {
        "ajout de membre": client.post(
            f"/servers/{cree['id']}/members",
            json={"user_id": third_id},
            headers=headers,
        ),
        "dépôt d'enveloppe": client.post(
            f"/channels/{canal_id}/keys",
            json={"user_id": invitee_id, "wrapped_key": wrapped_key_b64()},
            headers=headers,
        ),
        "retrait de membre": client.request(
            "DELETE",
            f"/servers/{cree['id']}/members/{user_id_of(client, owner)}",
            headers=headers,
        ),
    }
    for nom, reponse in mutations.items():
        assert reponse.status_code == 403, f"{nom} : {reponse.text}"
        # Un 403 d'autorisation, pas un 403 de jeton : c'est la distinction que
        # la version précédente du test brouillait. Un jeton périmé donnerait
        # "Jeton CSRF ..." et ferait passer le test pour une bonne raison.
        assert "CSRF" not in reponse.text, (
            f"{nom} refusé par le CSRF, pas par les droits : {reponse.text}"
        )

    # Dernier contrôle : le jeton du membre retiré fonctionne bel et bien. La même
    # mutation, avec ce même jeton, réussit pour le créateur — qui est membre.
    # Sans cela, un 403 de CSRF passerait inaperçu.
    client.cookies.clear()
    login_user(client, owner)
    entete_valide = csrf_headers(client)
    assert (
        client.post(
            f"/servers/{cree['id']}/members",
            json={"user_id": third_id},
            headers=entete_valide,
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/channels/{canal_id}/keys",
            json={"user_id": third_id, "wrapped_key": wrapped_key_b64()},
            headers=entete_valide,
        ).status_code
        == 201
    )


def test_un_retrait_porte_sur_tous_les_canaux_du_serveur(client: TestClient) -> None:
    """Ce qui rend le retrait différent d'avant : il ne porte plus sur un canal.

    Le membre retiré perd l'accès à l'ensemble de ce que contient le serveur. Une
    règle qui ne vaudrait que pour un canal laisserait les autres lisibles, ce qui
    serait une régression de la garantie.
    """
    owner = register_user(client, "alice")
    cree = create_server(client)
    premier = create_channel(client, "general", server_id=str(cree["id"]))
    second = create_channel(client, "annonces", server_id=str(cree["id"]))
    client.cookies.clear()
    invitee = register_user(client, "bob")
    invitee_id = user_id_of(client, "bob")
    client.cookies.clear()
    login_user(client, owner)
    client.post(
        f"/servers/{cree['id']}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )

    # Contrôle positif : les deux canaux sont accessibles avant le retrait.
    client.cookies.clear()
    login_user(client, invitee)
    for canal in (premier, second):
        assert client.get(f"/channels/{canal['id']}").status_code == 200

    client.cookies.clear()
    login_user(client, owner)
    client.request(
        "DELETE",
        f"/servers/{cree['id']}/members/{invitee_id}",
        headers=csrf_headers(client),
    )

    client.cookies.clear()
    login_user(client, invitee)
    for canal in (premier, second):
        assert client.get(f"/channels/{canal['id']}").status_code == 403
    # Et il ne voit plus le serveur dans sa liste, ni ses canaux dans la sienne.
    assert client.get(f"/servers/{cree['id']}").status_code == 403
    assert client.get("/channels").json() == []


def test_un_membre_non_admis_ne_vit_plus_apres_un_retrait(client: TestClient) -> None:
    """Un retrait suivi d'une réadmission redonne accès, mais pas l'enveloppe.

    Réintégrer quelqu'un ne lui rend pas une clé de salon qu'il n'a plus : il faut
    que le créateur en dépose une nouvelle, dans le canal de son choix. C'est ce
    qui évite qu'un ancien membre retrouve, par un simple retour, une clé de salon
    qu'on avait précisément retirée.
    """
    owner = register_user(client, "alice")
    cree = create_server(client)
    canal = create_channel(client, "general", server_id=str(cree["id"]))
    client.cookies.clear()
    invitee = register_user(client, "bob")
    invitee_id = user_id_of(client, "bob")
    client.cookies.clear()
    login_user(client, owner)
    add_server_member(client, str(cree["id"]), invitee_id)
    depose = client.post(
        f"/channels/{canal['id']}/keys",
        json={"user_id": invitee_id, "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )
    assert depose.status_code == 201, depose.text

    # Contrôle positif avant le retrait : l'enveloppe existe bien. Sans lui, le 404
    # de la fin serait indistinguable d'un dépôt qui n'a jamais eu lieu, et le
    # test passerait à vide en ne prouvant rien du tout.
    client.cookies.clear()
    login_user(client, invitee)
    assert client.get(f"/channels/{canal['id']}/keys/me").status_code == 200

    client.cookies.clear()
    login_user(client, owner)
    remove_server_member(client, str(cree["id"]), invitee_id)

    # Réadmission, puis contrôle : l'accès est revenu, l'enveloppe non.
    readmis = client.post(
        f"/servers/{cree['id']}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )
    assert readmis.status_code == 200, readmis.text

    client.cookies.clear()
    login_user(client, invitee)
    assert client.get(f"/channels/{canal['id']}").status_code == 200
    assert client.get(f"/channels/{canal['id']}/keys/me").status_code == 404


def test_les_routes_de_membres_de_canal_ont_disparu(client: TestClient) -> None:
    """Invariant de régression : il ne reste qu'un seul endroit où adhérer.

    Une route `/channels/{id}/members` qui survivrait accepterait une écriture que
    rien ne relit ensuite, et laisserait croire à une adhésion qui n'a pas eu lieu
    — l'appelant verrait « membre » dans une réponse, sans l'être pour
    l'autorisation.

    Le statut attendu n'est pas 404 mais 405, et c'est un détail qui mérite d'être
    dit : aucune route API ne revendique plus ce chemin, donc la requête atteint le
    montage du frontend sur `/`, qui ne connaît que `GET` et `HEAD`. La distinction
    importe parce que les deux directions sont exactes — 403 signifierait qu'un
    garde existe encore, ce qui n'est pas le cas.
    """
    register_user(client)
    cree = create_server(client)
    canal = create_channel(client, "general", server_id=str(cree["id"]))
    headers = csrf_headers(client)

    ajout = client.post(
        f"/channels/{canal['id']}/members",
        json={"user_id": dummy_object_id()},
        headers=headers,
    )
    retrait = client.request(
        "DELETE", f"/channels/{canal['id']}/members/{dummy_object_id()}", headers=headers
    )

    assert ajout.status_code == 405, ajout.text
    assert retrait.status_code == 405, retrait.text
