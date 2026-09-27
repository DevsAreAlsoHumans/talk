"""Canaux, accès par le serveur parent, et clés de salon.

Ces tests couvrent le partage de canal et, surtout, la frontière qui compte :
ce que le serveur doit savoir — qui est membre du serveur, quelle clé est
distribuée — et ce qu'il ne doit surtout pas pouvoir faire : distribuer une clé,
ou en déchiffrer une.

Un canal n'a plus de membres, il a un `server_id`. Toutes les vérifications
d'accès descendent donc le canal jusqu'à son serveur, et c'est la liste de
`server.members` qui décide. Les tests d'adhésion et de retrait ne sont donc pas
ici : ils appartiennent au serveur, et vivent dans `test_servers.py`.

Le protocole prévoit un cas volontairement imparfait : un canal peut exister
sans la moindre enveloppe, entre la création et le premier dépôt. Ce n'est pas
un oubli, c'est ce qui permet au créateur de rester maître de la clé, et les
tests le vérifient pour qu'on ne le « corrige » pas par réflexe.
"""

from __future__ import annotations

import base64
import uuid

import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

from app.config import get_settings
from tests.conftest import (
    add_server_member,
    create_channel,
    create_server,
    csrf_headers,
    current_user_id,
    dummy_object_id,
    login_user,
    publish_public_key,
    register_user,
    sync_database,
    unique_username,
    user_id_of,
    wrapped_key_b64,
)


def creer_serveur_puis_canal(client: TestClient, name: str = "general") -> tuple[dict, dict]:
    """Crée un serveur puis un canal à l'intérieur, et renvoie les deux.

    L'appelant est le créateur des deux, seule situation où il peut à la fois
    créer le canal et inviter quelqu'un dans le serveur qui le contient. Les tests
    qui ont besoin des deux objets passent par là ; ceux qui n'ont besoin que d'un
    canal lisible par son auteur appellent `create_channel` directement, qui crée
    un serveur au passage.
    """
    serveur = create_server(client, name)
    canal = create_channel(client, name, server_id=str(serveur["id"]))
    return serveur, canal


def test_creer_un_canal(client: TestClient) -> None:
    register_user(client)
    publish_public_key(client)
    serveur = create_server(client)
    client_ref = str(uuid.uuid4())

    response = client.post(
        f"/servers/{serveur['id']}/channels",
        json={"name": "  general  ", "client_ref": client_ref},
        headers=csrf_headers(client),
    )

    assert response.status_code == 201, response.text
    body = response.json()
    # Le nom est normalisé : deux membres ne doivent pas créer « general » et
    # « general   » en croyant obtenir deux canaux distincts.
    assert body["name"] == "general"
    assert body["client_ref"] == client_ref
    # Le canal ne se décrit que par son serveur parent. Ni membres, ni
    # propriétaire : ce serait une seconde copie de l'appartenance, appelée à
    # diverger dès que le serveur gagne ou perd quelqu'un.
    assert body["server_id"] == str(serveur["id"])
    assert "members" not in body
    assert "created_by" not in body


def test_creer_un_canal_exige_une_cle_publique(client: TestClient) -> None:
    register_user(client)
    serveur = create_server(client)
    response = client.post(
        f"/servers/{serveur['id']}/channels",
        json={"name": "general", "client_ref": str(uuid.uuid4())},
        headers=csrf_headers(client),
    )
    # Sans clé publique, le membre ne pourrait jamais déchiffrer une clé de
    # salon : mieux vaut refuser le canal maintenant que le rendre inutilisable.
    assert response.status_code == 409, response.text


def test_creer_un_canal_exige_le_csrf(client: TestClient) -> None:
    register_user(client)
    publish_public_key(client)
    serveur = create_server(client)
    response = client.post(
        f"/servers/{serveur['id']}/channels",
        json={"name": "general", "client_ref": str(uuid.uuid4())},
    )
    assert response.status_code == 403, response.text


@pytest.mark.parametrize(
    "name",
    ["", "   ", "-commence-par-un-tiret", "trop" * 30, "<script>alert(1)</script>", "a" * 65],
)
def test_les_noms_de_canal_invalides_sont_refuses(client: TestClient, name: str) -> None:
    register_user(client)
    publish_public_key(client)
    serveur = create_server(client)
    response = client.post(
        f"/servers/{serveur['id']}/channels",
        json={"name": name, "client_ref": str(uuid.uuid4())},
        headers=csrf_headers(client),
    )
    assert response.status_code == 422, response.text


def test_un_client_ref_est_unique_par_serveur(client: TestClient) -> None:
    """La référence locale est celle du serveur, et non celle d'un auteur.

    Avant la migration, elle était unique par créateur, donc chacun avait son
    propre espace. Elle est maintenant unique par serveur : deux canaux de même
    référence dans un même serveur entrent en collision, et le même `client_ref`
    reste accepté dans deux serveurs distincts. C'est ce qui rend la reprise après
    fermeture de navigateur non ambiguë — la référence désigne un canal dans le
    serveur que l'on rouvre.
    """
    register_user(client)
    publish_public_key(client)
    serveur = create_server(client)
    autre_serveur = create_server(client, "second")
    client_ref = str(uuid.uuid4())
    headers = csrf_headers(client)

    first = client.post(
        f"/servers/{serveur['id']}/channels",
        json={"name": "general", "client_ref": client_ref},
        headers=headers,
    )
    second = client.post(
        f"/servers/{serveur['id']}/channels",
        json={"name": "autre", "client_ref": client_ref},
        headers=headers,
    )
    elsewhere = client.post(
        f"/servers/{autre_serveur['id']}/channels",
        json={"name": "general", "client_ref": client_ref},
        headers=headers,
    )

    assert first.status_code == 201, first.text
    assert second.status_code == 409, second.text
    assert elsewhere.status_code == 201, elsewhere.text


def test_un_membre_du_serveur_ne_peut_pas_creer_un_canal(client: TestClient) -> None:
    """Seul le créateur du serveur en compose les canaux.

    Un membre ordinaire qui pourrait créer un canal le ferait pour lui seul, sans
    que personne d'autre puisse le lire, et sans propriétaire pour distribuer la
    clé de salon. La règle suit l'autorité, qui est celle du serveur.
    """
    owner = register_user(client)
    serveur, _canal = creer_serveur_puis_canal(client)
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    client.cookies.clear()
    login_user(client, owner)
    add_server_member(client, str(serveur["id"]), user_id_of(client, invitee))

    # Le membre ordinaire a une clé publique : il n'échoue donc pas sur ce garde,
    # et le 403 qu'il reçoit ne peut venir que de l'autorité.
    client.cookies.clear()
    login_user(client, invitee)
    publish_public_key(client)
    response = client.post(
        f"/servers/{serveur['id']}/channels",
        json={"name": "intrus", "client_ref": str(uuid.uuid4())},
        headers=csrf_headers(client),
    )

    # 403, et non 404 : le serveur existe et l'appelant en fait partie, c'est
    # l'acte qui est refusé.
    assert response.status_code == 403, response.text


def test_un_non_membre_ne_peut_pas_creer_un_canal(client: TestClient) -> None:
    register_user(client)
    serveur, _canal = creer_serveur_puis_canal(client)
    client.cookies.clear()
    outsider = register_user(client, unique_username())
    publish_public_key(client)

    response = client.post(
        f"/servers/{serveur['id']}/channels",
        json={"name": "intrus", "client_ref": str(uuid.uuid4())},
        headers=csrf_headers(client),
    )

    assert response.status_code == 403, response.text
    assert outsider


def test_lister_les_canaux_du_membre(client: TestClient) -> None:
    first_user = register_user(client)
    first = create_channel(client, "general")
    second = create_channel(client, "annonces")

    client.cookies.clear()
    register_user(client, unique_username())
    prive = create_channel(client, "prive")

    # Le canal du second utilisateur ne doit pas apparaître chez le premier.
    client.cookies.clear()
    login_user(client, first_user)
    response = client.get("/channels")

    assert response.status_code == 200, response.text
    visibles = {c["id"] for c in response.json()}
    assert {first["id"], second["id"]} == visibles
    assert prive["id"] not in visibles


def test_lister_les_canaux_d_un_serveur(client: TestClient) -> None:
    """La route hiérarchique renvoie les canaux du serveur, et lui seulement."""
    owner = register_user(client)
    serveur, _ = creer_serveur_puis_canal(client, "general")
    attendu = create_channel(client, "annonces", server_id=str(serveur["id"]))
    _autre_serveur, hors_perimetre = creer_serveur_puis_canal(client, "prive")

    response = client.get(f"/servers/{serveur['id']}/channels")

    assert response.status_code == 200, response.text
    ids = {c["id"] for c in response.json()}
    assert attendu["id"] in ids
    assert hors_perimetre["id"] not in ids

    # Un membre du serveur y lit la liste ; un tiers non.
    client.cookies.clear()
    membre = register_user(client, unique_username())
    client.cookies.clear()
    login_user(client, owner)
    add_server_member(client, str(serveur["id"]), user_id_of(client, membre))
    client.cookies.clear()
    login_user(client, membre)
    assert client.get(f"/servers/{serveur['id']}/channels").status_code == 200

    client.cookies.clear()
    outsider = register_user(client, unique_username("outsider"))
    assert client.get(f"/servers/{serveur['id']}/channels").status_code == 403
    assert outsider != membre


def test_lister_les_canaux_d_un_serveur_vide(client: TestClient) -> None:
    """Un serveur sans canal répond une liste vide, pas une erreur.

    C'est l'état dans lequel se trouve un serveur tout juste créé, et c'est
    aussi celui vers lequel bascule l'interface quand on sélectionne un serveur
    vide alors qu'un canal était ouvert auparavant. Le contrat sert donc les deux
    côtés : `200` et `[]`, pour le créateur comme pour un membre simple, afin que
    le client puisse distinguer « ce serveur n'a rien » d'un accès refusé.
    """
    owner = register_user(client)
    serveur = create_server(client)

    reponse = client.get(f"/servers/{serveur['id']}/channels")
    assert reponse.status_code == 200, reponse.text
    assert reponse.json() == []

    # Le serveur vide est bien lisible et modifiable par son membre : 403 ici
    # signifierait que l'interface afficherait un refus au lieu d'un état vide.
    client.cookies.clear()
    membre = register_user(client, unique_username())
    client.cookies.clear()
    login_user(client, owner)
    add_server_member(client, str(serveur["id"]), user_id_of(client, membre))
    client.cookies.clear()
    login_user(client, membre)
    assert client.get(f"/servers/{serveur['id']}/channels").json() == []

    # Et le canal créé ensuite apparaît, sans quoi la liste serait figée. La
    # création revient au créateur : un membre ordinaire en serait refusé, et
    # `create_channel` l'exigerait par un 403.
    client.cookies.clear()
    login_user(client, owner)
    attendu = create_channel(client, "general", server_id=str(serveur["id"]))
    ids = {c["id"] for c in client.get(f"/servers/{serveur['id']}/channels").json()}
    assert ids == {attendu["id"]}


def test_lire_un_canal_inexistant_renvoie_404(client: TestClient) -> None:
    register_user(client)
    assert client.get(f"/channels/{dummy_object_id()}").status_code == 404


def test_un_canal_est_invisible_pour_un_non_membre(client: TestClient) -> None:
    """Un tiers est refusé sur le canal, comme sur l'historique et l'enveloppe.

    Le refus porte sur le serveur parent, pas sur le canal : il n'y a plus de
    liste de membres de canal qui pourrait en décider autrement. Le contrôle est
    écrit une seule fois, dans `require_channel_server`, et ces trois routes
    l'utilisent telle quelle.
    """
    owner = register_user(client)
    _serveur, canal = creer_serveur_puis_canal(client)
    owner_id = user_id_of(client, owner)
    client.post(
        f"/channels/{canal['id']}/keys",
        json={"user_id": owner_id, "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )

    client.cookies.clear()
    outsider = register_user(client, unique_username())

    assert client.get(f"/channels/{canal['id']}").status_code == 403
    assert client.get(f"/channels/{canal['id']}/messages").status_code == 403
    assert client.get(f"/channels/{canal['id']}/keys/me").status_code == 403
    # L'identifiant n'est pas davantage devinable : un identifiant mal formé se
    # comporte comme un canal absent, pas comme une erreur serveur.
    assert client.get("/channels/pas-un-objectid").status_code == 404
    assert outsider


def test_un_canal_est_lisible_par_les_membres_du_serveur(client: TestClient) -> None:
    """L'appartenance au serveur suffit, et il n'y a rien d'autre à vérifier."""
    owner = register_user(client)
    serveur, canal = creer_serveur_puis_canal(client)
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    client.cookies.clear()
    login_user(client, owner)
    add_server_member(client, str(serveur["id"]), user_id_of(client, invitee))

    client.cookies.clear()
    login_user(client, invitee)
    response = client.get(f"/channels/{canal['id']}")

    assert response.status_code == 200, response.text
    assert response.json()["id"] == canal["id"]
    assert response.json()["server_id"] == str(serveur["id"])


def test_deposer_une_enveloppe_pour_un_membre(client: TestClient) -> None:
    """Le créateur dépose sa propre enveloppe, comme le fait le navigateur."""
    register_user(client)
    _serveur, canal = creer_serveur_puis_canal(client)

    response = client.post(
        f"/channels/{canal['id']}/keys",
        json={"user_id": current_user_id(client), "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["key_version"] == 1
    # Le serveur ne fait que restituer ce qu'il a reçu, octet pour octet.
    assert body["wrapped_key"] == wrapped_key_b64()


def test_un_membre_ordinaire_ne_peut_pas_deposer_d_enveloppe(client: TestClient) -> None:
    """La distribution de la clé de salon appartient au seul créateur du serveur.

    Le canal n'ayant plus de propriétaire, c'est le créateur du serveur qui
    distribue. Un membre ordinaire en est donc exclu, exactement comme il l'est
    pour créer un canal.
    """
    owner = register_user(client)
    serveur, canal = creer_serveur_puis_canal(client)
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    invitee_id = user_id_of(client, invitee)
    client.cookies.clear()
    login_user(client, owner)
    add_server_member(client, str(serveur["id"]), invitee_id)

    # Le membre qui a la clé de salon veut la redistribuer, à lui-même comme au
    # créateur. Ni pour l'un ni pour l'autre : c'est l'acte du créateur.
    client.cookies.clear()
    login_user(client, invitee)
    headers = csrf_headers(client)
    for target in (invitee_id, user_id_of(client, owner)):
        response = client.post(
            f"/channels/{canal['id']}/keys",
            json={"user_id": target, "wrapped_key": wrapped_key_b64()},
            headers=headers,
        )
        assert response.status_code == 403, response.text

    # Rien n'a été déposé pour le membre : il attend encore la clé du créateur.
    assert client.get(f"/channels/{canal['id']}/keys/me").status_code == 404


def test_un_membre_ne_peut_pas_preempter_l_enveloppe_d_un_autre(client: TestClient) -> None:
    """Le dépôt étant « premier arrivé, premier servi », seul le créateur peut
    déposer une enveloppe pour un membre.

    C'est la raison d'être de la règle : un membre ordinaire qui déposerait ici une
    enveloppe contenant une clé de salon de son choix verrait le destinataire la
    déchiffrer sans erreur, puis incapable de lire le moindre message chiffré avec
    la vraie clé — tout en pouvant lire ce que le déposant chiffrerait avec la clé
    imposée.
    """
    owner = register_user(client)
    serveur, canal = creer_serveur_puis_canal(client)
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    invitee_id = user_id_of(client, invitee)
    client.cookies.clear()
    intruder = register_user(client, unique_username())
    intruder_id = user_id_of(client, intruder)
    client.cookies.clear()
    login_user(client, owner)
    for target in (invitee_id, intruder_id):
        add_server_member(client, str(serveur["id"]), target)

    # Le membre ordinaire tente la préemption, pour le compte d'un autre membre.
    # Une enveloppe plausible, de la taille que le serveur accepte, et distincte de
    # celle que le créateur sera censé déposer : seule l'autorisation peut
    # l'empêcher de passer.
    forged = base64.b64encode(bytes([0xAB] * 256)).decode("ascii")
    assert forged != wrapped_key_b64()
    client.cookies.clear()
    login_user(client, intruder)
    attempt = client.post(
        f"/channels/{canal['id']}/keys",
        json={"user_id": invitee_id, "wrapped_key": forged},
        headers=csrf_headers(client),
    )
    assert attempt.status_code == 403, attempt.text

    # L'enveloppe légitime du créateur passe, et c'est bien elle qui est servie :
    # la préemption n'a rien laissé derrière elle.
    client.cookies.clear()
    login_user(client, owner)
    legitimate = client.post(
        f"/channels/{canal['id']}/keys",
        json={"user_id": invitee_id, "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )
    assert legitimate.status_code == 201, legitimate.text

    client.cookies.clear()
    login_user(client, invitee)
    stored = client.get(f"/channels/{canal['id']}/keys/me")
    assert stored.status_code == 200, stored.text
    assert stored.json()["wrapped_key"] == wrapped_key_b64()
    assert stored.json()["wrapped_key"] != forged


def test_un_non_membre_du_serveur_ne_peut_pas_deposer_d_enveloppe(client: TestClient) -> None:
    owner = register_user(client)
    serveur, canal = creer_serveur_puis_canal(client)
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    invitee_id = user_id_of(client, invitee)
    client.cookies.clear()
    login_user(client, owner)
    add_server_member(client, str(serveur["id"]), invitee_id)

    client.cookies.clear()
    outsider = register_user(client, unique_username())
    response = client.post(
        f"/channels/{canal['id']}/keys",
        json={"user_id": invitee_id, "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )
    assert response.status_code == 403, response.text

    # Le destinataire, n'ayant rien reçu, attend toujours son enveloppe : 404 et non
    # 403, car il est membre du serveur et seule la distribution lui manque.
    client.cookies.clear()
    login_user(client, invitee)
    assert client.get(f"/channels/{canal['id']}/keys/me").status_code == 404
    assert outsider != invitee


def test_un_membre_peut_lire_son_propre_enveloppe(client: TestClient) -> None:
    """La lecture reste ouverte au membre : c'est lui qui en est le destinataire.

    Réserver aussi la lecture au créateur le priverait de la clé qu'on lui a
    transmise, ce qui nuirait au modèle sans rien sécuriser de plus. L'accès, lui,
    remonte au serveur : c'est l'appartenance au serveur qui ouvre la route, pas
    une appartenance au canal.
    """
    owner = register_user(client)
    serveur, canal = creer_serveur_puis_canal(client)
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    invitee_id = user_id_of(client, invitee)
    client.cookies.clear()
    login_user(client, owner)
    add_server_member(client, str(serveur["id"]), invitee_id)
    client.post(
        f"/channels/{canal['id']}/keys",
        json={"user_id": invitee_id, "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )

    client.cookies.clear()
    login_user(client, invitee)
    response = client.get(f"/channels/{canal['id']}/keys/me")

    assert response.status_code == 200, response.text
    assert response.json()["wrapped_key"] == wrapped_key_b64()
    assert owner != invitee


def test_un_canal_peut_exister_sans_enveloppe(client: TestClient) -> None:
    register_user(client)
    _serveur, canal = creer_serveur_puis_canal(client)

    response = client.get(f"/channels/{canal['id']}/keys/me")

    # État normal et attendu : le canal vient d'être créé, la clé reste chez son
    # créateur. 404 et non 403, car le canal existe et l'appelant y accède par son
    # appartenance au serveur.
    assert response.status_code == 404, response.text


def test_un_depot_repete_est_idempotent(client: TestClient) -> None:
    register_user(client)
    _serveur, canal = creer_serveur_puis_canal(client)
    headers = csrf_headers(client)
    body = {"user_id": current_user_id(client), "wrapped_key": wrapped_key_b64()}

    first = client.post(f"/channels/{canal['id']}/keys", json=body, headers=headers)
    second = client.post(f"/channels/{canal['id']}/keys", json=body, headers=headers)

    assert first.status_code == 201, first.text
    # Un client qui n'a pas vu l'accusé renvoie la même enveloppe ; il ne doit pas
    # obtenir une erreur, mais le même résultat.
    assert second.status_code == 201, second.text
    assert first.json()["wrapped_key"] == second.json()["wrapped_key"]


def test_deposer_pour_un_hors_membre_est_refuse(client: TestClient) -> None:
    register_user(client)
    _serveur, canal = creer_serveur_puis_canal(client)

    response = client.post(
        f"/channels/{canal['id']}/keys",
        json={"user_id": dummy_object_id(), "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )
    # 409, et non 403 : le créateur de l'enveloppe est bien autorisé à agir, c'est
    # le destinataire qui n'a pas sa place. Le corps n'est pas refusé non plus,
    # l'utilisateur désigné existe peut-être : il n'est simplement pas membre.
    assert response.status_code == 409, response.text


def test_une_enveloppe_de_taille_implausible_est_refusee(client: TestClient) -> None:
    register_user(client)
    _serveur, canal = creer_serveur_puis_canal(client)
    tiny = base64.b64encode(b"trop-court").decode("ascii")

    response = client.post(
        f"/channels/{canal['id']}/keys",
        json={"user_id": current_user_id(client), "wrapped_key": tiny},
        headers=csrf_headers(client),
    )
    assert response.status_code == 422, response.text


def test_le_serveur_ne_detient_aucune_cle_de_salon_en_clair(client: TestClient) -> None:
    """Invariant de régression, à ne jamais faire échouer.

    Le canal et son enveloppe sont les deux seules choses que le serveur détient.
    Aucune ne doit contenir quoi que ce soit d'exploitable.
    """
    register_user(client)
    _serveur, canal = creer_serveur_puis_canal(client)
    client.post(
        f"/channels/{canal['id']}/keys",
        json={"user_id": current_user_id(client), "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )

    mongo = sync_database()
    try:
        database = mongo[get_settings().mongo_db_name]
        envelopes = list(database.channel_keys.find({}))
    finally:
        mongo.close()

    assert envelopes, "L'enveloppe n'a pas été enregistrée."
    stored = envelopes[0]
    assert set(stored) >= {"wrapped_key", "user_id", "channel_id", "key_version"}
    # Aucun champ ne doit ressembler à une clé de salon utilisable telle quelle.
    for field, value in stored.items():
        assert field not in {"key", "room_key", "channel_key", "secret"}
        if isinstance(value, str) and field not in {"_id", "user_id", "channel_id"}:
            assert value == wrapped_key_b64()


def test_un_canal_ne_stocke_plus_de_membres(client: TestClient) -> None:
    """Invariant de régression : le document Mongo ne porte plus de `members`.

    C'est la promesse de la migration. Un canal qui garderait cette liste
    contrairement au schéma exposerait une copie de l'appartenance, et l'interface
    irait lire une information que l'autorisation, elle, ne consulte pas.
    """
    register_user(client)
    _serveur, canal = creer_serveur_puis_canal(client)

    mongo = sync_database()
    try:
        document = mongo[get_settings().mongo_db_name].channels.find_one(
            {"_id": ObjectId(str(canal["id"]))}
        )
    finally:
        mongo.close()

    assert document is not None, "Le canal devrait être en base."
    assert "members" not in document
    assert "created_by" not in document
    assert document["server_id"] == ObjectId(str(canal["server_id"]))
