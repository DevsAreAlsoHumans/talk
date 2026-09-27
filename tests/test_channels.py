"""Canaux, membres et clés de salon.

Ces tests couvrent le partage de canal et, surtout, la frontière qui compte :
ce que le serveur doit savoir (qui est membre, quelle clé est distribuée) et ce
qu'il ne doit surtout pas pouvoir faire (distribuer une clé, en déchiffrer une).

Le protocole prévoit un cas volontairement imparfait : un canal peut exister
sans la moindre enveloppe, entre la création et le premier dépôt. Ce n'est pas
un oubli, c'est ce qui permet au créateur de rester maître de la clé, et les
tests le vérifient pour qu'on ne le « corrige » pas par réflexe.
"""

from __future__ import annotations

import base64
import uuid

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from tests.conftest import (
    create_channel,
    csrf_headers,
    dummy_object_id,
    login_user,
    publish_public_key,
    register_user,
    sync_database,
    unique_username,
    user_id_of,
    wrapped_key_b64,
)


def test_creer_un_canal(client: TestClient) -> None:
    register_user(client)
    publish_public_key(client)
    client_ref = str(uuid.uuid4())

    response = client.post(
        "/channels",
        json={"name": "  general  ", "client_ref": client_ref},
        headers=csrf_headers(client),
    )

    assert response.status_code == 201, response.text
    body = response.json()
    # Le nom est normalisé : deux membres ne doivent pas créer « general » et
    # « general   » en croyant obtenir deux canaux distincts.
    assert body["name"] == "general"
    assert body["client_ref"] == client_ref
    assert len(body["members"]) == 1
    # Le créateur est membre, et sa clé est déjà publiée : l'empreinte est donc
    # connue sans échange supplémentaire.
    assert body["members"][0]["public_key_fingerprint"] is not None
    # La clé publique complète est exposée : c'est elle que le navigateur
    # emballe pour distribuer la clé de salon au nouveau membre.
    published = body["members"][0]["public_key_jwk"]
    assert published is not None
    assert published["kty"] == "RSA"
    assert published["alg"] == "RSA-OAEP-256"
    assert set(published) <= {"kty", "n", "e", "alg", "ext"}


def test_creer_un_canal_exige_une_cle_publique(client: TestClient) -> None:
    register_user(client)
    response = client.post(
        "/channels",
        json={"name": "general", "client_ref": str(uuid.uuid4())},
        headers=csrf_headers(client),
    )
    # Sans clé publique, le membre ne pourrait jamais déchiffrer une clé de
    # salon : mieux vaut refuser le canal maintenant que le rendre inutilisable.
    assert response.status_code == 409, response.text


def test_creer_un_canal_exige_le_csrf(client: TestClient) -> None:
    register_user(client)
    publish_public_key(client)
    response = client.post("/channels", json={"name": "general", "client_ref": str(uuid.uuid4())})
    assert response.status_code == 403, response.text


@pytest.mark.parametrize(
    "name",
    ["", "   ", "-commence-par-un-tiret", "trop" * 30, "<script>alert(1)</script>", "a" * 65],
)
def test_les_noms_de_canal_invalides_sont_refuses(client: TestClient, name: str) -> None:
    register_user(client)
    publish_public_key(client)
    response = client.post(
        "/channels",
        json={"name": name, "client_ref": str(uuid.uuid4())},
        headers=csrf_headers(client),
    )
    assert response.status_code == 422, response.text


def test_un_client_ref_est_unique_par_createur(client: TestClient) -> None:
    register_user(client)
    publish_public_key(client)
    client_ref = str(uuid.uuid4())
    headers = csrf_headers(client)

    first = client.post(
        "/channels", json={"name": "general", "client_ref": client_ref}, headers=headers
    )
    second = client.post(
        "/channels", json={"name": "autre", "client_ref": client_ref}, headers=headers
    )

    assert first.status_code == 201, first.text
    # C'est ce qui permet de retrouver le canal d'une création dont l'enveloppe
    # n'a pas encore été déposée, après fermeture du navigateur.
    assert second.status_code == 409, second.text


def test_lister_les_canaux_du_membre(client: TestClient) -> None:
    first_user = register_user(client)
    first = create_channel(client, "general")
    second = create_channel(client, "annonces")

    client.cookies.clear()
    register_user(client, unique_username())
    create_channel(client, "prive")

    # Le canal du second utilisateur ne doit pas apparaître chez le premier.
    client.cookies.clear()
    login_user(client, first_user)
    response = client.get("/channels")

    assert response.status_code == 200, response.text
    names = {channel["name"] for channel in response.json()}
    assert names == {"general", "annonces"}
    assert {first["id"], second["id"]} == {c["id"] for c in response.json()}


def test_lire_un_canal_inexistant_renvoie_404(client: TestClient) -> None:
    register_user(client)
    assert client.get(f"/channels/{dummy_object_id()}").status_code == 404


def test_un_canal_est_invisible_pour_un_non_membre(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)
    client.cookies.clear()
    outsider = register_user(client, unique_username())

    assert client.get(f"/channels/{channel['id']}").status_code == 403
    # L'identifiant n'est pas davantage devinable : un identifiant mal formé se
    # comporte comme un canal absent, pas comme une erreur serveur.
    assert client.get("/channels/pas-un-objectid").status_code == 404
    assert outsider


def test_ajouter_un_membre(client: TestClient) -> None:
    owner = register_user(client)
    channel = create_channel(client)
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    invitee_id = user_id_of(client, invitee)

    # C'est le créateur du canal qui invite, et lui seul le peut.
    client.cookies.clear()
    login_user(client, owner)
    response = client.post(
        f"/channels/{channel['id']}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )

    assert response.status_code == 200, response.text
    # Le créateur est identifié dans la représentation du canal : c'est cette
    # donnée que l'interface compare pour nier les actions d'administration.
    assert response.json()["created_by"] == user_id_of(client, owner)
    members = {member["username"] for member in response.json()["members"]}
    assert members == {owner, invitee}
    # Un membre ajouté n'a pas encore de clé : l'échange de clé se fait dans
    # son navigateur, jamais depuis le serveur. La clé est donc absente, et
    # l'interface peut le signaler au lieu d'échouer plus tard sans motif.
    added = [member for member in response.json()["members"] if member["username"] == invitee]
    assert added[0]["public_key_fingerprint"] is None
    assert added[0]["public_key_jwk"] is None


def test_un_membre_ordinaire_ne_peut_pas_ajouter_de_membre(client: TestClient) -> None:
    """Seul le créateur administre la composition du canal."""
    owner = register_user(client)
    channel = create_channel(client)
    channel_id = channel["id"]
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    invitee_id = user_id_of(client, invitee)
    client.cookies.clear()
    login_user(client, owner)
    added = client.post(
        f"/channels/{channel_id}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )
    assert added.status_code == 200, added.text

    # Un troisième utilisateur, que le membre ordinaire essaie d'inviter de son
    # propre chef : composer le canal ne lui appartient pas.
    client.cookies.clear()
    intruder = register_user(client, unique_username())
    intruder_id = user_id_of(client, intruder)
    client.cookies.clear()
    login_user(client, invitee)
    response = client.post(
        f"/channels/{channel_id}/members",
        json={"user_id": intruder_id},
        headers=csrf_headers(client),
    )

    # 403, et non 404 : le membre appartient bien au canal, c'est l'acte qui est
    # refusé. Sans la règle, n'importe quel membre convierait un inconnu.
    assert response.status_code == 403, response.text
    client.cookies.clear()
    login_user(client, owner)
    view = client.get(f"/channels/{channel_id}")
    assert intruder not in {member["username"] for member in view.json()["members"]}


def test_ajouter_un_membre_inexistant_renvoie_404(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)
    response = client.post(
        f"/channels/{channel['id']}/members",
        json={"user_id": dummy_object_id()},
        headers=csrf_headers(client),
    )
    assert response.status_code == 404, response.text


def test_un_non_membre_ne_peut_pas_ajouter_de_membre(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)
    client.cookies.clear()
    register_user(client, unique_username())

    response = client.post(
        f"/channels/{channel['id']}/members",
        json={"user_id": dummy_object_id()},
        headers=csrf_headers(client),
    )
    assert response.status_code == 403, response.text


def test_un_membre_ordinaire_ne_peut_pas_retirer_de_membre(client: TestClient) -> None:
    owner = register_user(client)
    channel = create_channel(client)
    channel_id = channel["id"]
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    invitee_id = user_id_of(client, invitee)
    client.cookies.clear()
    login_user(client, owner)
    client.post(
        f"/channels/{channel_id}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )

    # Même membre qui essaie de s'exclure lui-même : retirer un membre est un
    # acte du créateur, pas du membre concerné.
    client.cookies.clear()
    login_user(client, invitee)
    response = client.request(
        "DELETE",
        f"/channels/{channel_id}/members/{invitee_id}",
        headers=csrf_headers(client),
    )

    assert response.status_code == 403, response.text
    client.cookies.clear()
    login_user(client, owner)
    view = client.get(f"/channels/{channel_id}")
    assert {member["username"] for member in view.json()["members"]} == {owner, invitee}


def test_un_non_membre_ne_peut_pas_retirer_de_membre(client: TestClient) -> None:
    owner = register_user(client)
    channel = create_channel(client)
    channel_id = channel["id"]
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    invitee_id = user_id_of(client, invitee)
    client.cookies.clear()
    login_user(client, owner)
    client.post(
        f"/channels/{channel_id}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )

    # Un utilisateur resté en dehors du canal ne peut pas en évincer un membre,
    # et ne peut pas non plus se faire passer pour le créateur en glissant son
    # identifiant dans le corps de la requête.
    client.cookies.clear()
    outsider = register_user(client, unique_username())
    outsider_id = user_id_of(client, outsider)
    headers = csrf_headers(client)
    removal = client.request(
        "DELETE",
        f"/channels/{channel_id}/members/{invitee_id}",
        headers=headers,
    )
    add = client.post(
        f"/channels/{channel_id}/members",
        json={"user_id": outsider_id},
        headers=headers,
    )
    forged = client.post(
        f"/channels/{channel_id}/members",
        json={"user_id": outsider_id, "created_by": user_id_of(client, owner)},
        headers=headers,
    )

    assert removal.status_code == 403, removal.text
    assert add.status_code == 403, add.text
    # Un champ inattendu est refusé par le schéma, une identité usurpée par la
    # session ne l'est pas : dans les deux cas l'acte n'a pas lieu.
    assert forged.status_code in (403, 422), forged.text
    client.cookies.clear()
    login_user(client, owner)
    view = client.get(f"/channels/{channel_id}")
    assert {member["username"] for member in view.json()["members"]} == {owner, invitee}


def test_le_createur_ne_peut_pas_se_retirer_lui_meme(client: TestClient) -> None:
    """Un canal sans créateur n'aurait plus personne pour l'administrer.

    Le refus ne dépend pas du nombre de membres : même au milieu d'autres, un
    créateur qui s'absente laisserait un canal que plus personne ne peut composer
    ni dont plus personne ne peut distribuer la clé de salon.
    """
    owner = register_user(client)
    channel = create_channel(client)
    channel_id = channel["id"]
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    invitee_id = user_id_of(client, invitee)
    client.cookies.clear()
    login_user(client, owner)
    client.post(
        f"/channels/{channel_id}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )

    # Deux membres coexistent, et le retrait est malgré tout refusé.
    response = client.request(
        "DELETE",
        f"/channels/{channel_id}/members/{user_id_of(client, owner)}",
        headers=csrf_headers(client),
    )

    assert response.status_code == 409, response.text
    view = client.get(f"/channels/{channel_id}")
    assert {member["username"] for member in view.json()["members"]} == {owner, invitee}
    assert view.json()["created_by"] == user_id_of(client, owner)


def test_un_membre_retire_ne_recouvre_aucun_acces(client: TestClient) -> None:
    """Un retrait suffit : le membre ne rachète rien en appelant l'API."""
    owner = register_user(client)
    channel = create_channel(client)
    channel_id = channel["id"]
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    invitee_id = user_id_of(client, invitee)
    client.cookies.clear()
    login_user(client, owner)
    client.post(
        f"/channels/{channel_id}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )
    client.post(
        f"/channels/{channel_id}/keys",
        json={"user_id": invitee_id, "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )
    client.request(
        "DELETE",
        f"/channels/{channel_id}/members/{invitee_id}",
        headers=csrf_headers(client),
    )

    # L'ancien membre appelle directement chaque endpoint qui l'intéresse :
    # aucun ne doit lui rendre service.
    client.cookies.clear()
    login_user(client, invitee)
    headers = csrf_headers(client)
    third = register_user(client, unique_username())
    third_id = user_id_of(client, third)
    assert client.get(f"/channels/{channel_id}").status_code == 403
    assert client.get(f"/channels/{channel_id}/keys/me").status_code == 403
    assert client.get(f"/channels/{channel_id}/messages").status_code == 403
    assert (
        client.post(
            f"/channels/{channel_id}/members",
            json={"user_id": third_id},
            headers=headers,
        ).status_code
        == 403
    )
    assert (
        client.request(
            "DELETE",
            f"/channels/{channel_id}/members/{user_id_of(client, owner)}",
            headers=headers,
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/channels/{channel_id}/keys",
            json={"user_id": invitee_id, "wrapped_key": wrapped_key_b64()},
            headers=headers,
        ).status_code
        == 403
    )


def test_retirer_un_membre(client: TestClient) -> None:
    owner = register_user(client)
    channel = create_channel(client)
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    invitee_id = user_id_of(client, invitee)
    client.post(
        f"/channels/{channel['id']}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )

    # Le retrait est effectué par le créateur, seul habilité à le faire.
    client.cookies.clear()
    login_user(client, owner)
    response = client.request(
        "DELETE",
        f"/channels/{channel['id']}/members/{invitee_id}",
        headers=csrf_headers(client),
    )

    assert response.status_code == 200, response.text
    assert [member["username"] for member in response.json()["members"]] == [owner]


def test_retirer_un_membre_supprime_son_enveloppe(client: TestClient) -> None:
    owner = register_user(client)
    channel = create_channel(client)
    channel_id = channel["id"]
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    invitee_id = user_id_of(client, invitee)

    # Le créateur invite le membre, puis lui distribue la clé de salon.
    client.cookies.clear()
    login_user(client, owner)
    added = client.post(
        f"/channels/{channel_id}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )
    assert added.status_code == 200, added.text

    deposited = client.post(
        f"/channels/{channel_id}/keys",
        json={"user_id": invitee_id, "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )
    assert deposited.status_code == 201, deposited.text

    client.cookies.clear()
    login_user(client, invitee)
    assert client.get(f"/channels/{channel_id}/keys/me").status_code == 200

    # Après retrait, le membre n'a plus le droit de récupérer l'enveloppe.
    client.cookies.clear()
    login_user(client, owner)
    client.request(
        "DELETE",
        f"/channels/{channel_id}/members/{invitee_id}",
        headers=csrf_headers(client),
    )
    client.cookies.clear()
    login_user(client, invitee)
    assert client.get(f"/channels/{channel_id}/keys/me").status_code == 403


def test_un_canal_conserve_au_moins_un_membre(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)
    member_id = channel["members"][0]["id"]

    response = client.request(
        "DELETE", f"/channels/{channel['id']}/members/{member_id}", headers=csrf_headers(client)
    )

    # Le créateur est ici le seul membre, et il ne peut pas se retirer : c'est
    # l'absence de créateur, plus encore que l'absence de membre, qui rendrait
    # l'état inutilisable. Le refus vaut dans tous les cas, cf.
    # `test_le_createur_ne_peut_pas_se_retirer_lui_meme`.
    assert response.status_code == 409, response.text


def test_deposer_une_enveloppe_pour_un_membre(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)

    # Le créateur dépose sa propre enveloppe, comme le fait le navigateur juste
    # après la création du canal.
    response = client.post(
        f"/channels/{channel['id']}/keys",
        json={"user_id": channel["members"][0]["id"], "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["key_version"] == 1
    # Le serveur ne fait que restituer ce qu'il a reçu, octet pour octet.
    assert body["wrapped_key"] == wrapped_key_b64()


def test_un_membre_ordinaire_ne_peut_pas_deposer_d_enveloppe(client: TestClient) -> None:
    """La distribution de la clé de salon appartient au seul créateur."""
    owner = register_user(client)
    channel = create_channel(client)
    channel_id = channel["id"]
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    invitee_id = user_id_of(client, invitee)
    client.cookies.clear()
    login_user(client, owner)
    client.post(
        f"/channels/{channel_id}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )

    # Le membre qui a la clé de salon veut la redistribuer, à lui-même comme au
    # créateur. Ni pour l'un ni pour l'autre : c'est l'acte du créateur.
    client.cookies.clear()
    login_user(client, invitee)
    headers = csrf_headers(client)
    for target in (invitee_id, user_id_of(client, owner)):
        response = client.post(
            f"/channels/{channel_id}/keys",
            json={"user_id": target, "wrapped_key": wrapped_key_b64()},
            headers=headers,
        )
        assert response.status_code == 403, response.text

    # Rien n'a été déposé pour le membre : il attend encore la clé du créateur.
    assert client.get(f"/channels/{channel_id}/keys/me").status_code == 404


def test_un_membre_ne_peut_pas_preempter_l_enveloppe_d_un_autre(client: TestClient) -> None:
    """Le dépôt étant « premier arrivé, premier servi », seul le créateur peut
    déposer une enveloppe pour un membre.

    C'est la raison d'être de la règle : un membre ordinaire qui déposerait ici
    une enveloppe contenant une clé de salon de son choix verrait le
    destinataire la déchiffrer sans erreur, puis incapable de lire le moindre
    message chiffré avec la vraie clé — tout en pouvant lire ce que le
    déposant chiffrerait avec la clé imposée.
    """
    owner = register_user(client)
    channel = create_channel(client)
    channel_id = channel["id"]
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    invitee_id = user_id_of(client, invitee)
    client.cookies.clear()
    intruder = register_user(client, unique_username())
    intruder_id = user_id_of(client, intruder)
    client.cookies.clear()
    login_user(client, owner)
    for target in (invitee_id, intruder_id):
        added = client.post(
            f"/channels/{channel_id}/members",
            json={"user_id": target},
            headers=csrf_headers(client),
        )
        assert added.status_code == 200, added.text

    # Le membre ordinaire tente la préemption, pour le compte d'un autre membre.
    # Une enveloppe plausible, de la taille que le serveur accepte, et distincte
    # de celle que le créateur sera censé déposer : seule l'autorisation peut
    # l'empêcher de passer.
    forged = base64.b64encode(bytes([0xAB] * 256)).decode("ascii")
    assert forged != wrapped_key_b64()
    client.cookies.clear()
    login_user(client, intruder)
    attempt = client.post(
        f"/channels/{channel_id}/keys",
        json={"user_id": invitee_id, "wrapped_key": forged},
        headers=csrf_headers(client),
    )
    assert attempt.status_code == 403, attempt.text

    # L'enveloppe légitime du créateur passe, et c'est bien elle qui est servie :
    # la préemption n'a rien laissé derrière elle.
    client.cookies.clear()
    login_user(client, owner)
    legitimate = client.post(
        f"/channels/{channel_id}/keys",
        json={"user_id": invitee_id, "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )
    assert legitimate.status_code == 201, legitimate.text

    client.cookies.clear()
    login_user(client, invitee)
    stored = client.get(f"/channels/{channel_id}/keys/me")
    assert stored.status_code == 200, stored.text
    assert stored.json()["wrapped_key"] == wrapped_key_b64()
    assert stored.json()["wrapped_key"] != forged


def test_un_non_membre_ne_peut_pas_deposer_d_enveloppe(client: TestClient) -> None:
    owner = register_user(client)
    channel = create_channel(client)
    channel_id = channel["id"]
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    invitee_id = user_id_of(client, invitee)
    client.cookies.clear()
    login_user(client, owner)
    added = client.post(
        f"/channels/{channel_id}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )
    assert added.status_code == 200, added.text

    client.cookies.clear()
    outsider = register_user(client, unique_username())
    response = client.post(
        f"/channels/{channel_id}/keys",
        json={"user_id": invitee_id, "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )
    assert response.status_code == 403, response.text

    # Le destinataire, n'ayant rien reçu, attend toujours son enveloppe : 404 et
    # non 403, car il est membre et seule la distribution lui manque.
    client.cookies.clear()
    login_user(client, invitee)
    assert client.get(f"/channels/{channel_id}/keys/me").status_code == 404
    assert outsider != invitee


def test_un_membre_peut_lire_son_propre_enveloppe(client: TestClient) -> None:
    """La lecture reste ouverte au membre : c'est lui qui en est le destinataire.

    Réserver aussi la lecture au créateur le priverait de la clé qu'on lui a
    transmise, ce qui nuirait au modèle sans rien sécuriser de plus.
    """
    owner = register_user(client)
    channel = create_channel(client)
    channel_id = channel["id"]
    client.cookies.clear()
    invitee = register_user(client, unique_username())
    invitee_id = user_id_of(client, invitee)
    client.cookies.clear()
    login_user(client, owner)
    client.post(
        f"/channels/{channel_id}/members",
        json={"user_id": invitee_id},
        headers=csrf_headers(client),
    )
    client.post(
        f"/channels/{channel_id}/keys",
        json={"user_id": invitee_id, "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )

    client.cookies.clear()
    login_user(client, invitee)
    response = client.get(f"/channels/{channel_id}/keys/me")

    assert response.status_code == 200, response.text
    assert response.json()["wrapped_key"] == wrapped_key_b64()
    assert owner != invitee


def test_un_canal_peut_exister_sans_enveloppe(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)

    response = client.get(f"/channels/{channel['id']}/keys/me")

    # État normal et attendu : le canal vient d'être créé, la clé reste chez son
    # créateur. 404 et non 403, car le canal existe et l'appelant en est membre.
    assert response.status_code == 404, response.text


def test_un_depot_repete_est_idempotent(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)
    member_id = channel["members"][0]["id"]
    headers = csrf_headers(client)
    body = {"user_id": member_id, "wrapped_key": wrapped_key_b64()}

    first = client.post(f"/channels/{channel['id']}/keys", json=body, headers=headers)
    second = client.post(f"/channels/{channel['id']}/keys", json=body, headers=headers)

    assert first.status_code == 201, first.text
    # Un client qui n'a pas vu l'accusé renvoi la même enveloppe ; il ne doit pas
    # obtenir une erreur, mais le même résultat.
    assert second.status_code == 201, second.text
    assert first.json()["wrapped_key"] == second.json()["wrapped_key"]


def test_deposer_pour_un_non_membre_est_refuse(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)

    response = client.post(
        f"/channels/{channel['id']}/keys",
        json={"user_id": dummy_object_id(), "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )
    assert response.status_code == 409, response.text


def test_une_enveloppe_de_taille_implausible_est_refusee(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)
    tiny = base64.b64encode(b"trop-court").decode("ascii")

    response = client.post(
        f"/channels/{channel['id']}/keys",
        json={"user_id": channel["members"][0]["id"], "wrapped_key": tiny},
        headers=csrf_headers(client),
    )
    assert response.status_code == 422, response.text


def test_le_serveur_ne_detient_aucune_cle_de_salon_en_clair(client: TestClient) -> None:
    """Invariant de régression, à ne jamais faire échouer.

    Le canal et son enveloppe sont les deux seules choses que le serveur détient.
    Aucune ne doit contenir quoi que ce soit d'exploitable.
    """
    register_user(client)
    channel = create_channel(client)
    client.post(
        f"/channels/{channel['id']}/keys",
        json={"user_id": channel["members"][0]["id"], "wrapped_key": wrapped_key_b64()},
        headers=csrf_headers(client),
    )

    mongo = sync_database()
    try:
        database = mongo[get_settings().mongo_db_name]
        keys = list(database.channel_keys.find({}))
    finally:
        mongo.close()

    assert keys, "L'enveloppe n'a pas été enregistrée."
    stored = keys[0]
    assert set(stored) >= {"wrapped_key", "user_id", "channel_id", "key_version"}
    # Aucun champ ne doit ressembler à une clé de salon utilisable telle quelle.
    for field, value in stored.items():
        assert field not in {"key", "room_key", "channel_key", "secret"}
        if isinstance(value, str) and field not in {"_id", "user_id", "channel_id"}:
            assert value == wrapped_key_b64()
