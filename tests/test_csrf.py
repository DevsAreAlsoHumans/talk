"""Protection CSRF : bootstrap, absence, erreur et rejet entre sessions."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, SESSION_COOKIE_NAME
from tests.conftest import (
    VALID_PASSWORD,
    create_server,
    csrf_headers,
    login_user,
    register_user,
    set_cookie_attributes,
    unique_username,
)

# L'adhésion est la mutation la plus exposée du lot : elle change la composition
# d'un serveur, et son chemin ne peut pas être écrit en dur, puisque le
# `server_id` n'existe qu'une fois le serveur créé. L'entrée est donc un gabarit,
# rendu applicable par `resolve_mutation` — voir `preparer_adhesion`.
ADHESION = "/servers/{server_id}/members"
MEMBRE = "invite"

MUTATIONS = [
    ("/auth/register", {"username": "x", "password": VALID_PASSWORD}),
    ("/auth/login", {"username": "x", "password": "y"}),
    ("/auth/logout", {}),
    (ADHESION, {"username": MEMBRE}),
]


def preparer_adhesion(client: TestClient) -> tuple[str, dict[str, str], str]:
    """Rend l'adhésion possible, pour que le CSRF soit la seule variable.

    Trois conditions sont nécessaires, faute de quoi la route répond 404 ou 403
    pour une tout autre raison : un serveur doit exister, le nom désigné doit
    être inscrit, et l'appelant doit être le créateur. Les trois sont posées ici,
    et le client est rendu au créateur — un 403 de ces tests doit venir du jeton,
    jamais des droits.
    """
    createur = register_user(client)
    serveur = create_server(client)
    client.cookies.clear()
    register_user(client, MEMBRE)
    client.cookies.clear()
    login_user(client, createur)
    return ADHESION.format(server_id=serveur["id"]), {"username": MEMBRE}, createur


def resolve_mutation(
    client: TestClient, path: str, payload: dict[str, str]
) -> tuple[str, dict[str, str]]:
    """Rend une entrée de `MUTATIONS` applicable telle quelle.

    Les routes d'authentification sont fixes ; seule l'adhésion a besoin d'être
    préparée, et seulement parce que son chemin porte un identifiant créé à la
    demande.
    """
    if path != ADHESION:
        return path, payload
    chemin, _charge, _createur = preparer_adhesion(client)
    return chemin, payload


def test_csrf_endpoint_sets_both_cookies(client: TestClient) -> None:
    response = client.get("/auth/csrf")

    assert response.status_code == 200
    assert response.json()["csrf_token"]
    assert client.cookies.get(SESSION_COOKIE_NAME)
    assert client.cookies.get(CSRF_COOKIE_NAME) == response.json()["csrf_token"]


def test_session_cookie_is_httponly_and_csrf_cookie_is_not(client: TestClient) -> None:
    """La session porte le pouvoir et reste inaccessible au JS ; le CSRF doit
    rester lisible, sans quoi le double-submit est impossible."""
    response = client.get("/auth/csrf")

    session_cookie = set_cookie_attributes(response, SESSION_COOKIE_NAME)
    csrf_cookie = set_cookie_attributes(response, CSRF_COOKIE_NAME)

    assert "httponly" in session_cookie.lower()
    assert "samesite=lax" in session_cookie.lower()
    assert "httponly" not in csrf_cookie.lower()
    assert "samesite=lax" in csrf_cookie.lower()


def test_csrf_response_is_not_cacheable(client: TestClient) -> None:
    response = client.get("/auth/csrf")

    assert response.headers["cache-control"] == "no-store"


def test_csrf_is_idempotent(client: TestClient) -> None:
    """Un second appel renvoie le même jeton : un autre onglet ne casse rien."""
    first = client.get("/auth/csrf").json()["csrf_token"]
    second = client.get("/auth/csrf").json()["csrf_token"]

    assert first == second


@pytest.mark.parametrize(("path", "payload"), MUTATIONS)
def test_mutation_without_csrf_header_is_forbidden(
    client: TestClient, path: str, payload: dict[str, str]
) -> None:
    path, payload = resolve_mutation(client, path, payload)
    client.get("/auth/csrf")

    response = client.post(path, json=payload)

    assert response.status_code == 403
    # Un 403 d'autorité serait un faux positif : l'appelant de l'adhésion est
    # volontairement le créateur, pour que seule l'absence de jeton puisse le
    # refuser.
    assert "Jeton CSRF" in response.text, response.text


@pytest.mark.parametrize(("path", "payload"), MUTATIONS)
def test_mutation_with_wrong_csrf_token_is_forbidden(
    client: TestClient, path: str, payload: dict[str, str]
) -> None:
    path, payload = resolve_mutation(client, path, payload)
    client.get("/auth/csrf")

    response = client.post(
        path, json=payload, headers={CSRF_HEADER_NAME: "jeton-invente-000000000"}
    )

    assert response.status_code == 403
    assert "Jeton CSRF" in response.text, response.text


def test_adhesion_avec_un_csrf_valide_reussit(client: TestClient) -> None:
    """Le contrepoint des deux tests ci-dessus, sur la route d'adhésion.

    Sans lui, un 403 serait le seul résultat connu de cette mutation, et un garde
    qui refuserait tout — jeton compris — passerait les trois.
    """
    chemin, charge, _createur = preparer_adhesion(client)

    response = client.post(chemin, json=charge, headers=csrf_headers(client))

    assert response.status_code == 200, response.text
    assert MEMBRE in {membre["username"] for membre in response.json()["members"]}


def test_adhesion_avec_le_csrf_d_une_autre_session_est_refusee(client: TestClient) -> None:
    """Un jeton valide mais émis pour une autre session ne vaut rien non plus.

    Même utilisateur, deux sessions : c'est ce qui distingue le jeton de ce qu'un
    site tiers pourrait deviner. Il n'a pas la session, donc le jeton qu'il
    produit — ou qu'il copie d'un site tiers — ne correspond à rien.
    """
    chemin, charge, createur = preparer_adhesion(client)
    vole = client.get("/auth/csrf").json()["csrf_token"]

    # Nouvelle session pour le même compte : le jeton de l'ancienne ne suit pas.
    client.cookies.clear()
    login_user(client, createur)
    assert client.get("/auth/csrf").json()["csrf_token"] != vole

    response = client.post(chemin, json=charge, headers={CSRF_HEADER_NAME: vole})

    assert response.status_code == 403
    assert "Jeton CSRF" in response.text, response.text


def test_csrf_token_from_another_session_is_forbidden(client: TestClient) -> None:
    """Le jeton est lu dans la session de l'appelant : celui d'autrui ne vaut rien."""
    stolen = client.get("/auth/csrf").json()["csrf_token"]

    # Jar vierge : le client devient la « victime », avec une session qui lui est propre.
    client.cookies.clear()
    own = csrf_headers(client)[CSRF_HEADER_NAME]
    assert own != stolen

    response = client.post(
        "/auth/register",
        json={"username": unique_username(), "password": VALID_PASSWORD},
        headers={CSRF_HEADER_NAME: stolen},
    )

    assert response.status_code == 403


def test_mutation_with_valid_csrf_succeeds(client: TestClient) -> None:
    response = client.post(
        "/auth/register",
        json={"username": unique_username(), "password": VALID_PASSWORD},
        headers=csrf_headers(client),
    )

    assert response.status_code == 201


def test_reads_do_not_require_csrf(client: TestClient) -> None:
    client.get("/auth/csrf")

    assert client.get("/health").status_code == 200
    assert client.get("/auth/me").status_code == 401


def test_csrf_rejected_without_any_session(client: TestClient) -> None:
    """Un jeton présenté sans cookie de session n'a aucune valeur attendue."""
    response = client.post(
        "/auth/login",
        json={"username": "quelquun", "password": "peu-importe"},
        headers={CSRF_HEADER_NAME: "jeton-sans-session-000000000000"},
    )

    assert response.status_code == 403


def test_csrf_token_survives_a_fresh_page_load(client: TestClient) -> None:
    register_user(client)
    token = client.get("/auth/csrf").json()["csrf_token"]

    response = client.post("/auth/logout", headers={CSRF_HEADER_NAME: token})

    assert response.status_code == 204
