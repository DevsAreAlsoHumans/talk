from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_docs_are_reachable() -> None:
    """La documentation Swagger (/docs) doit être accessible."""
    response = client.get("/docs")

    assert response.status_code == 200


def test_unknown_route_returns_404() -> None:
    """Une route inexistante doit renvoyer 404, pas une erreur serveur."""
    response = client.get("/route-qui-nexiste-pas")

    assert response.status_code == 404
