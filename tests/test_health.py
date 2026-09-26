"""Tests de l'ossature de l'application Talk."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_status_ok() -> None:
    """GET /health doit répondre 200 avec {"status": "ok"}."""
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
