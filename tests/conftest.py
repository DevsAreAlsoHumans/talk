import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import create_app


@pytest.fixture(autouse=True)
def _settings() -> None:
    get_settings.cache_clear()


@pytest.fixture
def settings() -> object:
    return get_settings()


@pytest.fixture
def client(settings) -> TestClient:
    return TestClient(create_app())
