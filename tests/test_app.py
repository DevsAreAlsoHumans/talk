"""
Test suite for the Talk application.
Tests unitaires et d'intégration pour le backend FastAPI.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.security import SecurityUtils
from app.models import RoomType, MessageType


# Fixtures
@pytest.fixture
def client():
    """Crée un client de test FastAPI."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def test_user():
    """Utilisateur de test."""
    return {
        "username": "test_user",
        "email": "test@example.com",
        "password": "securepassword123"
    }


@pytest.fixture
def auth_header(client, test_user):
    """Retourne l'header Authorization avec le token."""
    # Inscription
    client.post("/api/auth/register", json=test_user)
    
    # Login
    login_data = {
        "email": test_user["email"],
        "password": test_user["password"]
    }
    login_response = client.post("/api/auth/login", json=login_data)
    
    token = login_response.json().get("access_token")
    
    return {"Authorization": f"Bearer {token}"}


def create_test_server(client, auth_header):
    response = client.post(
        "/api/rooms/",
        json={"name": "Test Server", "room_type": RoomType.SERVER.value},
        headers=auth_header,
    )
    assert response.status_code == 201
    return response.json()["id"]


# Tests d'authentification
class TestAuth:
    """Tests pour le module d'authentification."""

    def test_register_user(self, client, test_user):
        """Test d'inscription d'un nouvel utilisateur."""
        response = client.post("/api/auth/register", json=test_user)
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == test_user["username"]
        assert data["email"] == test_user["email"]
        assert "id" in data

    def test_register_duplicate_email(self, client, test_user):
        """Test d'inscription avec un email déjà utilisé."""
        client.post("/api/auth/register", json=test_user)
        response = client.post("/api/auth/register", json=test_user)
        assert response.status_code == 400

    def test_login_success(self, client, test_user):
        """Test de connexion réussie."""
        # D'abord inscrire
        client.post("/api/auth/register", json=test_user)
        
        # Puis se connecter
        login_data = {
            "email": test_user["email"],
            "password": test_user["password"]
        }
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == test_user["email"]
        assert "access_token" in data

    def test_login_wrong_password(self, client, test_user):
        """Test de connexion avec un mot de passe incorrect."""
        # D'abord inscrire
        client.post("/api/auth/register", json=test_user)
        
        # Essayer de se connecter avec mauvais mot de passe
        login_data = {
            "email": test_user["email"],
            "password": "wrongpassword"
        }
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 401

    def test_get_current_user(self, client, auth_header):
        """Test de récupération de l'utilisateur connecté."""
        response = client.get("/api/auth/me", headers=auth_header)
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "test@example.com"

    def test_csrf_token_generation(self, client):
        """Test de génération du token CSRF."""
        response = client.get("/api/auth/csrf-token")
        assert response.status_code == 200
        data = response.json()
        assert "csrf_token" in data
        assert len(data["csrf_token"]) >= 32


# Tests des salons (rooms)
class TestRooms:
    """Tests pour les salons de discussion."""

    def test_list_rooms(self, client):
        """Test de liste des salons publics."""
        response = client.get("/api/rooms/")
        assert response.status_code == 200

    def test_get_room_not_found(self, client, auth_header):
        """Test de récupération d'un salon inexistant."""
        response = client.get("/api/rooms/nonexistent-room-id", headers=auth_header)
        assert response.status_code == 404

    def test_create_room(self, client, auth_header):
        """Test de création d'un salon."""
        server_id = create_test_server(client, auth_header)
        room_data = {
            "name": "Test Room",
            "room_type": RoomType.CHANNEL.value,
            "is_private": False,
            "parent_server": server_id,
        }
        response = client.post("/api/rooms/", json=room_data, headers=auth_header)
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Test Room"
        assert data["room_type"] == "channel"

    def test_update_room(self, client, auth_header):
        """Test de mise à jour d'un salon."""
        # Créer d'abord un salon
        server_id = create_test_server(client, auth_header)
        room_data = {
            "name": "Room to Update",
            "room_type": RoomType.CHANNEL.value,
            "is_private": False,
            "parent_server": server_id,
        }
        create_response = client.post("/api/rooms/", json=room_data, headers=auth_header)
        assert create_response.status_code == 201
        room_id = create_response.json()["id"]

        # Mettre à jour
        update_data = {
            "name": "Updated Room",
            "room_type": RoomType.CHANNEL.value,
            "is_private": False,
            "parent_server": server_id,
        }
        update_response = client.put(f"/api/rooms/{room_id}", json=update_data, headers=auth_header)
        assert update_response.status_code == 200
        assert update_response.json()["name"] == "Updated Room"

    def test_delete_room(self, client, auth_header):
        """Test de suppression d'un salon."""
        # Créer d'abord un salon
        server_id = create_test_server(client, auth_header)
        room_data = {
            "name": "Room to Delete",
            "room_type": RoomType.CHANNEL.value,
            "is_private": False,
            "parent_server": server_id,
        }
        create_response = client.post("/api/rooms/", json=room_data, headers=auth_header)
        assert create_response.status_code == 201
        room_id = create_response.json()["id"]

        # Supprimer
        delete_response = client.delete(f"/api/rooms/{room_id}", headers=auth_header)
        assert delete_response.status_code == 200

        # Vérifier que le salon est supprimé
        get_response = client.get(f"/api/rooms/{room_id}", headers=auth_header)
        assert get_response.status_code == 404


# Tests des messages
class TestMessages:
    """Tests pour les messages."""

    def test_send_message(self, client, auth_header):
        """Test d'envoi d'un message."""
        # Créer d'abord un salon
        server_id = create_test_server(client, auth_header)
        room_data = {
            "name": "Test Room for Messages",
            "room_type": RoomType.CHANNEL.value,
            "is_private": False,
            "parent_server": server_id,
        }
        room_response = client.post("/api/rooms/", json=room_data, headers=auth_header)
        room_id = room_response.json()["id"]

        # Envoyer un message
        message_data = {
            "room_id": room_id,
            "content": "Hello, world!",
            "message_type": MessageType.TEXT.value,
            "encrypted": True
        }
        response = client.post("/api/messages/", json=message_data, headers=auth_header)
        assert response.status_code == 201
        data = response.json()
        assert data["content"] == "Hello, world!"

    def test_list_messages(self, client, auth_header):
        """Test de liste des messages d'un salon."""
        # Créer un salon
        server_id = create_test_server(client, auth_header)
        room_data = {
            "name": "Messages Room",
            "room_type": RoomType.CHANNEL.value,
            "is_private": False,
            "parent_server": server_id,
        }
        room_response = client.post("/api/rooms/", json=room_data, headers=auth_header)
        room_id = room_response.json()["id"]

        # Envoyer quelques messages
        for i in range(3):
            message_data = {
                "room_id": room_id,
                "content": f"Message {i+1}",
                "message_type": MessageType.TEXT.value,
                "encrypted": True
            }
            client.post("/api/messages/", json=message_data, headers=auth_header)

        # Lister les messages
        response = client.get(f"/api/messages/room/{room_id}", headers=auth_header)
        assert response.status_code == 200
        messages = response.json()
        assert len(messages) == 3


# Tests de sécurité
class TestSecurity:
    """Tests pour la sécurité."""

    def test_password_hashing(self):
        """Test du hachage des mots de passe."""
        password = "test_password_123"
        hashed = SecurityUtils.hash_password(password)
        assert hashed != password
        assert SecurityUtils.verify_password(password, hashed) is True
        assert SecurityUtils.verify_password("wrong_password", hashed) is False

    def test_token_creation_and_verification(self):
        """Test de création et vérification des tokens JWT."""
        token = SecurityUtils.create_access_token(data={"sub": "user_123"})
        payload = SecurityUtils.verify_token(token)
        assert payload["sub"] == "user_123"

    def test_token_with_invalid_data(self):
        """Test de vérification d'un token invalide."""
        with pytest.raises(Exception):
            SecurityUtils.verify_token("invalid_token")

    def test_csrf_token_generation(self):
        """Test de génération des tokens CSRF."""
        token = SecurityUtils.generate_csrf_token()
        assert len(token) >= 32
        assert SecurityUtils.validate_csrf_token(token) is True
        assert SecurityUtils.validate_csrf_token("short") is False

    def test_sanitize_input(self):
        """Test de la sanitisation des entrées."""
        malicious_input = "<script>alert('xss')</script>"
        sanitized = SecurityUtils.sanitize_input(malicious_input)
        assert "<script>" not in sanitized
        assert len(sanitized) < len(malicious_input)

    def test_input_truncation(self):
        """Test de la troncature des entrées longues."""
        long_input = "a" * 2000
        sanitized = SecurityUtils.sanitize_input(long_input, max_length=100)
        assert len(sanitized) == 100


# Tests d'intégration
class TestIntegration:
    """Tests d'intégration."""

    def test_full_workflow(self, client, test_user):
        """Test du flux complet: inscription -> connexion -> création salon."""
        # 1. Inscription
        register_response = client.post("/api/auth/register", json=test_user)
        assert register_response.status_code == 201

        # 2. Connexion
        login_data = {"email": test_user["email"], "password": test_user["password"]}
        login_response = client.post("/api/auth/login", json=login_data)
        assert login_response.status_code == 200
        
        token = login_response.json().get("access_token")
        auth_header = {"Authorization": f"Bearer {token}"}

        # 3. Récupération utilisateur
        user_response = client.get("/api/auth/me", headers=auth_header)
        assert user_response.status_code == 200

        # 4. Création d'un salon
        server_id = create_test_server(client, auth_header)
        room_data = {
            "name": "Integration Test Room",
            "room_type": RoomType.CHANNEL.value,
            "parent_server": server_id,
        }
        room_response = client.post("/api/rooms/", json=room_data, headers=auth_header)
        assert room_response.status_code == 201

        # 5. Envoyer un message
        message_data = {
            "room_id": room_response.json()["id"],
            "content": "Test message",
            "message_type": MessageType.TEXT.value,
            "encrypted": True
        }
        msg_response = client.post("/api/messages/", json=message_data, headers=auth_header)
        assert msg_response.status_code == 201

        # 6. Lister les messages
        list_response = client.get(f"/api/messages/room/{room_response.json()['id']}", headers=auth_header)
        assert list_response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])