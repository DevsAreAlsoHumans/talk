#!/usr/bin/env python3
"""
Test manuel simple pour vérifier la logique du backend Talk.
Ce script ne nécessite pas pytest ni de dépendances externes.
"""

import sys
import os

# Ajouter le répertoire parent au path pour importer app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security import SecurityUtils
from app.models import RoomType, MessageType, UserRole, MemberRole, MessageType


def test_security_utils():
    """Test des utilitaires de sécurité."""
    print("=== Test SecurityUtils ===")
    
    # Test hash password
    password = "test_password_123"
    hashed = SecurityUtils.hash_password(password)
    assert hashed != password, "Hash should differ from password"
    assert SecurityUtils.verify_password(password, hashed) is True, "Valid password should verify"
    assert SecurityUtils.verify_password("wrong", hashed) is False, "Wrong password should fail"
    print("✓ Password hashing/verification")
    
    # Test token creation/verification
    token = SecurityUtils.create_access_token(data={"sub": "user_123"})
    payload = SecurityUtils.verify_token(token)
    assert payload["sub"] == "user_123", "Token should contain user ID"
    print("✓ JWT token creation/verification")
    
    # Test invalid token
    try:
        SecurityUtils.verify_token("invalid_token")
        assert False, "Should have raised exception"
    except Exception:
        pass
    print("✓ Invalid token rejection")
    
    # Test CSRF token
    csrf = SecurityUtils.generate_csrf_token()
    assert len(csrf) >= 32, "CSRF token should be long enough"
    assert SecurityUtils.validate_csrf_token(csrf) is True
    assert SecurityUtils.validate_csrf_token("short") is False
    print("✓ CSRF token generation/validation")
    
    # Test sanitize
    malicious = "<script>alert('xss')</script>"
    sanitized = SecurityUtils.sanitize_input(malicious)
    assert "<script>" not in sanitized, "Script tags should be removed"
    print("✓ XSS sanitization")
    
    # Test truncation
    long_input = "a" * 2000
    truncated = SecurityUtils.sanitize_input(long_input, max_length=100)
    assert len(truncated) == 100, "Should truncate to max_length"
    print("✓ Input truncation")
    
    return True


def test_models():
    """Test des modèles Pydantic."""
    print("\n=== Test Models ===")
    
    # Test UserCreate
    user_data = UserCreate(username="test", email="test@example.com", password="pass123")
    assert user_data.username == "test"
    assert user_data.email == "test@example.com"
    print("✓ UserCreate model")
    
    # Test RoomCreate
    room_data = RoomCreate(
        name="Test Room",
        description="Description",
        room_type=RoomType.CHANNEL,
        is_private=False
    )
    assert room_data.name == "Test Room"
    assert room_data.room_type == RoomType.CHANNEL
    print("✓ RoomCreate model")
    
    # Test MessageCreate
    msg_data = MessageCreate(
        room_id="room_123",
        content="Hello",
        message_type=MessageType.TEXT,
        encrypted=True
    )
    assert msg_data.room_id == "room_123"
    assert msg_data.content == "Hello"
    print("✓ MessageCreate model")
    
    # Test enums
    assert RoomType.CHANNEL.value == "channel"
    assert RoomType.SERVER.value == "server"
    assert MessageType.TEXT.value == "text"
    assert UserRole.MEMBER.value == "member"
    assert MemberRole.OWNER.value == "owner"
    print("✓ All enums")
    
    return True


def test_app_imports():
    """Test que l'application peut être importée."""
    print("\n=== Test App Imports ===")
    
    from app.main import app
    from app.config import settings
    from app.database import get_redis, close_redis
    
    assert app is not None, "FastAPI app should import"
    assert settings is not None, "Settings should import"
    print("✓ FastAPI app imports")
    print("✓ Config imports")
    print("✓ Database imports")
    
    return True


def test_router_imports():
    """Test que les routes peuvent être importées."""
    print("\n=== Test Router Imports ===")
    
    from app.routers import auth, rooms, messages, websocket
    
    assert auth.router is not None
    assert rooms.router is not None
    assert messages.router is not None
    assert websocket.router is not None
    print("✓ All router modules import")
    
    return True


def main():
    """Exécute tous les tests."""
    print("🧪 Démarrage des tests manuels Talk\n")
    
    tests = [
        test_security_utils,
        test_models,
        test_app_imports,
        test_router_imports,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"❌ ÉCHEC {test.__name__}: {e}")
            failed += 1
    
    print(f"\n{'='*40}")
    print(f"Résultats: {passed} réussis, {failed} échoués")
    
    if failed == 0:
        print("✅ Tous les tests manuels passent !")
        return 0
    else:
        print("❌ Certains tests ont échoué")
        return 1


if __name__ == "__main__":
    sys.exit(main())