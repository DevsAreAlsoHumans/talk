from datetime import timedelta

from app.auth.service import create_access_token, decode_access_token, hash_password, verify_password


def test_hash_and_verify_password():
    hashed = hash_password("MySecretP@ss1")
    assert hashed != "MySecretP@ss1"
    assert verify_password("MySecretP@ss1", hashed) is True


def test_verify_wrong_password():
    hashed = hash_password("MySecretP@ss1")
    assert verify_password("WrongPassword", hashed) is False


def test_create_and_decode_access_token():
    token = create_access_token({"sub": "user123"})
    payload = decode_access_token(token)
    assert payload["sub"] == "user123"
    assert "exp" in payload


def test_decode_invalid_token():
    result = decode_access_token("invalid.token.here")
    assert result is None


def test_decode_expired_token():
    token = create_access_token({"sub": "user123"}, expires_delta=timedelta(seconds=-1))
    result = decode_access_token(token)
    assert result is None
