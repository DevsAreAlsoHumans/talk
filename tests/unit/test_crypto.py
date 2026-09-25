from app.crypto.service import validate_public_key_format


def test_validate_valid_pem():
    key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----"
    assert validate_public_key_format(key) is True


def test_validate_invalid_pem():
    assert validate_public_key_format("not a key") is False
    assert validate_public_key_format("") is False
    assert validate_public_key_format(None) is False
