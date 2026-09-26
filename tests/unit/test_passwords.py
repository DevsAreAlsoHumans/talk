from app.security.passwords import hash_password, validate_password_strength, verify_password


def test_hash_and_verify_roundtrip() -> None:
    """Un mot de passe haché ne doit jamais être stocké/comparé en clair."""
    password = "Sup3r$ecretPass!"
    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("wrong-password", hashed) is False


def test_validate_password_strength_rejects_short_password() -> None:
    assert validate_password_strength("Short1!") is not None


def test_validate_password_strength_rejects_missing_uppercase() -> None:
    assert validate_password_strength("nouppercase123!") is not None


def test_validate_password_strength_rejects_missing_special_char() -> None:
    assert validate_password_strength("NoSpecialChar123") is not None


def test_validate_password_strength_accepts_strong_password() -> None:
    assert validate_password_strength("Sup3r$ecretPass!") is None
