import pytest

from app.crypto.service import key_fingerprint, public_key_bytes, validate_public_key_format

KEY_A = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----"
KEY_B = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ9A\n-----END PUBLIC KEY-----"


# ---------- Format ----------


def test_validate_valid_pem():
    assert validate_public_key_format(KEY_A) is True


def test_validate_invalid_pem():
    assert validate_public_key_format("not a key") is False
    assert validate_public_key_format("") is False
    assert validate_public_key_format(None) is False


def test_validate_tolerates_surrounding_whitespace():
    assert validate_public_key_format(f"\n  {KEY_A}  \n") is True


# ---------- Extraction du corps DER ----------


def test_public_key_bytes_decodes_body():
    raw = public_key_bytes(KEY_A)
    assert isinstance(raw, bytes)
    assert len(raw) > 0


def test_public_key_bytes_rejects_bad_format():
    assert public_key_bytes("pas une clé") is None


def test_public_key_bytes_rejects_invalid_base64():
    broken = "-----BEGIN PUBLIC KEY-----\n!!!pas du base64!!!\n-----END PUBLIC KEY-----"
    assert public_key_bytes(broken) is None


# ---------- Empreinte ----------


def test_fingerprint_shape():
    """12 groupes de 5 chiffres, lisibles à voix haute."""
    fp = key_fingerprint(KEY_A)
    groups = fp.split(" ")
    assert len(groups) == 12
    assert all(len(g) == 5 and g.isdigit() for g in groups)


def test_fingerprint_is_deterministic():
    """La même clé donne toujours la même empreinte, sinon la comparaison
    entre deux personnes n'aurait aucun sens."""
    assert key_fingerprint(KEY_A) == key_fingerprint(KEY_A)


def test_fingerprint_ignores_pem_whitespace():
    """Un retour à la ligne de plus ne doit pas changer l'empreinte."""
    compact = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A-----END PUBLIC KEY-----"
    assert key_fingerprint(compact) == key_fingerprint(KEY_A)


def test_different_keys_give_different_fingerprints():
    """Le point entier du dispositif : une clé substituée doit se voir."""
    assert key_fingerprint(KEY_A) != key_fingerprint(KEY_B)


@pytest.mark.parametrize("bad", [None, "", "pas une clé"])
def test_fingerprint_of_invalid_key_is_none(bad):
    assert key_fingerprint(bad) is None
