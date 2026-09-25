import pytest
from pydantic import ValidationError

from app.auth.models import UserCreate, UserLogin
from app.messages.models import MessageCreate
from app.salons.models import ChannelCreate, MemberRemove

PUB_KEY = "-----BEGIN PUBLIC KEY-----\nMIIBI...\n-----END PUBLIC KEY-----"


def make_user(**overrides):
    data = {
        "username": "alice",
        "email": "alice@example.com",
        "password": "StrongP@ss1",
        "public_key": PUB_KEY,
    }
    data.update(overrides)
    return UserCreate(**data)


# ---------- UserCreate ----------


def test_user_create_valid():
    user = make_user()
    assert user.username == "alice"
    assert user.email == "alice@example.com"
    assert user.website == ""


def test_user_create_short_password():
    with pytest.raises(ValidationError):
        make_user(password="short1")


def test_user_create_password_needs_a_digit():
    with pytest.raises(ValidationError):
        make_user(password="onlyletters")


def test_user_create_password_needs_a_letter():
    with pytest.raises(ValidationError):
        make_user(password="12345678")


def test_user_create_invalid_email():
    with pytest.raises(ValidationError):
        make_user(email="not-an-email")


@pytest.mark.parametrize("username", ["ab", "a" * 31, "espace nom", "accentué", "sym$bole"])
def test_user_create_rejects_bad_usernames(username):
    with pytest.raises(ValidationError):
        make_user(username=username)


def test_user_create_accepts_honeypot_value():
    """Le champ-piège est accepté par le modèle ; c'est la route qui refuse."""
    assert make_user(website="http://spam.example").website == "http://spam.example"


def test_user_login_valid():
    login = UserLogin(username="alice", password="StrongP@ss1")
    assert login.username == "alice"


@pytest.mark.parametrize("payload", [{"$gt": ""}, ["alice"], 42])
def test_user_login_rejects_non_string(payload):
    """Barrage aux injections NoSQL : seuls les types attendus passent."""
    with pytest.raises(ValidationError):
        UserLogin(username=payload, password="x")


# ---------- MessageCreate ----------


def test_message_requires_ciphertext_and_iv():
    with pytest.raises(ValidationError):
        MessageCreate(ciphertext="", iv="iv")


def test_message_ciphertext_is_capped():
    with pytest.raises(ValidationError):
        MessageCreate(ciphertext="A" * 20000, iv="iv")


def test_message_channel_is_optional():
    assert MessageCreate(ciphertext="c", iv="i").channel_id is None


# ---------- Salons ----------


@pytest.mark.parametrize("name", ["général", "annonces", "dev-front", "canal 2"])
def test_channel_names_accepted(name):
    assert ChannelCreate(name=name).name == name


@pytest.mark.parametrize("name", ["", "Majuscule", "#diese", " espace-initial"])
def test_channel_names_rejected(name):
    with pytest.raises(ValidationError):
        ChannelCreate(name=name)


def test_member_remove_defaults_to_empty_rekey():
    assert MemberRemove().rekey == []
