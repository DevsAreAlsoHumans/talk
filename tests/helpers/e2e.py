"""Client de référence du protocole de chiffrement de bout en bout, écrit en Python.

Il reproduit exactement ce que fait ``frontend/js/crypto.js`` dans le navigateur. Les tests
s'en servent pour jouer le rôle de « vrais clients » : le serveur ne reçoit que ce que
recevrait un navigateur (clés publiques, clés enveloppées, texte chiffré).

Protocole (voir README) :
  - dérivation  : PBKDF2-SHA256(mot de passe, sel="talk-e2e-v1:<pseudo>") → HKDF
                  → clé d'enveloppe (info "talk-wrap-key") et secret d'authentification
                  (info "talk-auth-secret") ;
  - identité    : paire ECDH P-256 ; la clé privée (PKCS8) est chiffrée en AES-GCM avec la
                  clé d'enveloppe avant d'être confiée au serveur ;
  - clé de salon: AES-256 aléatoire, enveloppée pour chaque membre (ECDH éphémère → HKDF → AES-GCM) ;
  - message     : AES-GCM, IV aléatoire de 12 octets, AAD = "<room_id>:<sender_id>".
Le même schéma chiffre les octets des médias et avatars (``encrypt_bytes``/``decrypt_bytes``),
le texte n'étant qu'un cas particulier.
"""

import base64
import os
import unicodedata
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

TEST_ITERATIONS = 1000  # 600 000 dans le navigateur ; le serveur ignore ce paramètre.
PRIVATE_KEY_AAD = b"talk-private-key"
ROOM_KEY_AAD = b"talk-room-key"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def _hkdf(secret: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret)


def derive_keys(password: str, username: str, iterations: int = TEST_ITERATIONS) -> tuple[bytes, str]:
    """Renvoie (clé d'enveloppe, secret d'authentification en base64)."""
    master = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=f"talk-e2e-v1:{username}".encode(),
        iterations=iterations,
    ).derive(unicodedata.normalize("NFKC", password).encode())
    return _hkdf(master, b"talk-wrap-key"), b64(_hkdf(master, b"talk-auth-secret"))


def public_key_b64(public_key: ec.EllipticCurvePublicKey) -> str:
    return b64(
        public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    )


def _load_public_key(text: str) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64(text))


def encrypt_private_key(private_key: ec.EllipticCurvePrivateKey, wrap_key: bytes) -> str:
    pkcs8 = private_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    iv = os.urandom(12)
    return b64(iv + AESGCM(wrap_key).encrypt(iv, pkcs8, PRIVATE_KEY_AAD))


def decrypt_private_key(blob: str, wrap_key: bytes) -> ec.EllipticCurvePrivateKey:
    raw = unb64(blob)
    pkcs8 = AESGCM(wrap_key).decrypt(raw[:12], raw[12:], PRIVATE_KEY_AAD)
    return serialization.load_der_private_key(pkcs8, password=None)


def generate_room_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def wrap_room_key(room_key: bytes, recipient_public_key: str) -> dict[str, str]:
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    shared = ephemeral.exchange(ec.ECDH(), _load_public_key(recipient_public_key))
    iv = os.urandom(12)
    wrapped = AESGCM(_hkdf(shared, b"talk-room-key-wrap")).encrypt(iv, room_key, ROOM_KEY_AAD)
    return {
        "ephemeral_public_key": public_key_b64(ephemeral.public_key()),
        "iv": b64(iv),
        "wrapped_key": b64(wrapped),
    }


def unwrap_room_key(wrapped: dict[str, str], private_key: ec.EllipticCurvePrivateKey) -> bytes:
    shared = private_key.exchange(ec.ECDH(), _load_public_key(wrapped["ephemeral_public_key"]))
    return AESGCM(_hkdf(shared, b"talk-room-key-wrap")).decrypt(
        unb64(wrapped["iv"]), unb64(wrapped["wrapped_key"]), ROOM_KEY_AAD
    )


def encrypt_bytes(room_key: bytes, data: bytes, room_id: str, sender_id: str) -> dict[str, str]:
    """Chiffre des octets quelconques (média, avatar) avec la clé du salon."""
    iv = os.urandom(12)
    ciphertext = AESGCM(room_key).encrypt(iv, data, f"{room_id}:{sender_id}".encode())
    return {"iv": b64(iv), "ciphertext": b64(ciphertext)}


def decrypt_bytes(room_key: bytes, message: dict) -> bytes:
    aad = f"{message['room_id']}:{message['sender_id']}".encode()
    return AESGCM(room_key).decrypt(unb64(message["iv"]), unb64(message["ciphertext"]), aad)


def encrypt_message(room_key: bytes, plaintext: str, room_id: str, sender_id: str) -> dict[str, str]:
    return encrypt_bytes(room_key, plaintext.encode(), room_id, sender_id)


def decrypt_message(room_key: bytes, message: dict) -> str:
    return decrypt_bytes(room_key, message).decode()


@dataclass
class Identity:
    """Ce que le navigateur d'un utilisateur détient : jamais envoyé tel quel au serveur."""

    username: str
    password: str
    private_key: ec.EllipticCurvePrivateKey
    wrap_key: bytes
    auth_secret: str

    @classmethod
    def create(cls, username: str, password: str = "un mot de passe très solide") -> "Identity":
        wrap_key, auth_secret = derive_keys(password, username)
        return cls(username, password, ec.generate_private_key(ec.SECP256R1()), wrap_key, auth_secret)

    @property
    def public_key(self) -> str:
        return public_key_b64(self.private_key.public_key())

    def registration_payload(self) -> dict[str, str]:
        return {
            "username": self.username,
            "auth_secret": self.auth_secret,
            "public_key": self.public_key,
            "encrypted_private_key": encrypt_private_key(self.private_key, self.wrap_key),
        }
