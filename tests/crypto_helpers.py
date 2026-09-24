import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def new_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _unsigned_bytes(value):
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def public_key_jwk(public_key):
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "n": _b64url(_unsigned_bytes(numbers.n)),
        "e": _b64url(_unsigned_bytes(numbers.e)),
        "alg": "RSA-OAEP-256",
    }


def wrap_channel_key(aes_key, public_key):
    wrapped = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(wrapped).decode()


def unwrap_channel_key(wrapped_b64, private_key):
    wrapped = base64.b64decode(wrapped_b64)
    return private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def encrypt_message(plaintext, aes_key):
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext + encryptor.tag).decode(),
    }


def decrypt_message(payload, aes_key):
    iv = base64.b64decode(payload["iv"])
    raw = base64.b64decode(payload["ciphertext"])
    ciphertext, tag = raw[:-16], raw[-16:]
    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()