"""Password-based encryption for the secret vault.

The master password never touches disk and is never passed as a CLI
argument or environment variable — it only ever exists inside the GUI
process's memory for the duration of a single dialog.
"""
import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 480_000


class WrongPassword(Exception):
    pass


def new_salt() -> bytes:
    return os.urandom(16)


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt(password: str, salt: bytes, plaintext: bytes) -> bytes:
    return Fernet(_derive_key(password, salt)).encrypt(plaintext)


def decrypt(password: str, salt: bytes, token: bytes) -> bytes:
    try:
        return Fernet(_derive_key(password, salt)).decrypt(token)
    except InvalidToken:
        raise WrongPassword(
            "Incorrect master password (or the vault file is corrupted)."
        ) from None
