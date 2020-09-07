import bcrypt
import secrets

from .config import config


def hash_secret(secret: str, bcrypt_cost: int = config().secret_bcrypt_cost):
    return bcrypt.hashpw(
        secret.encode("utf-8"), bcrypt.gensalt(rounds=bcrypt_cost)
    )


def make_secret_string(byte_count: int):
    return secrets.token_urlsafe(byte_count)
