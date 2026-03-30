from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

from db.repository import TopoLiteRepository

if TYPE_CHECKING:
    from configuration import AuthConfig


PBKDF2_ITERATIONS = 600_000


@dataclass(slots=True, frozen=True)
class AuthenticatedUser:
    id: int
    username: str
    role: str
    auth_method: str


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, encoded_password: str) -> bool:
    algorithm, iterations_text, salt, expected_digest = encoded_password.split("$", 3)
    if algorithm != "pbkdf2_sha256":
        return False
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        int(iterations_text),
    ).hex()
    return hmac.compare_digest(digest, expected_digest)


def hash_api_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def bootstrap_local_auth(repository: TopoLiteRepository, config: "AuthConfig") -> None:
    if not config.enabled:
        return
    admin = repository.upsert_user(
        username=config.admin_username,
        password_hash=hash_password(config.admin_password),
        role="admin",
    )
    repository.upsert_api_token(
        user_id=int(admin["id"]),
        token_hash=hash_api_token(config.admin_api_token),
        label="bootstrap-admin",
    )

    readonly = repository.upsert_user(
        username=config.readonly_username,
        password_hash=hash_password(config.readonly_password),
        role="read-only",
    )
    repository.upsert_api_token(
        user_id=int(readonly["id"]),
        token_hash=hash_api_token(config.readonly_api_token),
        label="bootstrap-readonly",
    )


def build_authenticated_user(user_row: dict[str, object], auth_method: str) -> AuthenticatedUser:
    return AuthenticatedUser(
        id=int(user_row["id"]),
        username=str(user_row["username"]),
        role=str(user_row["role"]),
        auth_method=auth_method,
    )
