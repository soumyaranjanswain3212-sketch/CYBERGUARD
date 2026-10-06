from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass

PASSWORD_HASH_SCHEME = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 600_000
SESSION_COOKIE_NAME = "cyberguard_session"
SESSION_MAX_AGE_SECONDS = 8 * 60 * 60


class AuthenticationConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class AnalystSession:
    username: str
    csrf_token: str


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str, salt: bytes | None = None) -> str:
    if len(password) < 12:
        raise ValueError("Analyst password must be at least 12 characters.")
    actual_salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        actual_salt,
        PASSWORD_HASH_ITERATIONS,
    )
    return (
        f"{PASSWORD_HASH_SCHEME}${PASSWORD_HASH_ITERATIONS}"
        f"${_b64encode(actual_salt)}${_b64encode(digest)}"
    )


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        scheme, iteration_text, encoded_salt, encoded_digest = encoded_hash.split("$", 3)
        iterations = int(iteration_text)
        if scheme != PASSWORD_HASH_SCHEME or not 100_000 <= iterations <= 2_000_000:
            return False
        salt = _b64decode(encoded_salt)
        expected_digest = _b64decode(encoded_digest)
    except (ValueError, TypeError, binascii.Error):
        return False

    actual_digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=len(expected_digest),
    )
    return hmac.compare_digest(actual_digest, expected_digest)


def _password_hash_is_configured(encoded_hash: str) -> bool:
    try:
        scheme, iteration_text, encoded_salt, encoded_digest = encoded_hash.split("$", 3)
        iterations = int(iteration_text)
        salt = _b64decode(encoded_salt)
        digest = _b64decode(encoded_digest)
    except (ValueError, TypeError, binascii.Error):
        return False
    return (
        scheme == PASSWORD_HASH_SCHEME
        and 100_000 <= iterations <= 2_000_000
        and len(salt) >= 16
        and len(digest) == 32
    )


def _configuration() -> tuple[str, str, bytes]:
    username = os.getenv("CYBERGUARD_ANALYST_USERNAME", "").strip()
    password_hash = os.getenv("CYBERGUARD_ANALYST_PASSWORD_HASH", "")
    secret = os.getenv("CYBERGUARD_SESSION_SECRET", "")
    if not username or len(username) > 80:
        raise AuthenticationConfigurationError(
            "Set CYBERGUARD_ANALYST_USERNAME to a non-empty username of at most 80 characters."
        )
    if not _password_hash_is_configured(password_hash):
        raise AuthenticationConfigurationError(
            "Set CYBERGUARD_ANALYST_PASSWORD_HASH using the local password-hash utility."
        )
    if len(secret.encode("utf-8")) < 32:
        raise AuthenticationConfigurationError(
            "Set CYBERGUARD_SESSION_SECRET to a random secret of at least 32 bytes."
        )
    return username, password_hash, secret.encode("utf-8")


def authentication_ready() -> bool:
    try:
        _configuration()
    except AuthenticationConfigurationError:
        return False
    return True


def authenticate(username: str, password: str) -> bool:
    configured_username, password_hash, _ = _configuration()
    username_matches = hmac.compare_digest(
        username.strip().encode("utf-8"),
        configured_username.encode("utf-8"),
    )
    password_matches = verify_password(password, password_hash)
    return username_matches and password_matches


def create_session(username: str) -> tuple[str, AnalystSession]:
    _, _, secret = _configuration()
    csrf_token = secrets.token_urlsafe(32)
    payload = {
        "username": username,
        "csrf": csrf_token,
        "expires": int(time.time()) + SESSION_MAX_AGE_SECONDS,
    }
    encoded_payload = _b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signature = _b64encode(
        hmac.new(secret, encoded_payload.encode("ascii"), hashlib.sha256).digest()
    )
    return f"{encoded_payload}.{signature}", AnalystSession(username, csrf_token)


def read_session(cookie_value: str | None) -> AnalystSession | None:
    if not cookie_value:
        return None
    try:
        encoded_payload, supplied_signature = cookie_value.split(".", 1)
        username, _, secret = _configuration()
        expected_signature = _b64encode(
            hmac.new(secret, encoded_payload.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return None
        payload = json.loads(_b64decode(encoded_payload))
        if (
            payload.get("username") != username
            or not isinstance(payload.get("csrf"), str)
            or int(payload.get("expires", 0)) <= int(time.time())
        ):
            return None
        return AnalystSession(username, payload["csrf"])
    except (ValueError, TypeError, json.JSONDecodeError, binascii.Error):
        return None


def session_cookie_secure() -> bool:
    configured = os.getenv("CYBERGUARD_COOKIE_SECURE", "false").strip().casefold()
    if configured not in {"true", "false"}:
        raise AuthenticationConfigurationError(
            "CYBERGUARD_COOKIE_SECURE must be either true or false."
        )
    return configured == "true"
