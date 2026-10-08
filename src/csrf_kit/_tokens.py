"""Internal token protocol implemented entirely with the Python standard library.

Wire: v1.<unix seconds>.<32 random bytes as hex>.<HMAC-SHA256 hex>.
The MAC also binds a trusted session nonce which is not included in the token.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time

_FORMAT = re.compile(r"v1\.(0|[1-9][0-9]{0,11})\.([0-9a-f]{64})\.([0-9a-f]{64})")
_DOMAIN = b"csrf-kit/token/v1\x00"


class InvalidToken(ValueError):
    """Untrusted token failed validation."""


def _mac(key: bytes, nonce: str, payload: str) -> str:
    binding = nonce.encode("utf-8")
    message = _DOMAIN + len(binding).to_bytes(4, "big") + binding + payload.encode("ascii")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def issue(key: bytes, nonce: str) -> str:
    payload = f"v1.{int(time.time())}.{secrets.token_hex(32)}"
    return f"{payload}.{_mac(key, nonce, payload)}"


def verify(token: str | None, key: bytes, nonce: str, ttl: int) -> None:
    if not isinstance(token, str) or not token:
        raise InvalidToken("The CSRF token is missing.")
    if len(token) > 160 or (match := _FORMAT.fullmatch(token)) is None:
        raise InvalidToken("The CSRF token is malformed.")
    payload, signature = token.rsplit(".", 1)
    if not hmac.compare_digest(signature, _mac(key, nonce, payload)):
        raise InvalidToken("The CSRF token is invalid for this session.")
    age = int(time.time()) - int(match[1])
    if age < 0:
        raise InvalidToken("The CSRF token is from the future.")
    if age > ttl:
        raise InvalidToken("The CSRF token has expired.")
