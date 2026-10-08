"""Protocol tests independent of Flask's request or cookie handling."""

import ast
import hashlib
import hmac
import inspect
import sys

import pytest

from csrf_kit import _tokens

KEY = b"test-only-key"
NONCE = "a" * 64


def signed(payload, key=KEY, nonce=NONCE):
    # Independent reference construction, using the documented wire protocol.
    binding = nonce.encode()
    message = b"csrf-kit/token/v1\0" + len(binding).to_bytes(4, "big") + binding + payload.encode()
    return payload + "." + hmac.new(key, message, hashlib.sha256).hexdigest()


def test_reference_vector(monkeypatch):
    monkeypatch.setattr(_tokens.time, "time", lambda: 1000)
    monkeypatch.setattr(_tokens.secrets, "token_hex", lambda n: "b" * (n * 2))
    token = _tokens.issue(KEY, NONCE)
    assert token == signed("v1.1000." + "b" * 64)
    _tokens.verify(token, KEY, NONCE, 1)


def test_random_each_issue():
    first = _tokens.issue(KEY, NONCE)
    second = _tokens.issue(KEY, NONCE)
    assert first.split(".")[2] != second.split(".")[2]
    assert NONCE not in first
    _tokens.verify(first, KEY, NONCE, 3600)
    _tokens.verify(second, KEY, NONCE, 3600)


@pytest.mark.parametrize("field", [0, 1, 2, 3])
def test_each_field_tampering(field, monkeypatch):
    monkeypatch.setattr(_tokens.time, "time", lambda: 1000)
    parts = _tokens.issue(KEY, NONCE).split(".")
    if field == 0:
        parts[field] = "v2"
    elif field == 1:
        parts[field] = "1001"
    else:
        parts[field] = ("1" if parts[field][0] == "0" else "0") + parts[field][1:]
    with pytest.raises(_tokens.InvalidToken):
        _tokens.verify(".".join(parts), KEY, NONCE, 3600)


@pytest.mark.parametrize("timestamp", ["-1", "+1000", "01000", "1e3", "1.0", "9" * 13, "\u0661"])
def test_signed_noncanonical_timestamps(timestamp, monkeypatch):
    monkeypatch.setattr(_tokens.time, "time", lambda: 1000)
    token = signed(f"v1.{timestamp}." + "c" * 64)
    with pytest.raises(_tokens.InvalidToken):
        _tokens.verify(token, KEY, NONCE, 3600)


@pytest.mark.parametrize("suffix", ["\n", ".extra", " ", "\0"])
def test_trailing_garbage(suffix):
    with pytest.raises(_tokens.InvalidToken):
        _tokens.verify(_tokens.issue(KEY, NONCE) + suffix, KEY, NONCE, 3600)


def test_key_and_nonce_binding():
    token = _tokens.issue(KEY, NONCE)
    with pytest.raises(_tokens.InvalidToken):
        _tokens.verify(token, b"different-key", NONCE, 3600)
    with pytest.raises(_tokens.InvalidToken):
        _tokens.verify(token, KEY, "b" * 64, 3600)


@pytest.mark.parametrize(
    "now,reason", [(999, "future"), (1000, None), (4600, None), (4601, "expired")]
)
def test_time_boundaries_without_session_cookie(now, reason, monkeypatch):
    monkeypatch.setattr(_tokens.time, "time", lambda: now)
    token = signed("v1.1000." + "c" * 64)
    if reason:
        with pytest.raises(_tokens.InvalidToken, match=reason):
            _tokens.verify(token, KEY, NONCE, 3600)
    else:
        _tokens.verify(token, KEY, NONCE, 3600)


def test_authenticate_before_expiry(monkeypatch):
    monkeypatch.setattr(_tokens.time, "time", lambda: 99999)
    token = signed("v1.1000." + "c" * 64, key=b"wrong-key")
    with pytest.raises(_tokens.InvalidToken, match="invalid for this session"):
        _tokens.verify(token, KEY, NONCE, 3600)


def test_token_engine_imports_only_stdlib():
    tree = ast.parse(inspect.getsource(_tokens))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name.split(".")[0] in sys.stdlib_module_names for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module.split(".")[0] in sys.stdlib_module_names
