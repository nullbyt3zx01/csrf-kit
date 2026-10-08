"""Flask integration for csrf-kit."""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from html import escape
from typing import TypeVar
from urllib.parse import urlsplit

from flask import Blueprint, Flask, current_app, g, request, session
from markupsafe import Markup
from werkzeug.exceptions import BadRequest

from . import _tokens

T = TypeVar("T", bound=Callable | Blueprint)
_NONCE = "_csrf_kit_nonce"
_CACHE = "_csrf_kit_cache"
_SAFE = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


class Rejected(BadRequest):
    """CSRF rejection; register a Flask error handler to customize it."""

    description = "CSRF validation failed."


@dataclass(frozen=True)
class _Settings:
    ttl: int
    field_name: str
    header_name: str
    strict_origin: bool
    automatic: bool
    signing_key: str | bytes | None


def _origin(value: str) -> tuple[str, str, int] | None:
    try:
        url = urlsplit(value)
        if url.scheme not in {"http", "https"} or not url.hostname:
            return None
        if url.username is not None or url.password is not None:
            return None
        port = url.port if url.port is not None else (443 if url.scheme == "https" else 80)
        return url.scheme, url.hostname.lower(), port
    except ValueError:
        return None


class CSRF:
    """Use CSRF(app), csrf.field() in Jinja, and csrf.token() in Python.

    For factories, create CSRF() once and call install(app, **options) per app.
    """

    def __init__(self, app: Flask | None = None) -> None:
        if app is not None:
            self.install(app)

    def install(
        self,
        app: Flask,
        *,
        ttl: int = 3600,
        field_name: str = "_csrf",
        header_name: str = "X-CSRF-Kit",
        strict_origin: bool = True,
        automatic: bool = True,
        signing_key: str | bytes | None = None,
    ) -> CSRF:
        """Attach to an app. Options are stored per app, not on this shared object."""
        if "csrf_kit" in app.extensions:
            raise RuntimeError("CSRF is already installed on this app.")
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
            raise ValueError("ttl must be a positive integer in seconds.")
        if not isinstance(field_name, str) or not field_name:
            raise ValueError("field_name must be a non-empty string.")
        if not isinstance(header_name, str) or not re.fullmatch(
            r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", header_name
        ):
            raise ValueError("header_name must be a valid HTTP header name.")
        if type(strict_origin) is not bool or type(automatic) is not bool:
            raise ValueError("strict_origin and automatic must be booleans.")
        if signing_key is not None and (
            not isinstance(signing_key, (str, bytes)) or not signing_key
        ):
            raise ValueError("signing_key must be a non-empty string or bytes.")
        if "csrf" in app.jinja_env.globals:
            raise RuntimeError("The Jinja global 'csrf' is already in use.")
        settings = _Settings(ttl, field_name, header_name, strict_origin, automatic, signing_key)
        app.extensions["csrf_kit"] = (self, settings)
        app.jinja_env.globals["csrf"] = self

        @app.before_request
        def _check() -> None:
            if not settings.automatic or request.endpoint is None:
                return
            view = app.view_functions.get(request.endpoint)
            if getattr(view, "_csrf_kit_skip", False):
                return
            if any(
                getattr(app.blueprints[name], "_csrf_kit_skip", False)
                for name in request.blueprints
            ):
                return
            self.guard()

        return self

    def _settings(self) -> _Settings:
        installed = current_app.extensions.get("csrf_kit")
        if installed is None or installed[0] is not self:
            raise RuntimeError("Install this CSRF instance on the current app first.")
        return installed[1]

    def _key(self) -> bytes:
        settings = self._settings()
        if not current_app.secret_key:
            raise RuntimeError("CSRF requires Flask SECRET_KEY for session storage.")
        key = settings.signing_key or current_app.secret_key
        if not isinstance(key, (str, bytes)):
            raise RuntimeError("The signing secret must be a string or bytes.")
        return key.encode("utf-8") if isinstance(key, str) else key

    def token(self) -> str:
        """Get a request-cached token; repair a cleared or malformed session nonce."""
        key = self._key()
        nonce = session.get(_NONCE)
        if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
            nonce = session[_NONCE] = secrets.token_hex(32)
        cached = g.get(_CACHE)
        if cached is None or cached[0] != nonce:
            cached = (nonce, _tokens.issue(key, nonce))
            setattr(g, _CACHE, cached)
        return cached[1]

    def field(self) -> Markup:
        """Render an escaped hidden input as {{ csrf.field() }} in Jinja."""
        name = escape(self._settings().field_name, quote=True)
        value = escape(self.token(), quote=True)
        return Markup(f'<input type="hidden" name="{name}" value="{value}">')

    def renew(self) -> str:
        """Rotate the session nonce after login/logout and return a fresh token."""
        self._key()
        session[_NONCE] = secrets.token_hex(32)
        g.pop(_CACHE, None)
        return self.token()

    def verify(self, token: str | None) -> None:
        """Check a token only; guard() also checks request method and HTTPS origin."""
        key = self._key()
        nonce = session.get(_NONCE)
        if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
            raise Rejected("The CSRF session token is missing.")
        try:
            _tokens.verify(token, key, nonce, self._settings().ttl)
        except _tokens.InvalidToken as exc:
            raise Rejected(str(exc)) from exc

    def skip(self, target: T) -> T:
        """Skip automatic checks for a view or Blueprint; guard() still checks it."""
        if not callable(target) and not isinstance(target, Blueprint):
            raise TypeError("skip requires a view function or Blueprint.")
        target._csrf_kit_skip = True
        return target

    def guard(self) -> None:
        """Enforce token and HTTPS origin checks on the current unsafe request."""
        settings = self._settings()
        if request.method in _SAFE:
            return
        token = request.form.get(settings.field_name) or request.headers.get(settings.header_name)
        self.verify(token)
        if request.is_secure and settings.strict_origin:
            source = request.headers.get("Origin")
            if source is None:
                source = request.referrer
            if (
                not source
                or _origin(source) is None
                or _origin(source) != _origin(request.host_url)
            ):
                raise Rejected("The CSRF request origin is missing or does not match.")
