import re

import pytest
from flask import Blueprint, Flask, render_template_string, session

from csrf_kit import CSRF, Rejected, _tokens
from csrf_kit.flask import _origin


def make_app(**options):
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test-secret-only")
    csrf = CSRF().install(app, **options)

    @app.get("/token")
    def token():
        return {"token": csrf.token()}

    @app.route("/submit", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "CUSTOM"])
    def submit():
        return {"ok": True}

    @app.post("/renew")
    def renew():
        csrf.token()
        return {"token": csrf.renew()}

    @app.post("/skip")
    @csrf.skip
    def skip():
        return "ok"

    @app.errorhandler(Rejected)
    def error(exc):
        return {"reason": exc.description}, 400

    return app, csrf


@pytest.fixture
def app():
    return make_app()[0]


@pytest.fixture
def csrf(app):
    return app.extensions["csrf_kit"][0]


@pytest.fixture
def client(app):
    return app.test_client()


def token_for(client, **kwargs):
    return client.get("/token", **kwargs).json["token"]


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "CUSTOM"])
def test_unsafe_methods(client, method):
    assert client.open("/submit", method=method).status_code == 400
    token = token_for(client)
    assert client.open("/submit", method=method, data={"_csrf": token}).status_code == 200


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_safe_methods(client, method):
    assert client.open("/submit", method=method).status_code == 200


def test_token_sources_and_precedence(client):
    token = token_for(client)
    assert client.post("/submit", json={}, headers={"X-CSRF-Kit": token}).status_code == 200
    assert client.post("/submit", json={"_csrf": token}).status_code == 400
    assert client.post("/submit", query_string={"_csrf": token}).status_code == 400
    assert client.post("/submit", headers={"X-CSRFToken": token}).status_code == 400
    assert (
        client.post("/submit", data={"_csrf": "bad"}, headers={"X-CSRF-Kit": token}).status_code
        == 400
    )


def test_tampering_and_session_binding(app, client):
    token = token_for(client)
    assert client.post("/submit", data={"_csrf": "bad" + token}).status_code == 400
    assert app.test_client().post("/submit", data={"_csrf": token}).status_code == 400
    other = app.test_client()
    token_for(other)
    assert other.post("/submit", data={"_csrf": token}).status_code == 400


def test_expiry_and_future(client, monkeypatch):
    monkeypatch.setattr(_tokens.time, "time", lambda: 10000)
    token = token_for(client)
    monkeypatch.setattr(_tokens.time, "time", lambda: 13600)
    assert client.post("/submit", data={"_csrf": token}).status_code == 200
    monkeypatch.setattr(_tokens.time, "time", lambda: 13601)
    response = client.post("/submit", data={"_csrf": token})
    assert response.status_code == 400
    assert "expired" in response.json["reason"]
    monkeypatch.setattr(_tokens.time, "time", lambda: 9999)
    assert client.post("/submit", data={"_csrf": token}).status_code == 400


def test_renew(client):
    token = token_for(client)
    new = client.post("/renew", data={"_csrf": token}).json["token"]
    assert new != token
    assert client.post("/submit", data={"_csrf": token}).status_code == 400
    assert client.post("/submit", data={"_csrf": new}).status_code == 200


def test_session_clear(client):
    token = token_for(client)
    with client.session_transaction() as state:
        state.clear()
    assert client.post("/submit", data={"_csrf": token}).status_code == 400


@pytest.mark.parametrize(
    "headers,code",
    [
        ({"Origin": "https://localhost"}, 200),
        ({"Origin": "https://LOCALHOST:443"}, 200),
        ({"Referer": "https://localhost/form?a=1"}, 200),
        ({}, 400),
        ({"Origin": "null"}, 400),
        ({"Origin": "https://evil.example", "Referer": "https://localhost/"}, 400),
        ({"Origin": "http://localhost"}, 400),
        ({"Origin": "https://localhost:444"}, 400),
        ({"Origin": "https://localhost:0"}, 400),
        ({"Origin": "https://localhost.evil.example"}, 400),
        ({"Origin": "https://user@localhost"}, 400),
        ({"Origin": "https://localhost:bad"}, 400),
        ({"Origin": ""}, 400),
    ],
)
def test_https_origin(client, headers, code):
    token = token_for(client, base_url="https://localhost")
    assert (
        client.post(
            "/submit", base_url="https://localhost", headers=headers, data={"_csrf": token}
        ).status_code
        == code
    )


def test_disable_origin_check():
    app, _ = make_app(strict_origin=False)
    client = app.test_client()
    token = token_for(client, base_url="https://localhost")
    assert (
        client.post("/submit", base_url="https://localhost", data={"_csrf": token}).status_code
        == 200
    )


def test_skip_and_unknown_route(client):
    assert client.post("/skip").status_code == 200
    assert client.post("/missing").status_code == 404


def test_nested_blueprint_skip():
    app, csrf = make_app()
    parent = Blueprint("parent", __name__)
    child = Blueprint("child", __name__)
    child.add_url_rule("/child", view_func=lambda: "ok", methods=["POST"])
    parent.register_blueprint(child)
    csrf.skip(parent)
    app.register_blueprint(parent)
    assert app.test_client().post("/child").status_code == 200
    assert app.test_client().post("/submit").status_code == 400
    with pytest.raises(TypeError):
        csrf.skip("endpoint-name")


def test_manual_guard():
    app, csrf = make_app(automatic=False)
    assert app.test_client().post("/submit").status_code == 200
    with app.test_request_context("/skip", method="POST"):
        with pytest.raises(Rejected):
            csrf.guard()

    other, guard = make_app(automatic=False)
    other.before_request(guard.guard)
    assert other.test_client().post("/submit").status_code == 400


def test_custom_options():
    app, _ = make_app(
        field_name="anti_forgery",
        header_name="X-Custom-CSRF",
        signing_key=b"independent-signing-secret",
    )
    client = app.test_client()
    token = token_for(client)
    assert client.post("/submit", data={"anti_forgery": token}).status_code == 200
    assert client.post("/submit", headers={"X-Custom-CSRF": token}).status_code == 200
    assert client.post("/submit", headers={"X-CSRF-Kit": token}).status_code == 400


def test_cache_and_clear_within_request(app, csrf):
    with app.test_request_context():
        first = csrf.token()
        assert csrf.token() == first
        assert render_template_string("{{ csrf.token() }}") == first
        csrf.verify(first)
        session.clear()
        fresh = csrf.token()
        assert fresh != first
        csrf.verify(fresh)
        with pytest.raises(Rejected):
            csrf.verify(first)


def test_field_autoescape():
    app, csrf = make_app(field_name='x" onfocus="alert(1)')
    with app.test_request_context():
        rendered = render_template_string("{{ csrf.field() }}")
        assert rendered.startswith('<input type="hidden"')
        assert 'name="x&quot; onfocus=&quot;alert(1)"' in rendered
        assert "&lt;input" not in rendered


@pytest.mark.parametrize("value", [None, "", 1, "x" * 4097, "\u2603"])
def test_invalid_input(app, csrf, value):
    with app.test_request_context():
        csrf.token()
        with pytest.raises(Rejected):
            csrf.verify(value)


@pytest.mark.parametrize("value", [42, "invalid"])
def test_malformed_session(app, csrf, value):
    with app.test_request_context():
        token = csrf.token()
        session["_csrf_kit_nonce"] = value
        with pytest.raises(Rejected):
            csrf.verify(token)
        csrf.verify(csrf.token())


def test_factory_isolation():
    csrf = CSRF()
    first, second = Flask("one"), Flask("two")
    first.secret_key = second.secret_key = "same-secret"
    csrf.install(first, field_name="one", ttl=10)
    csrf.install(second, field_name="two", ttl=20)
    for app, name, ttl in [(first, "one", 10), (second, "two", 20)]:
        with app.test_request_context():
            assert f'name="{name}"' in csrf.field()
            assert csrf._settings().ttl == ttl
    with pytest.raises(RuntimeError, match="already installed"):
        csrf.install(first)


def test_setup_checks():
    app, csrf = Flask(__name__), CSRF()
    with app.test_request_context():
        with pytest.raises(RuntimeError, match="Install"):
            csrf.token()
    csrf.install(app)
    with app.test_request_context():
        with pytest.raises(RuntimeError, match="SECRET_KEY"):
            csrf.token()
        with pytest.raises(RuntimeError, match="Install"):
            CSRF().token()
    app.secret_key = 123
    with app.test_request_context():
        with pytest.raises(RuntimeError, match="string or bytes"):
            csrf.token()
    other = Flask("other")
    other.jinja_env.globals["csrf"] = "existing"
    with pytest.raises(RuntimeError, match="already in use"):
        CSRF(other)


@pytest.mark.parametrize(
    "options",
    [{"ttl": x} for x in [None, 0, -1, True, "3600", 1.5]]
    + [
        {"field_name": ""},
        {"field_name": None},
        {"header_name": "bad\nheader"},
        {"header_name": 1},
        {"strict_origin": 1},
        {"automatic": "false"},
        {"signing_key": b""},
        {"signing_key": 123},
    ],
)
def test_invalid_settings(options):
    with pytest.raises(ValueError):
        make_app(**options)


def test_origin_parser():
    assert _origin("https://[") is None
    assert _origin("https://[::1]:443/") == ("https", "::1", 443)


def test_demo():
    from examples.app import app

    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    token = re.search(rb'name="_csrf" value="([^"]+)"', response.data)[1].decode()
    assert client.post("/submit").status_code == 400
    assert client.post("/submit", data={"_csrf": token}).json == {"ok": True}
