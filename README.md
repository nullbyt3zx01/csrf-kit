# csrf-kit

Lightweight Cross-Site Request Forgery (CSRF) protection for Flask, with token generation and verification built on Python's standard library.

**Version:** 0.1.0 (Alpha)  
**Requirements:** Python 3.10+ and Flask 3.1+

## What does it do?

CSRF is an attack in which another website tricks a user's browser into sending an unwanted request to a site where the user is logged in. `csrf-kit` adds a session-bound token to legitimate requests and rejects requests that do not provide a valid token.

By default, it automatically checks unsafe HTTP methods such as `POST`, `PUT`, `PATCH`, and `DELETE`. Ordinary `GET` requests do not require a token. Invalid or missing tokens produce an HTTP **400 Bad Request** response.

## Installation

Install the package:

```bash
python -m pip install csrf-kit
```

Or, from an extracted source directory containing `pyproject.toml`:

```bash
python -m pip install .
```

## Basic Flask setup

Create `app.py`:

```python
import os
from flask import Flask, render_template
from csrf_kit import CSRF

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]

csrf = CSRF(app)

@app.get("/")
def home():
    response = app.make_response(render_template("form.html"))
    response.headers["Cache-Control"] = "no-store"
    return response

@app.post("/submit")
def submit():
    return "Form submitted successfully!"
```

**Explanation:** Flask uses `SECRET_KEY` to protect its session cookie; `csrf-kit` uses this key (unless configured otherwise) to sign tokens. `CSRF(app)` enables automatic validation for unsafe requests. The `/submit` route does not need a separate decorator. Set `SECRET_KEY` to a strong, stable, private value in your environment; do not hardcode it in a public repository.

For local development, set the `SECRET_KEY` environment variable before starting the application, then run:

```bash
flask --app app run
```

## Protect an HTML form

Create `templates/form.html`:

```html
<!doctype html>
<html lang="en">
<body>
  <form action="/submit" method="post">
    {{ csrf.field() }}
    <input type="text" name="message" placeholder="Your message">
    <button type="submit">Submit</button>
  </form>
</body>
</html>
```

**Explanation:** `{{ csrf.field() }}` inserts a hidden `<input>` containing the CSRF token. When the form is submitted, the browser sends that token along with the other form fields. `csrf-kit` validates it before Flask runs the `/submit` view. You should include this field in **every form that changes data**, including login, logout, account settings, and delete forms.

Without the field, or with an expired/invalid token, the request is rejected with status `400`.

## Protect JavaScript / fetch requests

For `fetch()` or AJAX requests, send the token as a request header instead of a form field:

```html
<button id="save">Save</button>
<script>
const csrfToken = {{ csrf.token() | tojson }};

document.querySelector('#save').addEventListener('click', async () => {
  const response = await fetch('/submit', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Kit': csrfToken
    },
    body: JSON.stringify({ message: 'Hello' })
  });
  console.log(response.status, await response.text());
});
</script>
```

**Explanation:** `csrf.token()` returns a token for the current session. Jinja's `tojson` filter safely embeds it in JavaScript. The default header is `X-CSRF-Kit`. `credentials: 'same-origin'` allows the session cookie to accompany same-origin requests. The CSRF token is **not** a replacement for login or authorization checks. Render this snippet through Jinja (for example inside a `.html` template), not in a standalone static `.js` file.

## Flask application factory

If your project uses `create_app()`, initialize the extension separately:

```python
from flask import Flask
from csrf_kit import CSRF

csrf = CSRF()

def create_app():
    app = Flask(__name__)
    app.config.from_prefixed_env()
    csrf.install(app)
    return app
```

**Explanation:** `CSRF()` creates an unbound extension, and `csrf.install(app)` attaches it to an individual Flask application. With `from_prefixed_env()`, configure `FLASK_SECRET_KEY` in the environment. Install the extension once per app.

## Configuration

You can customize the extension during installation:

```python
csrf = CSRF()
csrf.install(
    app,
    ttl=1800,
    field_name="_csrf",
    header_name="X-CSRF-Kit",
    strict_origin=True,
    automatic=True,
)
```

| Option | Default | Description |
| --- | --- | --- |
| `ttl` | `3600` | Token lifetime in seconds (e.g., `1800` = 30 minutes). |
| `field_name` | `_csrf` | Name of the hidden HTML form field. |
| `header_name` | `X-CSRF-Kit` | Header used for JavaScript requests. |
| `strict_origin` | `True` | On HTTPS, require a matching `Origin` or `Referer`. |
| `automatic` | `True` | Automatically check unsafe requests. |
| `signing_key` | `None` | Optional separate secret used for CSRF signing; Flask `SECRET_KEY` is still required for sessions. |

If you change `field_name` or `header_name`, update your forms or JavaScript accordingly. Avoid disabling `strict_origin` or `automatic` unless you understand the security consequences.

## Available methods

- **`csrf.field()`** — renders a complete hidden input in Jinja templates.
- **`csrf.token()`** — generates/returns the current session's token; use it in Python or Jinja.
- **`csrf.renew()`** — rotates the session's CSRF nonce and returns a fresh token. Call after a successful login or logout (once the session has been updated) to invalidate previously issued tokens.
- **`csrf.verify(token)`** — checks one supplied token; it does **not** perform HTTP-method or origin checks.
- **`csrf.guard()`** — checks the current unsafe request, including HTTPS origin checking when enabled. This runs automatically unless `automatic=False`.
- **`@csrf.skip`** — exempts a specific Flask view from automatic checking.

If you turn off automatic checking, explicitly call `csrf.guard()` for each unsafe route you intend to protect.

## Exempt a webhook endpoint

Some incoming webhooks cannot send your user's CSRF token. You can exempt only those routes:

```python
from flask import request

@app.post('/webhook')
@csrf.skip
def webhook():
    # Verify the provider's webhook signature before processing the payload.
    return {'received': True}
```

**Explanation:** `@csrf.skip` skips automatic CSRF checking for this view. This does **not** authenticate the sender. Verify the webhook provider's signature or use another appropriate authentication method. Do not exempt ordinary user-facing forms just to fix a missing-token error. You can also apply `csrf.skip(blueprint)` to an entire blueprint, but that has a much wider effect.

## Customize CSRF errors

By default, invalid requests raise `Rejected`, a subclass of Flask/Werkzeug's `BadRequest` (HTTP 400). Register an error handler for a user-friendly response:

```python
from flask import jsonify
from csrf_kit import Rejected

@app.errorhandler(Rejected)
def handle_csrf_error(error):
    return jsonify(error="csrf_failed", message="Please refresh and try again."), 400
```

**Explanation:** Users may encounter a failure if a form has been left open longer than `ttl`, the session has changed, or the token is missing. Refreshing the page generates a current token. Avoid exposing internal verification details in production error messages.

## Run the included example

From the project root, after installation:

```bash
flask --app examples.app run
```

Open `http://127.0.0.1:5000` to test a protected HTML form and a JSON `fetch()` request. The bundled example uses a temporary secret if none is set **for local demonstration only**.

## Security notes

- Use a strong, stable `SECRET_KEY` and protect it as a secret; rotate it deliberately because rotation invalidates existing sessions/tokens.
- Use HTTPS in production and enable appropriate Flask session cookie settings (`SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True`, and a suitable `SESSION_COOKIE_SAMESITE`).
- Configure and trust your reverse proxy correctly so Flask knows whether the original request used HTTPS and which host the user accessed.
- Do not put CSRF tokens in URLs, logs, or publicly cached pages. Avoid shared caches for session-specific HTML containing tokens.
- CSRF protection does not replace authentication, authorization, input validation, or protection against XSS.
- Only exempt endpoints that have an independent, verified security mechanism.

**Status:** This is an alpha release and has not been independently security audited. `csrf-kit` is not affiliated with Flask-WTF or the Pallets project.

## Contributors

- [nullbyt3zx01](https://github.com/nullbyt3zx01) — Creator & Maintainer
- [T3Calt](https://github.com/T3Calt) — Contributor
- [Jup1ng](https://github.com/kittiphonpr-lang) — Contributor
- [PunPoon](https://github.com/punpoon16) — Contributor
- [Velupra](https://github.com/phitchadal-ship-it) — Contributor
- [Cake](https://github.com/ChayadaBo) — Contributor
- [chocrypto](https://github.com/chotikaset-crypto) - Contributor
