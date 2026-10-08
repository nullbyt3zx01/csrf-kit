"""Run: flask --app examples.app run (development only)."""

import os
import secrets

from flask import Flask, jsonify, render_template_string

from csrf_kit import CSRF, Rejected

app = Flask(__name__)
# Ephemeral fallback for local demos only; production needs a stable environment secret.
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
csrf = CSRF(app)


@app.get("/")
def index():
    response = app.make_response(
        render_template_string("""
        <!doctype html><title>csrf-kit</title>
        <h1>csrf-kit</h1>
        <form method="post" action="/submit">
          {{ csrf.field() }}
          <button>Submit protected form</button>
        </form>
        <button id="send">Send protected JSON</button><pre id="result"></pre>
        <script>
        document.querySelector('#send').onclick = async () => {
          const response = await fetch('/submit', {
            method: 'POST', credentials: 'same-origin',
            headers: {'Content-Type': 'application/json',
                      'X-CSRF-Kit': {{ csrf.token() | tojson }}},
            body: JSON.stringify({message: 'hello'})
          });
          document.querySelector('#result').textContent = await response.text();
        };
        </script>
    """)
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/submit")
def submit():
    return jsonify(ok=True)


@app.errorhandler(Rejected)
def csrf_error(error):
    return jsonify(error="csrf_failed", reason=error.description), 400
