# Changelog

## 0.1.0 — Unreleased

- Rename the unreleased project to csrf-kit (Python import: csrf_kit).
- Implement a versioned token engine using only secrets, hmac, hashlib, re and time.
- Introduce the CSRF object: install, token, field, renew, verify, guard and skip.
- Use _csrf form fields and the X-CSRF-Kit header with per-app keyword options.
- Retain session binding, token expiry, HTTPS origin checks and blueprint exclusions.
- Add protocol tests, a Flask demo, GitHub CI and packaging instructions.
- Breaking change from the earlier unpublished draft: old imports, config keys,
  helper names and tokens are not supported; refresh all token-bearing pages.
