# Local validation — 2026-10-08

Environment: Windows, Python 3.14.6, Flask 3.1.3.

- 82 pytest cases passed against the editable source package.
- Coverage: 100% of 159 statements and 58 branches in csrf_kit.
- Protocol tests cover independent HMAC reference construction, session/key binding,
  changes to every token field, malformed timestamps, expiry boundaries, future
  timestamps and authenticating before evaluating expiry.
- A dependency-boundary test verifies that _tokens.py imports only standard-library modules.
- Flask tests cover forms, JSON headers, origins, renewal, factory isolation,
  clearing sessions, field escaping, custom settings, exclusions and the demo.
- Ruff checks passed.
- Built the sdist, then built the wheel from that sdist successfully.
- Twine metadata/readme checks passed for both distributions.
- Installed the wheel with pip, replacing the editable install; all 82 tests passed again.
- Confirmed imports came from site-packages and distribution metadata uses csrf-kit.

Python 3.10–3.13 and GitHub Actions have not been executed locally. The included
CI matrix will run after GitHub upload. No package has been published and no
remote repository has been created. Coverage does not replace a security audit.

The CSRF token engine uses the standard library only. Flask's session machinery
still depends transitively on ItsDangerous; this package does not remove or
replace Flask's session signing.
