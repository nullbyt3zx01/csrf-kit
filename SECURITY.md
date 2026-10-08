# Security

This is a new alpha package and has not received an independent security audit.
The tests exercise security properties but are not a guarantee of security.

Before public release, enable GitHub private vulnerability reporting under
repository Settings > Security. Report suspected vulnerabilities there; do not
post real secrets or working exploit details in a public issue. If private
reporting is unavailable, ask the maintainer for a private contact first.

Only the latest 0.1.x release is intended to receive fixes. Deployments need
secure secret management, HTTPS, correct proxy/host configuration and separate
authentication, authorization and XSS controls. See README for token and session
limitations.
