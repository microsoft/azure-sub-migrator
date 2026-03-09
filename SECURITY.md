# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Tenova, please report it
responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@learnazurewithmo.com**

Include:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within **48 hours** and provide a
detailed response within **7 business days**.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Security Practices

- All authentication uses **MSAL** (Microsoft Authentication Library).
- No credentials are stored — only short-lived OAuth tokens in
  server-side sessions.
- Dependencies are monitored via **Dependabot** and **pip-audit**.
- Static analysis is performed via **CodeQL** and **Ruff** in CI.
- The web UI enforces **CSRF protection**, **secure cookie flags**,
  and standard **security headers** (CSP, HSTS, X-Frame-Options).
