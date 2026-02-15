# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in goop-shield, please report it responsibly.

**Do NOT open a public issue for security vulnerabilities.**

Instead, please email security reports to: **kobepaw@proton.me**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Fix Timeline**: Depends on severity, typically within 2 weeks for critical issues

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Best Practices

When deploying goop-shield:

1. **Set `SHIELD_API_KEY`** — Without it, all endpoints are unauthenticated
2. **Use HTTPS** — Deploy behind a reverse proxy with TLS
3. **Restrict `/debug/defend`** — This endpoint exposes defense names; only use for admin/debug
4. **Review config presets** — `shield_strict.yaml` enables maximum protection
5. **Monitor audit logs** — Enable `audit_enabled: true` and review events regularly
