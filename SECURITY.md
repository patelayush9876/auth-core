# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x     | ✅        |

## Reporting a Vulnerability

**Please do not report security vulnerabilities via GitHub Issues.**

To report a security issue, email **patelayush7007@gmail,com** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

You will receive a response within **48 hours**. If the issue is confirmed, we will:

1. Work on a fix privately
2. Release a patched version
3. Credit you in the changelog (unless you prefer anonymity)

## Security Design Principles

- All secret comparisons use `crypto.timingSafeEqual` — no `===`
- Passwords are hashed with Argon2id (bcrypt fallback) — never stored plaintext
- JWT `alg` header is always validated — `alg:none` attacks are rejected
- Refresh token rotation with reuse detection — stolen tokens trigger full session revocation
- Rate limiting on all auth endpoints — sliding window, Redis-backed for distributed deployments
- Audit events emitted for all security-relevant actions
- InMemory adapters warn loudly in production — they are dev/test only
