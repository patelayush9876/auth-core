# Auth System Architecture

A modular, framework-agnostic authentication system built with TypeScript. This structure is designed for scalability, security, and flexibility across different runtimes and storage backends.

---

## 📁 Project Structure


```text
src/
├── types/index.ts          — all TypeScript interfaces (UserStore, SessionStore, TokenStore, AuthConfig, etc.)
├── errors.ts               — AuthError class + typed error factories
├── config.ts               — resolveConfig() with safe defaults, parseDuration()
├── audit.ts                — typed EventEmitter + async handler override
├── ratelimit.ts            — sliding window rate limiter (memory)
├── session.ts              — createSession, rotateRefreshToken, revokeSession, reuse detection
├── crypto/
│   ├── tokens.ts           — generateOpaqueToken, hashToken, safeCompare, generateOTP
│   ├── pkce.ts             — S256 verifier/challenge generation + validation
│   ├── password.ts         — Argon2id/bcrypt hash + verify + needsRehash
│   └── jwt.ts              — sign/verify with alg:none prevention (jose)
├── strategies/
│   ├── local/              — register, login (lock/unlock), verifyEmail, forgotPassword, resetPassword
│   ├── oauth/              — PKCE+state flow, Google/GitHub/Discord/Microsoft presets
│   ├── passwordless/       — magic link + 6-digit OTP (crypto.randomInt)
│   ├── mfa/                — TOTP (otpauth), backup codes (bcrypt bulk hash)
│   └── webauthn/           — @simplewebauthn/server wrapper, no reimplemented primitives
├── middleware/
│   ├── core.ts             — framework-agnostic authenticate/protect/requireRole/requireMFA
│   ├── express/            — ~30-line Express wrapper
│   ├── fastify/            — ~30-line Fastify wrapper
│   └── hono/               — ~30-line Hono wrapper
└── adapters/
    ├── memory/             — InMemory* (dev/test, warns in production)
    ├── sql/                — SqlUserStore/SessionStore/TokenStore (query executor pattern)
    ├── mongodb/            — MongoUserStore/SessionStore/TokenStore (collection injection)
    └── redis/              — RedisSessionStore/TokenStore/RateLimitStore (ioredis-compatible)
```


---

## 🧩 Core Modules

### `types/index.ts`
Defines all core TypeScript interfaces:
- `UserStore`
- `SessionStore`
- `TokenStore`
- `AuthConfig`
- Shared types across modules

---

### `errors.ts`
Centralized error handling:
- `AuthError` class
- Typed error factories for consistent error responses

---

### `config.ts`
Configuration resolver:
- `resolveConfig()` for merging defaults with user config
- `parseDuration()` utility for time parsing

---

### `audit.ts`
Audit logging system:
- Typed `EventEmitter`
- Supports async handlers for logging/security tracking

---

### `ratelimit.ts`
Rate limiting implementation:
- Sliding window algorithm
- In-memory store (can be swapped via adapters)

---

### `session.ts`
Session lifecycle management:
- `createSession`
- `rotateRefreshToken`
- `revokeSession`
- Refresh token reuse detection

---

## 🔐 Crypto Layer (`crypto/`)

### `tokens.ts`
- Opaque token generation
- Secure hashing
- Timing-safe comparison
- OTP generation

### `pkce.ts`
- PKCE verifier & challenge generation
- S256 validation

### `password.ts`
- Password hashing (Argon2id / bcrypt)
- Verification
- Rehash detection

### `jwt.ts`
- JWT signing & verification
- Protection against `alg: none` attacks (via `jose`)

---

## 🔑 Authentication Strategies (`strategies/`)

### `local/`
- User registration
- Login with lock/unlock logic
- Email verification
- Password reset flow

### `oauth/`
- OAuth2 with PKCE + state
- Preconfigured providers:
  - Google
  - GitHub
  - Discord
  - Microsoft

### `passwordless/`
- Magic link authentication
- 6-digit OTP login

### `mfa/`
- TOTP (Time-based One-Time Password)
- Backup codes (hashed)

### `webauthn/`
- Passkey authentication
- Wrapper around `@simplewebauthn/server`

---

## 🧱 Middleware (`middleware/`)

### `core.ts`
Framework-agnostic middleware:
- `authenticate`
- `protect`
- `requireRole`
- `requireMFA`

### Framework Wrappers
Lightweight integrations (~30 LOC each):
- `express/`
- `fastify/`
- `hono/`

---

## 🗄️ Storage Adapters (`adapters/`)

### `memory/`
- In-memory stores
- Intended for development/testing
- Warns if used in production

### `sql/`
- SQL-based stores
- Uses query executor pattern

### `mongodb/`
- MongoDB collections injection
- Flexible schema handling

### `redis/`
- Redis-backed stores
- Compatible with `ioredis`
- Supports sessions, tokens, and rate limiting

---

## ⚙️ Design Principles

- **Framework Agnostic** — Works across Express, Fastify, Hono, etc.
- **Modular** — Replace strategies, adapters, or crypto independently
- **Secure by Default** — Built-in protections against common auth vulnerabilities
- **Extensible** — Easily plug in new providers or storage layers
- **Typed End-to-End** — Strong TypeScript guarantees

---

## 🚀 Use Cases

- Full-featured authentication system for SaaS apps
- Microservices auth layer
- API-first backends
- Systems requiring multiple auth strategies (OAuth, MFA, WebAuthn)

---

## 📌 Notes

- Prefer production adapters (`sql`, `mongodb`, `redis`) over `memory`
- Always configure secure defaults in `AuthConfig`
- Use audit events for monitoring suspicious activity

---