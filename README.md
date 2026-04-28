# node-auth-core

Self-hosted, framework-agnostic authentication for Node.js. Zero dependency on external auth services.

```
npm install node-auth-core
```

**Requires Node.js ≥ 18.**

---

## Quickstart (Express + InMemory)

```ts
import express from 'express';
import { createAuth } from 'node-auth-core';
import { InMemoryUserStore, InMemorySessionStore, InMemoryTokenStore } from 'node-auth-core/adapters/memory';
import { register, login } from 'node-auth-core/strategies/local';
import { createProtectMiddleware } from 'node-auth-core/middleware/express';

const auth = createAuth({
  secret: process.env.AUTH_SECRET!, // min 32 chars in production
  adapters: {
    user: new InMemoryUserStore(),
    session: new InMemorySessionStore(),
    token: new InMemoryTokenStore(),
  },
});

const app = express();
app.use(express.json());

app.post('/register', async (req, res) => {
  const { user, emailVerificationToken } = await register(req.body, auth);
  // Send emailVerificationToken via email
  res.json({ userId: user.id });
});

app.post('/login', async (req, res) => {
  const { tokens } = await login(req.body, auth, { ip: req.ip });
  res.json(tokens);
});

const protect = createProtectMiddleware(auth);

app.get('/me', protect, (req, res) => {
  res.json(req.auth!.user);
});
```

> ⚠️ `InMemoryUserStore` is for development only. Data is lost on restart. See [Adapters](#adapters).

---

## Configuration

All fields are optional except `secret` (required for HS256).

```ts
const auth = createAuth({
  // Required for HS256 JWT signing (min 32 chars in production)
  secret: process.env.AUTH_SECRET,

  accessToken: {
    algorithm: 'HS256',   // 'HS256' | 'RS256' | 'ES256'
    expiresIn: '15m',     // default: 15 minutes
    issuer: 'my-app',
    audience: 'my-client',
  },

  refreshToken: {
    expiresIn: '7d',      // default: 7 days
    rotateOnUse: true,    // default: true — issue new token on every refresh
    reuseDetection: true, // default: true — revoke all sessions on reuse
  },

  password: {
    algorithm: 'argon2id', // 'argon2id' | 'bcrypt'
    argon2: { memoryCost: 65536, timeCost: 3, parallelism: 4 },
    bcrypt: { rounds: 12 },
    minStrengthScore: 3,   // zxcvbn score 0–4, default: 3
  },

  session: {
    cookieName: '__session',
    cookie: {
      httpOnly: true,
      secure: true,        // false in development
      sameSite: 'Strict',
      path: '/',
    },
    absoluteTimeout: '30d',
    idleTimeout: '7d',
  },

  mfa: {
    enforcement: 'optional', // 'required' | 'optional' | 'disabled'
    issuer: 'My App',
  },

  rateLimit: {
    enabled: true,
    store: 'memory',       // 'memory' | 'redis'
    login: { windowMs: 900_000, max: 10 },
    register: { windowMs: 3_600_000, max: 5 },
  },

  adapters: { user, session, token },

  hooks: {
    onAfterRegister: async (user) => { /* send welcome email */ },
    onAfterLogin: async (user, session) => { /* log login */ },
  },

  isDevelopment: process.env.NODE_ENV === 'development',
});
```

---

## Adapters

### InMemory (dev/test only)

```ts
import {
  InMemoryUserStore,
  InMemorySessionStore,
  InMemoryTokenStore,
} from 'node-auth-core/adapters/memory';
```

### SQL (Prisma / Drizzle / Knex)

```ts
import { SqlUserStore, SqlSessionStore, SqlTokenStore } from 'node-auth-core/adapters/sql';

// Provide a query executor — any function that runs parameterized SQL
const exec = (sql, params) => prisma.$queryRawUnsafe(sql, ...params);

const adapters = {
  user: new SqlUserStore(exec),
  session: new SqlSessionStore(exec),
  token: new SqlTokenStore(exec),
};
```

### MongoDB

```ts
import { MongoUserStore, MongoSessionStore, MongoTokenStore } from 'node-auth-core/adapters/mongodb';

const adapters = {
  user: new MongoUserStore(db.collection('users')),
  session: new MongoSessionStore(db.collection('sessions')),
  token: new MongoTokenStore(db.collection('tokens')),
};
```

### Redis (sessions + tokens)

```ts
import Redis from 'ioredis';
import { RedisSessionStore, RedisTokenStore, RedisRateLimitStore } from 'node-auth-core/adapters/redis';

const redis = new Redis(process.env.REDIS_URL);

const adapters = {
  session: new RedisSessionStore(redis),
  token: new RedisTokenStore(redis),
  rateLimit: new RedisRateLimitStore(redis),
};
```

---

## Authentication Strategies

### Local (email + password)

```ts
import { register, login, verifyEmail, forgotPassword, resetPassword } from 'node-auth-core/strategies/local';

// Register
const { user, emailVerificationToken } = await register({ email, password }, auth);

// Login
const { user, tokens, mfaRequired } = await login({ email, password }, auth, { ip });

// Verify email
await verifyEmail({ token: req.query.token }, auth);

// Password reset
const result = await forgotPassword({ email }, auth);
if (result) sendResetEmail(result.resetToken);

await resetPassword({ token, newPassword }, auth);
```

### OAuth 2.0

```ts
import { buildAuthorizationUrl, handleOAuthCallback, PROVIDERS } from 'node-auth-core/strategies/oauth';

const provider = { ...PROVIDERS.google, clientId: '...', clientSecret: '...' };

// Step 1: redirect
const { url, state, codeVerifier } = buildAuthorizationUrl(provider, redirectUri);
// Store state + codeVerifier in session

// Step 2: callback
const { user, tokens, isNewUser } = await handleOAuthCallback(
  provider,
  { code, state, storedState, codeVerifier, redirectUri },
  auth,
  async (profile) => {
    // You control the linking policy
    const existing = await db.findByEmail(profile.email);
    return existing
      ? { user: existing, isNewUser: false }
      : { user: await db.createUser(profile), isNewUser: true };
  },
);
```

### Passwordless (magic link + OTP)

```ts
import { requestMagicLink, verifyMagicLink, requestOTP, verifyOTP } from 'node-auth-core/strategies/passwordless';

// Magic link
const result = await requestMagicLink({ email }, auth);
if (result) sendEmail(result.token);

const { user, tokens } = await verifyMagicLink({ token }, auth);

// OTP
const result = await requestOTP({ email }, auth);
if (result) sendSMS(result.otp);

const { user, tokens } = await verifyOTP({ email, otp }, auth);
```

### MFA (TOTP + backup codes)

```ts
import { setupTOTP, verifyTOTPSetup, validateTOTP, generateBackupCodes, verifyBackupCode } from 'node-auth-core/strategies/mfa';

// Setup
const { otpauthUri } = await setupTOTP(user, auth);
// Show QR code from otpauthUri

// Confirm setup
await verifyTOTPSetup(user, totpCode, auth);

// Validate on login
const valid = await validateTOTP(user, totpCode, auth);

// Backup codes
const { codes } = await generateBackupCodes(user, auth);
// Show codes once — they are hashed in storage
```

---

## Middleware

### Express

```ts
import {
  createAuthenticateMiddleware,
  createProtectMiddleware,
  createRequireRoleMiddleware,
  createRequireMFAMiddleware,
} from 'node-auth-core/middleware/express';

app.use(createAuthenticateMiddleware(auth));          // attaches req.auth if valid token
app.get('/admin', createProtectMiddleware(auth), createRequireRoleMiddleware(auth, 'admin'), handler);
app.get('/secure', createProtectMiddleware(auth), createRequireMFAMiddleware(auth), handler);
```

### Fastify

```ts
import { createProtectHook, createRequireRoleHook } from 'node-auth-core/middleware/fastify';

fastify.get('/admin', { preHandler: [createProtectHook(auth), createRequireRoleHook(auth, 'admin')] }, handler);
```

### Hono

```ts
import { honoProtect, honoRequireRole } from 'node-auth-core/middleware/hono';

app.get('/admin', honoProtect(auth), honoRequireRole(auth, 'admin'), handler);
```

---

## Audit Events

```ts
import { auditEmitter } from 'node-auth-core';

auditEmitter.on('user.login', (event) => {
  logger.info({ userId: event.userId, ip: event.ip }, 'User logged in');
});

auditEmitter.on('security.refresh_reuse_detected', (event) => {
  alertSecurityTeam(event);
});

// Or use an async handler for reliable delivery
auditEmitter.setAsyncHandler(async (event) => {
  await db.insertAuditLog(event);
});
```

---

## Session Management

```ts
import { rotateRefreshToken, revokeSession, revokeAllSessions } from 'node-auth-core';

// Refresh tokens
const { tokens } = await rotateRefreshToken(refreshToken, auth);

// Revoke a single session
await revokeSession(sessionId, auth);

// Revoke all sessions (e.g. on password change)
await revokeAllSessions(userId, auth);
```

---

## Security Model

- **Passwords**: Argon2id (64 MiB, 3 iterations, 4 threads) by default. bcrypt (12 rounds) as fallback.
- **Tokens**: `crypto.randomBytes` for opaque tokens, SHA-256 hashed before storage.
- **Comparisons**: `crypto.timingSafeEqual` everywhere — no `===` for secrets.
- **JWTs**: `alg` header validated on every verify — `alg:none` attacks rejected.
- **Refresh tokens**: Rotated on every use. Reuse triggers full session revocation.
- **PKCE**: S256 only — `plain` method rejected.
- **Cookies**: `HttpOnly`, `Secure`, `SameSite=Strict` by default.
- **Rate limiting**: Sliding window, per-IP and per-account.
- **Errors**: Internal details (stack traces, SQL errors) never returned to clients.

---

## License

MIT
