/**
 * node-auth-core — self-hosted, framework-agnostic authentication for Node.js
 *
 * @example
 * ```ts
 * import { createAuth } from 'node-auth-core';
 * import { InMemoryUserStore, InMemorySessionStore, InMemoryTokenStore } from 'node-auth-core/adapters/memory';
 *
 * const auth = createAuth({
 *   secret: process.env.AUTH_SECRET,
 *   adapters: {
 *     user: new InMemoryUserStore(),
 *     session: new InMemorySessionStore(),
 *     token: new InMemoryTokenStore(),
 *   },
 * });
 * ```
 */

export { AuthError, Errors } from './errors.js';
export { resolveConfig, parseDuration } from './config.js';
export { auditEmitter, emitAudit } from './audit.js';
export { createSession, rotateRefreshToken, revokeSession, revokeAllSessions } from './session.js';
export { checkRateLimit, MemoryRateLimitStore } from './ratelimit.js';

// Crypto primitives
export {
  generateOpaqueToken,
  hashToken,
  safeCompare,
  safeCompareBuffers,
  secureRandomInt,
  generateOTP,
} from './crypto/tokens.js';
export {
  generateCodeVerifier,
  generateCodeChallenge,
  validateCodeVerifier,
} from './crypto/pkce.js';
export {
  hashPassword,
  verifyPassword,
  needsRehash,
  resolvePasswordConfig,
} from './crypto/password.js';
export {
  signAccessToken,
  verifyAccessToken,
  decodeTokenUnsafe,
  clearKeyCache,
} from './crypto/jwt.js';

// Middleware core
export {
  authenticate,
  protect,
  requireRole,
  requireMFA,
  serializeCookie,
  AUTH_SECURITY_HEADERS,
} from './middleware/core.js';

// All types
export type {
  BaseUser,
  Session,
  StoredToken,
  TokenType,
  TokenPair,
  JWTPayload,
  WebAuthnCredential,
  OAuthProfile,
  OAuthAccount,
  MFAEnforcement,
  TOTPSecret,
  BackupCode,
  UserStore,
  SessionStore,
  TokenStore,
  CredentialStore,
  OAuthStore,
  MFAStore,
  RateLimitStore,
  AuditEvent,
  AuditEventName,
  LifecycleHooks,
  CookieOptions,
  AccessTokenConfig,
  RefreshTokenConfig,
  PasswordConfig,
  SessionConfig,
  MFAConfig,
  RateLimitConfig,
  RateLimitWindowConfig,
  AuthConfig,
  ResolvedAuthConfig,
  AuthRequest,
  AuthContext,
  AuthErrorCode,
} from './types/index.js';

import type { BaseUser, AuthConfig, ResolvedAuthConfig } from './types/index.js';
import { resolveConfig } from './config.js';

/**
 * Create a configured auth instance.
 * Returns the resolved config — pass this to strategy functions and middleware.
 *
 * @example
 * ```ts
 * const auth = createAuth({ secret: 'my-secret', adapters: { ... } });
 * // auth is a ResolvedAuthConfig — pass it to login(), protect(), etc.
 * ```
 */
export function createAuth<TUser extends BaseUser>(
  config: AuthConfig<TUser>,
): ResolvedAuthConfig<TUser> {
  return resolveConfig(config);
}
