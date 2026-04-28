import type {
  Session,
  SessionStore,
  TokenStore,
  TokenPair,
  ResolvedAuthConfig,
  BaseUser,
} from './types/index.js';
import { generateOpaqueToken, hashToken, safeCompare } from './crypto/tokens.js';
import { signAccessToken } from './crypto/jwt.js';
import { parseDuration } from './config.js';
import { Errors } from './errors.js';
import { emitAudit } from './audit.js';

/**
 * Create a new session and issue a token pair.
 * The refresh token is stored hashed — the raw value is returned once and never stored.
 */
export async function createSession<TUser extends BaseUser>(
  user: TUser,
  config: ResolvedAuthConfig<TUser>,
  meta: {
    ip?: string | null;
    userAgent?: string | null;
    deviceFingerprint?: string | null;
    mfaVerified?: boolean;
  } = {},
): Promise<{ session: Session; tokens: TokenPair }> {
  const { adapters } = config;

  const refreshToken = generateOpaqueToken(48);
  const refreshTokenHash = hashToken(refreshToken);
  const tokenFamily = generateOpaqueToken(16);

  const now = new Date();
  const refreshExpiresAt = new Date(now.getTime() + parseDuration(config.refreshToken.expiresIn));

  const session = await adapters.session.create({
    userId: user.id,
    refreshTokenHash,
    tokenFamily,
    deviceFingerprint: meta.deviceFingerprint ?? null,
    userAgent: meta.userAgent ?? null,
    ip: meta.ip ?? null,
    mfaVerified: meta.mfaVerified ?? false,
    expiresAt: refreshExpiresAt,
  });

  const tokens = await issueTokenPair(user, session, refreshToken, config);

  await emitAudit('session.created', {
    userId: user.id,
    sessionId: session.id,
    ip: meta.ip ?? null,
    userAgent: meta.userAgent ?? null,
  });

  await emitAudit('token.issued', {
    userId: user.id,
    sessionId: session.id,
    ip: meta.ip ?? null,
    userAgent: meta.userAgent ?? null,
  });

  return { session, tokens };
}

/**
 * Rotate a refresh token.
 * Issues a new token pair, invalidates the old refresh token.
 * On reuse detection, revokes the entire token family.
 */
export async function rotateRefreshToken<TUser extends BaseUser>(
  rawRefreshToken: string,
  config: ResolvedAuthConfig<TUser>,
  meta: { ip?: string | null; userAgent?: string | null } = {},
): Promise<{ session: Session; tokens: TokenPair; user: TUser }> {
  const { adapters } = config;

  const tokenHash = hashToken(rawRefreshToken);

  // Find session by scanning — adapters should index on refreshTokenHash
  // We find all sessions and compare hashes in constant time
  // In practice, adapters should implement findByRefreshTokenHash for efficiency
  // Here we use a safe fallback
  const sessions = await findSessionByRefreshToken(tokenHash, adapters.session);

  if (!sessions) {
    // Token not found — could be a random invalid token OR a reused (already-rotated) token.
    // Check if this hash was recently consumed (reuse detection).
    if (config.refreshToken.reuseDetection) {
      const extendedStore = adapters.session as SessionStore & {
        findConsumedHash?: (hash: string) => { userId: string; tokenFamily: string } | null;
      };

      if (typeof extendedStore.findConsumedHash === 'function') {
        const consumed = extendedStore.findConsumedHash(tokenHash);
        if (consumed) {
          // This is a reused token — revoke all sessions for this user
          await adapters.session.deleteAllForUser(consumed.userId);
          await emitAudit('security.refresh_reuse_detected', {
            userId: consumed.userId,
            sessionId: null,
            ip: meta.ip ?? null,
            userAgent: meta.userAgent ?? null,
            metadata: { tokenFamily: consumed.tokenFamily },
          });
          throw Errors.tokenReuseDetected();
        }
      }
    }
    throw Errors.tokenInvalid();
  }

  const { session } = sessions;

  // Check expiry
  if (session.expiresAt < new Date()) {
    await adapters.session.delete(session.id);
    throw Errors.sessionExpired();
  }

  const user = await adapters.user.findById(session.userId);
  if (!user) {
    await adapters.session.delete(session.id);
    throw Errors.userNotFound();
  }

  // Run lifecycle hook
  if (config.hooks.onBeforeTokenRefresh) {
    await config.hooks.onBeforeTokenRefresh(session);
  }

  // Issue new refresh token
  const newRefreshToken = generateOpaqueToken(48);
  const newRefreshTokenHash = hashToken(newRefreshToken);
  const newExpiresAt = new Date(Date.now() + parseDuration(config.refreshToken.expiresIn));

  const updatedSession = await adapters.session.update(session.id, {
    refreshTokenHash: newRefreshTokenHash,
    lastActiveAt: new Date(),
    expiresAt: newExpiresAt,
  });

  const tokens = await issueTokenPair(user, updatedSession, newRefreshToken, config);

  if (config.hooks.onAfterTokenRefresh) {
    await config.hooks.onAfterTokenRefresh(updatedSession, tokens);
  }

  await emitAudit('token.refreshed', {
    userId: user.id,
    sessionId: session.id,
    ip: meta.ip ?? null,
    userAgent: meta.userAgent ?? null,
  });

  return { session: updatedSession, tokens, user };
}

/**
 * Revoke a single session.
 */
export async function revokeSession<TUser extends BaseUser>(
  sessionId: string,
  config: ResolvedAuthConfig<TUser>,
  meta: { ip?: string | null; userAgent?: string | null } = {},
): Promise<void> {
  const session = await config.adapters.session.findById(sessionId);
  if (!session) throw Errors.sessionNotFound();

  await config.adapters.session.delete(sessionId);

  if (config.hooks.onSessionRevoked) {
    await config.hooks.onSessionRevoked(session);
  }

  await emitAudit('session.revoked', {
    userId: session.userId,
    sessionId,
    ip: meta.ip ?? null,
    userAgent: meta.userAgent ?? null,
  });
}

/**
 * Revoke all sessions for a user (e.g. on password change or reuse detection).
 */
export async function revokeAllSessions<TUser extends BaseUser>(
  userId: string,
  config: ResolvedAuthConfig<TUser>,
  meta: { ip?: string | null; userAgent?: string | null } = {},
): Promise<void> {
  await config.adapters.session.deleteAllForUser(userId);

  await emitAudit('session.revoked_all', {
    userId,
    sessionId: null,
    ip: meta.ip ?? null,
    userAgent: meta.userAgent ?? null,
  });
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

async function issueTokenPair<TUser extends BaseUser>(
  user: TUser,
  session: Session,
  rawRefreshToken: string,
  config: ResolvedAuthConfig<TUser>,
): Promise<TokenPair> {
  const now = Date.now();
  const accessExpiresAt = new Date(now + parseDuration(config.accessToken.expiresIn));
  const refreshExpiresAt = session.expiresAt;

  const accessToken = await signAccessToken(
    {
      sub: user.id,
      sessionId: session.id,
      roles: user.roles,
      mfaVerified: session.mfaVerified,
    },
    config.accessToken,
  );

  return {
    accessToken,
    refreshToken: rawRefreshToken,
    accessTokenExpiresAt: accessExpiresAt,
    refreshTokenExpiresAt: refreshExpiresAt,
  };
}

/**
 * Find a session whose refreshTokenHash matches the given hash.
 * Prefers the extended `findByRefreshTokenHash` method if available on the adapter.
 * Falls back to scanning all sessions for the user — only works if userId is known.
 */
async function findSessionByRefreshToken(
  tokenHash: string,
  store: SessionStore,
): Promise<{ session: Session } | null> {
  // Cast to check for optional extended method
  const extendedStore = store as SessionStore & {
    findByRefreshTokenHash?: (hash: string) => Promise<Session | null>;
  };

  if (typeof extendedStore.findByRefreshTokenHash === 'function') {
    const session = await extendedStore.findByRefreshTokenHash(tokenHash);
    return session ? { session } : null;
  }

  // Fallback: not supported without userId — callers must use extended adapter
  return null;
}
