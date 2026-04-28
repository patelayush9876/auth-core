import type {
  BaseUser,
  ResolvedAuthConfig,
  AuthRequest,
  AuthContext,
  Session,
} from '../types/index.js';
import { verifyAccessToken } from '../crypto/jwt.js';
import { Errors } from '../errors.js';

/**
 * Security headers applied to all auth responses.
 * Prevents caching of sensitive auth data.
 */
export const AUTH_SECURITY_HEADERS: Record<string, string> = {
  'Cache-Control': 'no-store',
  'Pragma': 'no-cache',
  'X-Content-Type-Options': 'nosniff',
};

/**
 * Extract a Bearer token from the Authorization header.
 */
export function extractBearerToken(headers: AuthRequest['headers']): string | null {
  const auth = headers['authorization'];
  const value = Array.isArray(auth) ? auth[0] : auth;
  if (!value || !value.startsWith('Bearer ')) return null;
  return value.slice(7).trim() || null;
}

/**
 * Extract a token from a cookie.
 */
export function extractCookieToken(
  cookies: AuthRequest['cookies'],
  cookieName: string,
): string | null {
  return cookies[cookieName] ?? null;
}

/**
 * Core authenticate function — framework-agnostic.
 * Tries Bearer header first, then cookie.
 * Returns null (non-blocking) if no valid token is found.
 */
export async function authenticate<TUser extends BaseUser>(
  req: AuthRequest,
  config: ResolvedAuthConfig<TUser>,
  options: { priority?: 'bearer' | 'cookie' } = {},
): Promise<AuthContext<TUser> | null> {
  const priority = options.priority ?? 'bearer';

  let token: string | null = null;

  if (priority === 'bearer') {
    token = extractBearerToken(req.headers) ?? extractCookieToken(req.cookies, config.session.cookieName);
  } else {
    token = extractCookieToken(req.cookies, config.session.cookieName) ?? extractBearerToken(req.headers);
  }

  if (!token) return null;

  try {
    const payload = await verifyAccessToken(token, config.accessToken);

    const userId = payload.sub;
    const sessionId = payload['sessionId'] as string | undefined;

    if (!userId) return null;

    const user = await config.adapters.user.findById(userId);
    if (!user) return null;

    let session: Session | null = null;
    if (sessionId) {
      session = await config.adapters.session.findById(sessionId);
      if (!session || session.expiresAt < new Date()) return null;

      // Update last active
      await config.adapters.session.update(sessionId, { lastActiveAt: new Date() });
    }

    if (!session) return null;

    return { user, session };
  } catch {
    return null;
  }
}

/**
 * Protect middleware — calls authenticate and throws 401 if unauthenticated.
 */
export async function protect<TUser extends BaseUser>(
  req: AuthRequest,
  config: ResolvedAuthConfig<TUser>,
  options: { priority?: 'bearer' | 'cookie'; redirectTo?: string } = {},
): Promise<AuthContext<TUser>> {
  const ctx = await authenticate(req, config, options);
  if (!ctx) {
    throw Errors.tokenInvalid();
  }
  return ctx;
}

/**
 * Require one of the specified roles.
 * Must be called after protect().
 */
export function requireRole<TUser extends BaseUser>(
  ctx: AuthContext<TUser>,
  ...roles: string[]
): void {
  const hasRole = roles.some((r) => ctx.user.roles.includes(r));
  if (!hasRole) {
    throw new (class extends Error {
      readonly code = 'FORBIDDEN';
      readonly statusCode = 403;
    })(`Requires one of roles: ${roles.join(', ')}`);
  }
}

/**
 * Require MFA verification on the current session.
 * Returns MFA_REQUIRED error if the session was not MFA-verified.
 */
export function requireMFA<TUser extends BaseUser>(ctx: AuthContext<TUser>): void {
  if (!ctx.session.mfaVerified) {
    throw Errors.mfaRequired();
  }
}

/**
 * Serialize a cookie string with the configured options.
 */
export function serializeCookie(
  name: string,
  value: string,
  options: {
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: 'Strict' | 'Lax' | 'None';
    path?: string;
    domain?: string;
    maxAge?: number;
    expires?: Date;
  } = {},
): string {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.httpOnly) parts.push('HttpOnly');
  if (options.secure) parts.push('Secure');
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  if (options.path) parts.push(`Path=${options.path}`);
  if (options.domain) parts.push(`Domain=${options.domain}`);
  if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
  if (options.expires) parts.push(`Expires=${options.expires.toUTCString()}`);
  return parts.join('; ');
}
