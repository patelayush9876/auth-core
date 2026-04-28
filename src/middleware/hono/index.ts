/**
 * Hono middleware adapter (~30 lines of glue code).
 * Wraps the framework-agnostic core.
 */
import type { Context, MiddlewareHandler } from 'hono';
import type { BaseUser, ResolvedAuthConfig, AuthContext } from '../../types/index.js';
import {
  authenticate,
  protect,
  requireRole,
  requireMFA,
  AUTH_SECURITY_HEADERS,
} from '../core.js';
import { AuthError } from '../../errors.js';

function toAuthRequest(c: Context) {
  const cookieHeader = c.req.header('cookie') ?? '';
  const cookies: Record<string, string> = Object.fromEntries(
    cookieHeader.split(';').map((p) => {
      const [k, ...v] = p.trim().split('=');
      return [k?.trim() ?? '', decodeURIComponent(v.join('='))];
    }),
  );

  return {
    headers: Object.fromEntries(c.req.raw.headers.entries()),
    cookies,
    body: {} as Record<string, unknown>,
    ip: c.req.header('x-forwarded-for') ?? c.req.header('x-real-ip') ?? null,
    userAgent: c.req.header('user-agent') ?? null,
  };
}

function applySecurityHeaders(c: Context): void {
  for (const [k, v] of Object.entries(AUTH_SECURITY_HEADERS)) {
    c.header(k, v);
  }
}

/** Hono middleware — attaches auth context if token is valid. Non-blocking. */
export function honoAuthenticate<TUser extends BaseUser>(
  config: ResolvedAuthConfig<TUser>,
): MiddlewareHandler {
  return async (c, next) => {
    const ctx = await authenticate(toAuthRequest(c), config);
    if (ctx) c.set('auth', ctx);
    await next();
  };
}

/** Hono middleware — blocks unauthenticated requests. */
export function honoProtect<TUser extends BaseUser>(
  config: ResolvedAuthConfig<TUser>,
  options: { redirectTo?: string } = {},
): MiddlewareHandler {
  return async (c, next) => {
    applySecurityHeaders(c);
    try {
      const ctx = await protect(toAuthRequest(c), config);
      c.set('auth', ctx);
      await next();
    } catch (err) {
      if (options.redirectTo) {
        return c.redirect(options.redirectTo, 302);
      }
      if (err instanceof AuthError) {
        return c.json(err.toJSON(), err.statusCode as Parameters<typeof c.json>[1]);
      }
      throw err;
    }
  };
}

/** Hono middleware — requires roles. Use after honoProtect. */
export function honoRequireRole<TUser extends BaseUser>(
  config: ResolvedAuthConfig<TUser>,
  ...roles: string[]
): MiddlewareHandler {
  return async (c, next) => {
    const auth = c.get('auth') as AuthContext<TUser> | undefined;
    if (!auth) {
      return c.json({ code: 'TOKEN_INVALID', message: 'Unauthenticated', statusCode: 401 }, 401);
    }
    try {
      requireRole(auth, ...roles);
      await next();
    } catch {
      return c.json({ code: 'FORBIDDEN', message: `Requires role: ${roles.join(' or ')}`, statusCode: 403 }, 403);
    }
  };
}

/** Hono middleware — requires MFA. Use after honoProtect. */
export function honoRequireMFA<TUser extends BaseUser>(
  config: ResolvedAuthConfig<TUser>,
): MiddlewareHandler {
  return async (c, next) => {
    const auth = c.get('auth') as AuthContext<TUser> | undefined;
    if (!auth) {
      return c.json({ code: 'TOKEN_INVALID', message: 'Unauthenticated', statusCode: 401 }, 401);
    }
    try {
      requireMFA(auth);
      await next();
    } catch (err) {
      if (err instanceof AuthError) {
        return c.json(err.toJSON(), err.statusCode as Parameters<typeof c.json>[1]);
      }
      throw err;
    }
  };
}
