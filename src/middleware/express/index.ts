/**
 * Express middleware adapter (~30 lines of glue code).
 * Wraps the framework-agnostic core.
 */
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { BaseUser, ResolvedAuthConfig, AuthContext } from '../../types/index.js';
import {
  authenticate,
  protect,
  requireRole,
  requireMFA,
  AUTH_SECURITY_HEADERS,
} from '../core.js';
import { AuthError } from '../../errors.js';

declare module 'express' {
  interface Request {
    auth?: AuthContext;
  }
}

function toAuthRequest(req: Request) {
  return {
    headers: req.headers as Record<string, string | string[] | undefined>,
    cookies: (req.cookies ?? {}) as Record<string, string | undefined>,
    body: (req.body ?? {}) as Record<string, unknown>,
    ip: req.ip ?? null,
    userAgent: req.get('user-agent') ?? null,
  };
}

function applySecurityHeaders(res: Response): void {
  for (const [k, v] of Object.entries(AUTH_SECURITY_HEADERS)) {
    res.setHeader(k, v);
  }
}

/** Attach user + session to req.auth if a valid token is present. Non-blocking. */
export function createAuthenticateMiddleware<TUser extends BaseUser>(
  config: ResolvedAuthConfig<TUser>,
): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction) => {
    req.auth = (await authenticate(toAuthRequest(req), config)) as AuthContext | undefined ?? undefined;
    next();
  };
}

/** Block unauthenticated requests with 401. */
export function createProtectMiddleware<TUser extends BaseUser>(
  config: ResolvedAuthConfig<TUser>,
  options: { redirectTo?: string } = {},
): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction) => {
    applySecurityHeaders(res);
    try {
      req.auth = (await protect(toAuthRequest(req), config)) as AuthContext;
      next();
    } catch (err) {
      if (options.redirectTo) {
        res.redirect(302, options.redirectTo);
        return;
      }
      if (err instanceof AuthError) {
        res.status(err.statusCode).json(err.toJSON());
        return;
      }
      next(err);
    }
  };
}

/** Require roles — use after createProtectMiddleware. */
export function createRequireRoleMiddleware<TUser extends BaseUser>(
  config: ResolvedAuthConfig<TUser>,
  ...roles: string[]
): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.auth) {
      res.status(401).json({ code: 'TOKEN_INVALID', message: 'Unauthenticated', statusCode: 401 });
      return;
    }
    try {
      requireRole(req.auth as AuthContext<TUser>, ...roles);
      next();
    } catch {
      res.status(403).json({ code: 'FORBIDDEN', message: `Requires role: ${roles.join(' or ')}`, statusCode: 403 });
    }
  };
}

/** Require MFA — use after createProtectMiddleware. */
export function createRequireMFAMiddleware<TUser extends BaseUser>(
  config: ResolvedAuthConfig<TUser>,
): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.auth) {
      res.status(401).json({ code: 'TOKEN_INVALID', message: 'Unauthenticated', statusCode: 401 });
      return;
    }
    try {
      requireMFA(req.auth as AuthContext<TUser>);
      next();
    } catch (err) {
      if (err instanceof AuthError) {
        res.status(err.statusCode).json(err.toJSON());
        return;
      }
      next(err);
    }
  };
}
