/**
 * Fastify plugin adapter (~30 lines of glue code).
 * Wraps the framework-agnostic core.
 */
import type { FastifyRequest, FastifyReply, FastifyPluginCallback } from 'fastify';
import type { BaseUser, ResolvedAuthConfig, AuthContext } from '../../types/index.js';
import {
  authenticate,
  protect,
  requireRole,
  requireMFA,
  AUTH_SECURITY_HEADERS,
} from '../core.js';
import { AuthError } from '../../errors.js';

declare module 'fastify' {
  interface FastifyRequest {
    auth?: AuthContext;
  }
}

function toAuthRequest(req: FastifyRequest) {
  const userAgentHeader = req.headers['user-agent'];
  const userAgent =
    typeof userAgentHeader === 'string'
      ? userAgentHeader
      : Array.isArray(userAgentHeader)
        ? userAgentHeader[0] ?? null
        : null;

  return {
    headers: req.headers as Record<string, string | string[] | undefined>,
    cookies: (req.cookies ?? {}) as Record<string, string | undefined>,
    body: (req.body ?? {}) as Record<string, unknown>,
    ip: req.ip ?? null,
    userAgent,
  };
}

function applySecurityHeaders(reply: FastifyReply): void {
  for (const [k, v] of Object.entries(AUTH_SECURITY_HEADERS)) {
    void reply.header(k, v);
  }
}

/** Fastify preHandler — attaches auth context if token is valid. Non-blocking. */
export function createAuthenticateHook<TUser extends BaseUser>(
  config: ResolvedAuthConfig<TUser>,
) {
  return async (req: FastifyRequest): Promise<void> => {
    const ctx = await authenticate(toAuthRequest(req), config);
    if (ctx) req.auth = ctx as AuthContext;
  };
}

/** Fastify preHandler — blocks unauthenticated requests. */
export function createProtectHook<TUser extends BaseUser>(
  config: ResolvedAuthConfig<TUser>,
  options: { redirectTo?: string } = {},
) {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    applySecurityHeaders(reply);
    try {
      req.auth = (await protect(toAuthRequest(req), config)) as AuthContext;
    } catch (err) {
      if (options.redirectTo) {
        await reply.redirect(302, options.redirectTo);
        return;
      }
      if (err instanceof AuthError) {
        await reply.status(err.statusCode).send(err.toJSON());
        return;
      }
      throw err;
    }
  };
}

/** Fastify preHandler — requires roles. Use after createProtectHook. */
export function createRequireRoleHook<TUser extends BaseUser>(
  config: ResolvedAuthConfig<TUser>,
  ...roles: string[]
) {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!req.auth) {
      await reply.status(401).send({ code: 'TOKEN_INVALID', message: 'Unauthenticated', statusCode: 401 });
      return;
    }
    try {
      requireRole(req.auth as AuthContext<TUser>, ...roles);
    } catch {
      await reply.status(403).send({ code: 'FORBIDDEN', message: `Requires role: ${roles.join(' or ')}`, statusCode: 403 });
    }
  };
}

/** Fastify preHandler — requires MFA. Use after createProtectHook. */
export function createRequireMFAHook<TUser extends BaseUser>(
  config: ResolvedAuthConfig<TUser>,
) {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!req.auth) {
      await reply.status(401).send({ code: 'TOKEN_INVALID', message: 'Unauthenticated', statusCode: 401 });
      return;
    }
    try {
      requireMFA(req.auth as AuthContext<TUser>);
    } catch (err) {
      if (err instanceof AuthError) {
        await reply.status(err.statusCode).send(err.toJSON());
        return;
      }
      throw err;
    }
  };
}
