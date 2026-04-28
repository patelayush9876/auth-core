import type {
  AuthConfig,
  ResolvedAuthConfig,
  BaseUser,
  AccessTokenConfig,
  RefreshTokenConfig,
  SessionConfig,
  MFAConfig,
  RateLimitConfig,
} from './types/index.js';
import { Errors } from './errors.js';
import { resolvePasswordConfig } from './crypto/password.js';

const isDev = (): boolean =>
  process.env['NODE_ENV'] === 'development' || process.env['NODE_ENV'] === 'test';

/**
 * Resolve a partial AuthConfig into a fully-typed ResolvedAuthConfig with safe defaults.
 * Throws on obviously insecure or missing required config.
 */
export function resolveConfig<TUser extends BaseUser>(
  config: AuthConfig<TUser>,
): ResolvedAuthConfig<TUser> {
  const development = config.isDevelopment ?? isDev();

  // ── Secret validation ──────────────────────────────────────────────────────
  const algorithm = config.accessToken?.algorithm ?? 'HS256';

  if (algorithm === 'HS256') {
    if (!config.secret) {
      if (!development) {
        throw Errors.missingSecret();
      }
      // In development, warn loudly but don't crash
      console.warn(
        '[node-auth-core] WARNING: No `secret` provided. ' +
          'Using an insecure default. Set a strong secret before going to production.',
      );
    } else if (!development && config.secret.length < 32) {
      throw Errors.invalidConfig(
        '`secret` must be at least 32 characters for production use.',
      );
    }
  }

  const secret = config.secret ?? 'INSECURE_DEV_SECRET_DO_NOT_USE_IN_PRODUCTION';

  // ── Access token ───────────────────────────────────────────────────────────
  const accessToken: AccessTokenConfig = {
    algorithm,
    expiresIn: config.accessToken?.expiresIn ?? '15m',
    issuer: config.accessToken?.issuer,
    audience: config.accessToken?.audience,
    // For HS256, privateKey holds the secret; for RS256/ES256 it's a PEM key
    privateKey: algorithm === 'HS256' ? secret : config.accessToken?.privateKey,
    publicKey: config.accessToken?.publicKey,
  };

  // ── Refresh token ──────────────────────────────────────────────────────────
  const refreshToken: RefreshTokenConfig = {
    expiresIn: config.refreshToken?.expiresIn ?? '7d',
    rotateOnUse: config.refreshToken?.rotateOnUse ?? true,
    reuseDetection: config.refreshToken?.reuseDetection ?? true,
  };

  // ── Session ────────────────────────────────────────────────────────────────
  const session: SessionConfig = {
    cookieName: config.session?.cookieName ?? '__session',
    cookie: {
      httpOnly: config.session?.cookie?.httpOnly ?? true,
      secure: config.session?.cookie?.secure ?? !development,
      sameSite: config.session?.cookie?.sameSite ?? 'Strict',
      path: config.session?.cookie?.path ?? '/',
      domain: config.session?.cookie?.domain,
      maxAge: config.session?.cookie?.maxAge,
    },
    absoluteTimeout: config.session?.absoluteTimeout ?? '30d',
    idleTimeout: config.session?.idleTimeout ?? '7d',
  };

  // ── MFA ────────────────────────────────────────────────────────────────────
  const mfa: MFAConfig = {
    enforcement: config.mfa?.enforcement ?? 'optional',
    issuer: config.mfa?.issuer ?? 'node-auth-core',
  };

  // ── Rate limiting ──────────────────────────────────────────────────────────
  const rateLimit: RateLimitConfig = {
    enabled: config.rateLimit?.enabled ?? true,
    store: config.rateLimit?.store ?? 'memory',
    login: config.rateLimit?.login ?? { windowMs: 15 * 60 * 1000, max: 10 },
    register: config.rateLimit?.register ?? { windowMs: 60 * 60 * 1000, max: 5 },
    forgotPassword: config.rateLimit?.forgotPassword ?? { windowMs: 60 * 60 * 1000, max: 5 },
    verifyOtp: config.rateLimit?.verifyOtp ?? { windowMs: 5 * 60 * 1000, max: 5 },
  };

  return {
    secret,
    accessToken,
    refreshToken,
    password: resolvePasswordConfig(config.password),
    session,
    mfa,
    rateLimit,
    adapters: config.adapters,
    hooks: config.hooks ?? {},
    isDevelopment: development,
  };
}

/**
 * Parse a duration string (e.g. '15m', '7d', '1h') into milliseconds.
 */
export function parseDuration(duration: string): number {
  const match = /^(\d+)(ms|s|m|h|d|w)$/.exec(duration);
  if (!match) {
    throw Errors.invalidConfig(`Invalid duration string: '${duration}'`);
  }
  const value = parseInt(match[1] ?? '0', 10);
  const unit = match[2];
  const multipliers: Record<string, number> = {
    ms: 1,
    s: 1_000,
    m: 60_000,
    h: 3_600_000,
    d: 86_400_000,
    w: 604_800_000,
  };
  return value * (multipliers[unit ?? 'ms'] ?? 1);
}
