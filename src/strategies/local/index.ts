import type { BaseUser, ResolvedAuthConfig, TokenPair, Session } from '../../types/index.js';
import { hashPassword, verifyPassword, needsRehash } from '../../crypto/password.js';
import { generateOpaqueToken, hashToken } from '../../crypto/tokens.js';
import { parseDuration } from '../../config.js';
import { Errors } from '../../errors.js';
import { emitAudit } from '../../audit.js';
import { createSession } from '../../session.js';
import { checkRateLimit } from '../../ratelimit.js';

// zxcvbn is a CommonJS module — import dynamically
async function checkPasswordStrength(password: string): Promise<number> {
  const { default: zxcvbn } = await import('zxcvbn');
  return zxcvbn(password).score;
}

/** Normalize email: lowercase + trim. */
export function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}

export interface RegisterInput {
  email: string;
  password: string;
  /** Any additional fields your TUser requires. */
  [key: string]: unknown;
}

export interface RegisterResult<TUser extends BaseUser> {
  user: TUser;
  /** Raw email verification token — send this in the verification email. */
  emailVerificationToken: string;
}

/**
 * Register a new user with email + password.
 *
 * Flow:
 * 1. Normalize email
 * 2. Check for existing account
 * 3. Validate password strength (zxcvbn)
 * 4. Hash password (Argon2id)
 * 5. Create user
 * 6. Issue email verification token
 * 7. Emit audit event
 */
export async function register<TUser extends BaseUser>(
  input: RegisterInput,
  config: ResolvedAuthConfig<TUser>,
  meta: { ip?: string | null; userAgent?: string | null } = {},
): Promise<RegisterResult<TUser>> {
  const { adapters, hooks } = config;

  // Rate limit
  if (config.rateLimit.enabled && adapters.rateLimit) {
    const key = `register:ip:${meta.ip ?? 'unknown'}`;
    await checkRateLimit(adapters.rateLimit, key, config.rateLimit.register);
  }

  if (hooks.onBeforeRegister) {
    await hooks.onBeforeRegister(input as Record<string, unknown>);
  }

  const email = normalizeEmail(input.email);

  // Check for duplicate
  const existing = await adapters.user.findByEmail(email);
  if (existing) throw Errors.emailAlreadyExists();

  // Password strength
  const score = await checkPasswordStrength(input.password);
  if (score < config.password.minStrengthScore) {
    throw Errors.passwordTooWeak(score);
  }

  const passwordHash = await hashPassword(input.password, config.password);

  // Build user data — spread extra fields, override security-sensitive ones
  const userData = {
    ...input,
    email,
    passwordHash,
    emailVerified: false,
    roles: (input['roles'] as string[] | undefined) ?? [],
    mfaEnabled: false,
    mfaEnforcement: config.mfa.enforcement,
    lockedUntil: null,
    failedLoginAttempts: 0,
  } as Omit<TUser, 'id' | 'createdAt' | 'updatedAt'>;

  const user = await adapters.user.create(userData);

  // Issue email verification token
  const rawToken = generateOpaqueToken(32);
  const tokenHash = hashToken(rawToken);
  const ttl = parseDuration('24h');

  await adapters.token.save({
    tokenHash,
    userId: user.id,
    type: 'email_verification',
    expiresAt: new Date(Date.now() + ttl),
    consumed: false,
  });

  if (hooks.onAfterRegister) {
    await hooks.onAfterRegister(user);
  }

  await emitAudit('user.registered', {
    userId: user.id,
    sessionId: null,
    ip: meta.ip ?? null,
    userAgent: meta.userAgent ?? null,
  });

  return { user, emailVerificationToken: rawToken };
}

export interface LoginInput {
  email: string;
  password: string;
}

export interface LoginResult<TUser extends BaseUser> {
  user: TUser;
  session: Session;
  tokens: TokenPair;
  /** True if MFA is required before the session is fully authenticated. */
  mfaRequired: boolean;
}

/**
 * Authenticate a user with email + password.
 *
 * SECURITY:
 * - Uses constant-time comparison via argon2.verify / bcrypt.compare
 * - Tracks failed attempts and locks account after N failures
 * - Always runs the same code path for unknown email vs wrong password
 *   to prevent user enumeration via timing
 */
export async function login<TUser extends BaseUser>(
  input: LoginInput,
  config: ResolvedAuthConfig<TUser>,
  meta: { ip?: string | null; userAgent?: string | null } = {},
): Promise<LoginResult<TUser>> {
  const { adapters, hooks } = config;

  // Rate limit by IP
  if (config.rateLimit.enabled && adapters.rateLimit) {
    const key = `login:ip:${meta.ip ?? 'unknown'}`;
    await checkRateLimit(adapters.rateLimit, key, config.rateLimit.login);
  }

  const email = normalizeEmail(input.email);

  if (hooks.onBeforeLogin) {
    await hooks.onBeforeLogin(email, meta.ip ?? null);
  }

  const user = await adapters.user.findByEmail(email);

  // Always hash even if user not found — prevents timing-based user enumeration
  const dummyHash =
    '$argon2id$v=19$m=65536,t=3,p=4$dummysaltdummysalt$dummyhashvaluedummyhashvaluedummyhashvalue';

  const passwordHash = (user as (TUser & { passwordHash?: string }) | null)?.passwordHash ?? dummyHash;

  const passwordValid = await verifyPassword(input.password, passwordHash, config.password);

  if (!user || !passwordValid) {
    if (user) {
      // Increment failed attempts
      const attempts = user.failedLoginAttempts + 1;
      const lockThreshold = 5; // TODO: make configurable
      const updates: Partial<TUser> = { failedLoginAttempts: attempts } as Partial<TUser>;

      if (attempts >= lockThreshold) {
        const lockDuration = parseDuration('15m');
        (updates as Record<string, unknown>)['lockedUntil'] = new Date(Date.now() + lockDuration);
        await adapters.user.update(user.id, updates);
        await emitAudit('user.locked', {
          userId: user.id,
          sessionId: null,
          ip: meta.ip ?? null,
          userAgent: meta.userAgent ?? null,
          metadata: { attempts },
        });
      } else {
        await adapters.user.update(user.id, updates);
      }

      // Rate limit by account
      if (config.rateLimit.enabled && adapters.rateLimit) {
        const key = `login:account:${user.id}`;
        await checkRateLimit(adapters.rateLimit, key, config.rateLimit.login);
      }
    }

    if (hooks.onLoginFailed) {
      await hooks.onLoginFailed(email, meta.ip ?? null, 'invalid_credentials');
    }

    await emitAudit('user.login_failed', {
      userId: user?.id ?? null,
      sessionId: null,
      ip: meta.ip ?? null,
      userAgent: meta.userAgent ?? null,
      metadata: { email },
    });

    throw Errors.invalidCredentials();
  }

  // Check account lock
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    if (hooks.onLoginFailed) {
      await hooks.onLoginFailed(email, meta.ip ?? null, 'account_locked');
    }
    throw Errors.accountLocked(user.lockedUntil);
  }

  // Reset failed attempts on successful login
  if (user.failedLoginAttempts > 0) {
    await adapters.user.update(user.id, {
      failedLoginAttempts: 0,
      lockedUntil: null,
    } as Partial<TUser>);
  }

  // Rehash if cost factors changed
  const userWithHash = user as TUser & { passwordHash?: string };
  if (userWithHash.passwordHash && await needsRehash(userWithHash.passwordHash, config.password)) {
    const newHash = await hashPassword(input.password, config.password);
    await adapters.user.update(user.id, { passwordHash: newHash } as Partial<TUser>);
  }

  const mfaRequired =
    config.mfa.enforcement === 'required' ||
    (config.mfa.enforcement === 'optional' && user.mfaEnabled);

  const { session, tokens } = await createSession(user, config, {
    ...meta,
    mfaVerified: !mfaRequired,
  });

  if (hooks.onAfterLogin) {
    await hooks.onAfterLogin(user, session);
  }

  await emitAudit('user.login', {
    userId: user.id,
    sessionId: session.id,
    ip: meta.ip ?? null,
    userAgent: meta.userAgent ?? null,
  });

  return { user, session, tokens, mfaRequired };
}

export interface VerifyEmailInput {
  token: string;
}

/**
 * Verify a user's email address using the token sent during registration.
 */
export async function verifyEmail<TUser extends BaseUser>(
  input: VerifyEmailInput,
  config: ResolvedAuthConfig<TUser>,
): Promise<TUser> {
  const { adapters } = config;
  const tokenHash = hashToken(input.token);

  const stored = await adapters.token.consume(tokenHash, 'email_verification');
  if (!stored) throw Errors.tokenInvalid();
  if (stored.expiresAt < new Date()) throw Errors.tokenExpired();

  const user = await adapters.user.update(stored.userId, {
    emailVerified: true,
  } as Partial<TUser>);

  return user;
}

export interface ForgotPasswordInput {
  email: string;
}

export interface ForgotPasswordResult {
  /** Raw reset token — send this in the reset email. */
  resetToken: string;
}

/**
 * Issue a password reset token.
 * Always returns success even if the email doesn't exist — prevents user enumeration.
 */
export async function forgotPassword<TUser extends BaseUser>(
  input: ForgotPasswordInput,
  config: ResolvedAuthConfig<TUser>,
  meta: { ip?: string | null } = {},
): Promise<ForgotPasswordResult | null> {
  const { adapters } = config;

  if (config.rateLimit.enabled && adapters.rateLimit) {
    const key = `forgot:ip:${meta.ip ?? 'unknown'}`;
    await checkRateLimit(adapters.rateLimit, key, config.rateLimit.forgotPassword);
  }

  const email = normalizeEmail(input.email);
  const user = await adapters.user.findByEmail(email);

  // Return null silently if user not found — caller should respond with 200 regardless
  if (!user) return null;

  const rawToken = generateOpaqueToken(32);
  const tokenHash = hashToken(rawToken);

  await adapters.token.save({
    tokenHash,
    userId: user.id,
    type: 'password_reset',
    expiresAt: new Date(Date.now() + parseDuration('15m')),
    consumed: false,
  });

  return { resetToken: rawToken };
}

export interface ResetPasswordInput {
  token: string;
  newPassword: string;
}

/**
 * Reset a user's password using a valid reset token.
 * Invalidates all existing sessions on success.
 */
export async function resetPassword<TUser extends BaseUser>(
  input: ResetPasswordInput,
  config: ResolvedAuthConfig<TUser>,
  meta: { ip?: string | null; userAgent?: string | null } = {},
): Promise<void> {
  const { adapters } = config;
  const tokenHash = hashToken(input.token);

  const stored = await adapters.token.consume(tokenHash, 'password_reset');
  if (!stored) throw Errors.tokenInvalid();
  if (stored.expiresAt < new Date()) throw Errors.tokenExpired();

  const score = await checkPasswordStrength(input.newPassword);
  if (score < config.password.minStrengthScore) {
    throw Errors.passwordTooWeak(score);
  }

  const newHash = await hashPassword(input.newPassword, config.password);
  await adapters.user.update(stored.userId, { passwordHash: newHash } as Partial<TUser>);

  // Revoke all sessions — force re-login
  await adapters.session.deleteAllForUser(stored.userId);

  await emitAudit('user.password_changed', {
    userId: stored.userId,
    sessionId: null,
    ip: meta.ip ?? null,
    userAgent: meta.userAgent ?? null,
  });

  await emitAudit('session.revoked_all', {
    userId: stored.userId,
    sessionId: null,
    ip: meta.ip ?? null,
    userAgent: meta.userAgent ?? null,
    metadata: { reason: 'password_reset' },
  });
}
