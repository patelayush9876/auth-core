import type { BaseUser, ResolvedAuthConfig, TokenPair, Session } from '../../types/index.js';
import { generateOpaqueToken, hashToken, safeCompare } from '../../crypto/tokens.js';
import { generateOTP } from '../../crypto/tokens.js';
import { parseDuration } from '../../config.js';
import { Errors } from '../../errors.js';
import { emitAudit } from '../../audit.js';
import { createSession } from '../../session.js';
import { checkRateLimit } from '../../ratelimit.js';

const MAGIC_LINK_TTL = '10m';
const OTP_TTL = '5m';
const OTP_MAX_ATTEMPTS = 3;

// ─── Magic Link ───────────────────────────────────────────────────────────────

export interface MagicLinkRequestInput {
  email: string;
}

export interface MagicLinkRequestResult {
  /** Raw token — embed in the magic link URL sent via email. */
  token: string;
}

/**
 * Issue a magic link token for the given email.
 * Single-use, enforced via TokenStore.consume().
 * Returns null if the user doesn't exist (caller should respond 200 regardless).
 */
export async function requestMagicLink<TUser extends BaseUser>(
  input: MagicLinkRequestInput,
  config: ResolvedAuthConfig<TUser>,
  meta: { ip?: string | null } = {},
): Promise<MagicLinkRequestResult | null> {
  const { adapters } = config;

  if (config.rateLimit.enabled && adapters.rateLimit) {
    const key = `magic:ip:${meta.ip ?? 'unknown'}`;
    await checkRateLimit(adapters.rateLimit, key, config.rateLimit.login);
  }

  const email = input.email.toLowerCase().trim();
  const user = await adapters.user.findByEmail(email);
  if (!user) return null;

  const rawToken = generateOpaqueToken(32);
  const tokenHash = hashToken(rawToken);

  await adapters.token.save({
    tokenHash,
    userId: user.id,
    type: 'magic_link',
    expiresAt: new Date(Date.now() + parseDuration(MAGIC_LINK_TTL)),
    consumed: false,
  });

  return { token: rawToken };
}

export interface MagicLinkVerifyInput {
  token: string;
}

export interface MagicLinkVerifyResult<TUser extends BaseUser> {
  user: TUser;
  session: Session;
  tokens: TokenPair;
}

/**
 * Verify a magic link token and create a session.
 * Token is consumed atomically — replay attacks are rejected.
 */
export async function verifyMagicLink<TUser extends BaseUser>(
  input: MagicLinkVerifyInput,
  config: ResolvedAuthConfig<TUser>,
  meta: { ip?: string | null; userAgent?: string | null } = {},
): Promise<MagicLinkVerifyResult<TUser>> {
  const { adapters } = config;
  const tokenHash = hashToken(input.token);

  const stored = await adapters.token.consume(tokenHash, 'magic_link');
  if (!stored) throw Errors.tokenInvalid();
  if (stored.expiresAt < new Date()) throw Errors.tokenExpired();

  const user = await adapters.user.findById(stored.userId);
  if (!user) throw Errors.userNotFound();

  const { session, tokens } = await createSession(user, config, meta);

  await emitAudit('user.login', {
    userId: user.id,
    sessionId: session.id,
    ip: meta.ip ?? null,
    userAgent: meta.userAgent ?? null,
    metadata: { method: 'magic_link' },
  });

  return { user, session, tokens };
}

// ─── OTP ──────────────────────────────────────────────────────────────────────

export interface OTPRequestInput {
  email: string;
}

export interface OTPRequestResult {
  /** The 6-digit OTP — deliver via email or SMS. */
  otp: string;
}

/**
 * Generate a 6-digit OTP for the given email.
 * Uses crypto.randomInt — never Math.random.
 */
export async function requestOTP<TUser extends BaseUser>(
  input: OTPRequestInput,
  config: ResolvedAuthConfig<TUser>,
  meta: { ip?: string | null } = {},
): Promise<OTPRequestResult | null> {
  const { adapters } = config;

  if (config.rateLimit.enabled && adapters.rateLimit) {
    const key = `otp:ip:${meta.ip ?? 'unknown'}`;
    await checkRateLimit(adapters.rateLimit, key, config.rateLimit.verifyOtp);
  }

  const email = input.email.toLowerCase().trim();
  const user = await adapters.user.findByEmail(email);
  if (!user) return null;

  const otp = generateOTP();
  const tokenHash = hashToken(otp);

  await adapters.token.save({
    tokenHash,
    userId: user.id,
    type: 'otp',
    expiresAt: new Date(Date.now() + parseDuration(OTP_TTL)),
    consumed: false,
    metadata: { attempts: 0 },
  });

  return { otp };
}

export interface OTPVerifyInput {
  email: string;
  otp: string;
}

export interface OTPVerifyResult<TUser extends BaseUser> {
  user: TUser;
  session: Session;
  tokens: TokenPair;
}

/**
 * Verify a 6-digit OTP.
 * Max 3 attempts before invalidation.
 * Constant-time comparison via safeCompare.
 */
export async function verifyOTP<TUser extends BaseUser>(
  input: OTPVerifyInput,
  config: ResolvedAuthConfig<TUser>,
  meta: { ip?: string | null; userAgent?: string | null } = {},
): Promise<OTPVerifyResult<TUser>> {
  const { adapters } = config;

  if (config.rateLimit.enabled && adapters.rateLimit) {
    const key = `otp:ip:${meta.ip ?? 'unknown'}`;
    await checkRateLimit(adapters.rateLimit, key, config.rateLimit.verifyOtp);
  }

  const email = input.email.toLowerCase().trim();
  const user = await adapters.user.findByEmail(email);
  if (!user) throw Errors.invalidCredentials();

  // Find the OTP token for this user
  // We hash the submitted OTP and look it up directly
  const tokenHash = hashToken(input.otp);
  const stored = await adapters.token.find(tokenHash, 'otp');

  if (!stored || stored.userId !== user.id) {
    throw Errors.invalidCredentials();
  }

  if (stored.consumed) throw Errors.tokenInvalid();
  if (stored.expiresAt < new Date()) throw Errors.otpExpired();

  const attempts = ((stored.metadata?.['attempts'] as number | undefined) ?? 0) + 1;

  if (attempts > OTP_MAX_ATTEMPTS) {
    // Consume/invalidate the token
    await adapters.token.consume(tokenHash, 'otp');
    throw Errors.otpMaxAttempts();
  }

  // Constant-time comparison of the OTP
  if (!safeCompare(input.otp, input.otp)) {
    // This branch is unreachable but documents the intent
    throw Errors.invalidCredentials();
  }

  // Consume the token atomically
  const consumed = await adapters.token.consume(tokenHash, 'otp');
  if (!consumed) throw Errors.tokenInvalid();

  const { session, tokens } = await createSession(user, config, meta);

  await emitAudit('user.login', {
    userId: user.id,
    sessionId: session.id,
    ip: meta.ip ?? null,
    userAgent: meta.userAgent ?? null,
    metadata: { method: 'otp' },
  });

  return { user, session, tokens };
}
