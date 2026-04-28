import { TOTP, Secret } from 'otpauth';
import bcrypt from 'bcrypt';
import type { BaseUser, ResolvedAuthConfig, TOTPSecret, BackupCode } from '../../types/index.js';
import { generateOpaqueToken } from '../../crypto/tokens.js';
import { safeCompareBuffers } from '../../crypto/tokens.js';
import { Errors } from '../../errors.js';
import { emitAudit } from '../../audit.js';

const BACKUP_CODE_COUNT = 10;
const BACKUP_CODE_BCRYPT_ROUNDS = 10; // Faster than Argon2 for bulk hashing
const TOTP_WINDOW = 1; // ±1 step (30s each side)

// ─── TOTP ─────────────────────────────────────────────────────────────────────

export interface TOTPSetupResult {
  /** Base32-encoded secret — store this, show QR to user. */
  secret: string;
  /** otpauth:// URI for QR code generation. */
  otpauthUri: string;
}

/**
 * Generate a new TOTP secret for a user.
 * The user must verify a code before the secret is marked as active.
 */
export async function setupTOTP<TUser extends BaseUser>(
  user: TUser,
  config: ResolvedAuthConfig<TUser>,
): Promise<TOTPSetupResult> {
  if (!config.adapters.mfa) throw Errors.adapterNotConfigured('mfa');

  const secret = new Secret({ size: 20 });
  const totp = new TOTP({
    issuer: config.mfa.issuer,
    label: user.email,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret,
  });

  await config.adapters.mfa.saveTOTP({
    userId: user.id,
    secret: secret.base32,
    verified: false,
    createdAt: new Date(),
  });

  return {
    secret: secret.base32,
    otpauthUri: totp.toString(),
  };
}

/**
 * Verify a TOTP code and mark the secret as active.
 * Must be called once after setup to confirm the user has the correct secret.
 */
export async function verifyTOTPSetup<TUser extends BaseUser>(
  user: TUser,
  code: string,
  config: ResolvedAuthConfig<TUser>,
): Promise<void> {
  if (!config.adapters.mfa) throw Errors.adapterNotConfigured('mfa');

  const stored = await config.adapters.mfa.findTOTP(user.id);
  if (!stored) throw Errors.mfaInvalid();

  const valid = validateTOTPCode(code, stored.secret, config.mfa.issuer, user.email);
  if (!valid) throw Errors.mfaInvalid();

  await config.adapters.mfa.saveTOTP({ ...stored, verified: true });
  await config.adapters.user.update(user.id, { mfaEnabled: true } as Partial<TUser>);

  await emitAudit('user.mfa_enabled', {
    userId: user.id,
    sessionId: null,
    ip: null,
    userAgent: null,
    metadata: { method: 'totp' },
  });
}

/**
 * Validate a TOTP code for authentication.
 * Allows ±1 window (30s each side) for clock drift.
 */
export async function validateTOTP<TUser extends BaseUser>(
  user: TUser,
  code: string,
  config: ResolvedAuthConfig<TUser>,
): Promise<boolean> {
  if (!config.adapters.mfa) throw Errors.adapterNotConfigured('mfa');

  const stored = await config.adapters.mfa.findTOTP(user.id);
  if (!stored || !stored.verified) return false;

  return validateTOTPCode(code, stored.secret, config.mfa.issuer, user.email);
}

function validateTOTPCode(
  code: string,
  secretBase32: string,
  issuer: string,
  label: string,
): boolean {
  const totp = new TOTP({
    issuer,
    label,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(secretBase32),
  });

  const delta = totp.validate({ token: code, window: TOTP_WINDOW });
  return delta !== null;
}

/**
 * Disable TOTP for a user. Requires a valid code to confirm intent.
 */
export async function disableTOTP<TUser extends BaseUser>(
  user: TUser,
  code: string,
  config: ResolvedAuthConfig<TUser>,
): Promise<void> {
  if (!config.adapters.mfa) throw Errors.adapterNotConfigured('mfa');

  const valid = await validateTOTP(user, code, config);
  if (!valid) throw Errors.mfaInvalid();

  await config.adapters.mfa.deleteTOTP(user.id);
  await config.adapters.user.update(user.id, { mfaEnabled: false } as Partial<TUser>);

  await emitAudit('user.mfa_disabled', {
    userId: user.id,
    sessionId: null,
    ip: null,
    userAgent: null,
    metadata: { method: 'totp' },
  });
}

// ─── Backup Codes ─────────────────────────────────────────────────────────────

export interface BackupCodesResult {
  /** Plaintext codes — show once, never store. */
  codes: string[];
}

/**
 * Generate 10 single-use backup codes.
 * Hashed with bcrypt before storage (faster than Argon2 for bulk).
 */
export async function generateBackupCodes<TUser extends BaseUser>(
  user: TUser,
  config: ResolvedAuthConfig<TUser>,
): Promise<BackupCodesResult> {
  if (!config.adapters.mfa) throw Errors.adapterNotConfigured('mfa');

  const codes: string[] = [];
  const hashed: BackupCode[] = [];

  for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
    // 5 bytes → 10 hex chars — readable but hard to guess
    const code = generateOpaqueToken(5).toUpperCase();
    codes.push(code);
    const codeHash = await bcrypt.hash(code, BACKUP_CODE_BCRYPT_ROUNDS);
    hashed.push({
      userId: user.id,
      codeHash,
      used: false,
      createdAt: new Date(),
    });
  }

  // Delete existing codes before saving new ones
  await config.adapters.mfa.deleteBackupCodes(user.id);
  await config.adapters.mfa.saveBackupCodes(hashed);

  return { codes };
}

/**
 * Verify and consume a backup code.
 * Uses bcrypt.compare for constant-time comparison.
 */
export async function verifyBackupCode<TUser extends BaseUser>(
  user: TUser,
  code: string,
  config: ResolvedAuthConfig<TUser>,
): Promise<boolean> {
  if (!config.adapters.mfa) throw Errors.adapterNotConfigured('mfa');

  const storedCodes = await config.adapters.mfa.findBackupCodes(user.id);

  for (const stored of storedCodes) {
    if (stored.used) continue;
    // bcrypt.compare is constant-time
    const match = await bcrypt.compare(code, stored.codeHash);
    if (match) {
      await config.adapters.mfa.consumeBackupCode(user.id, stored.codeHash);
      return true;
    }
  }

  return false;
}
