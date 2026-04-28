import type { PasswordConfig } from '../types/index.js';

/**
 * Password hashing and verification.
 * Default: Argon2id (memory-hard, resistant to GPU/ASIC attacks).
 * Fallback: bcrypt (widely supported, still acceptable).
 *
 * SECURITY NOTE: Never store plaintext passwords. Never use MD5/SHA for passwords.
 * These functions use audited libraries (argon2, bcrypt) — no custom crypto.
 */

/** Default Argon2id parameters — OWASP recommended minimums. */
const ARGON2_DEFAULTS = {
  memoryCost: 65536, // 64 MiB
  timeCost: 3,
  parallelism: 4,
} as const;

const BCRYPT_DEFAULTS = {
  rounds: 12,
} as const;

/**
 * Hash a password using the configured algorithm.
 *
 * @param password - Plaintext password
 * @param config - Password configuration
 * @returns Hash string (includes algorithm + params — self-describing)
 */
export async function hashPassword(
  password: string,
  config: PasswordConfig,
): Promise<string> {
  if (config.algorithm === 'argon2id') {
    const argon2 = await import('argon2');
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: config.argon2.memoryCost,
      timeCost: config.argon2.timeCost,
      parallelism: config.argon2.parallelism,
    });
  }

  const bcrypt = await import('bcrypt');
  return bcrypt.hash(password, config.bcrypt.rounds);
}

/**
 * Verify a password against a stored hash.
 * Uses the library's built-in constant-time comparison.
 *
 * @param password - Plaintext password to verify
 * @param hash - Stored hash
 * @param config - Password configuration
 * @returns true if the password matches
 */
export async function verifyPassword(
  password: string,
  hash: string,
  config: PasswordConfig,
): Promise<boolean> {
  try {
    if (config.algorithm === 'argon2id') {
      const argon2 = await import('argon2');
      return await argon2.verify(hash, password);
    }

    const bcrypt = await import('bcrypt');
    return await bcrypt.compare(password, hash);
  } catch {
    // Any error (malformed hash, etc.) → treat as mismatch, never throw to caller
    return false;
  }
}

/**
 * Check if a hash needs to be rehashed (e.g. cost factors changed).
 * Only supported for Argon2 — bcrypt does not expose this natively.
 */
export async function needsRehash(
  hash: string,
  config: PasswordConfig,
): Promise<boolean> {
  if (config.algorithm !== 'argon2id') return false;
  const argon2 = await import('argon2');
  return argon2.needsRehash(hash, {
    memoryCost: config.argon2.memoryCost,
    timeCost: config.argon2.timeCost,
    parallelism: config.argon2.parallelism,
  });
}

/**
 * Build a PasswordConfig with defaults applied.
 */
export function resolvePasswordConfig(partial?: Partial<PasswordConfig>): PasswordConfig {
  return {
    algorithm: partial?.algorithm ?? 'argon2id',
    argon2: {
      memoryCost: partial?.argon2?.memoryCost ?? ARGON2_DEFAULTS.memoryCost,
      timeCost: partial?.argon2?.timeCost ?? ARGON2_DEFAULTS.timeCost,
      parallelism: partial?.argon2?.parallelism ?? ARGON2_DEFAULTS.parallelism,
    },
    bcrypt: {
      rounds: partial?.bcrypt?.rounds ?? BCRYPT_DEFAULTS.rounds,
    },
    minStrengthScore: partial?.minStrengthScore ?? 3,
  };
}
