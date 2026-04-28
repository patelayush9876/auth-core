import { randomBytes, timingSafeEqual, createHash } from 'node:crypto';

/**
 * Generate a cryptographically secure random opaque token.
 * Uses crypto.randomBytes — never Math.random.
 *
 * @param byteLength - Number of random bytes (default 32 → 64 hex chars)
 * @returns Hex-encoded token string
 */
export function generateOpaqueToken(byteLength = 32): string {
  return randomBytes(byteLength).toString('hex');
}

/**
 * Hash a token with SHA-256 for storage.
 * Store the hash; compare hashes with timingSafeEqual.
 *
 * @param token - Raw token string
 * @returns Hex-encoded SHA-256 hash
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Compare two strings in constant time to prevent timing attacks.
 * Pads to equal length before comparison so length differences don't leak.
 *
 * @param a - First value
 * @param b - Second value
 * @returns true if equal
 */
export function safeCompare(a: string, b: string): boolean {
  // Always allocate buffers of the same length to prevent length-based timing leaks.
  // We use the longer length and pad the shorter one.
  const maxLen = Math.max(Buffer.byteLength(a, 'utf8'), Buffer.byteLength(b, 'utf8'));
  const bufA = Buffer.alloc(maxLen);
  const bufB = Buffer.alloc(maxLen);
  bufA.write(a, 'utf8');
  bufB.write(b, 'utf8');
  return timingSafeEqual(bufA, bufB);
}

/**
 * Compare two Buffers or Uint8Arrays in constant time.
 * Both must be the same length — throws if not (use safeCompare for strings).
 */
export function safeCompareBuffers(a: Buffer | Uint8Array, b: Buffer | Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

import { randomInt } from 'node:crypto';

/**
 * Generate a cryptographically secure random integer in [0, max).
 * Uses crypto.randomInt — never Math.random.
 *
 * @param max - Exclusive upper bound
 */
export function secureRandomInt(max: number): number {
  return randomInt(max);
}

/**
 * Generate a 6-digit OTP using crypto.randomInt.
 * Range: 000000–999999, zero-padded to 6 digits.
 */
export function generateOTP(): string {
  return randomInt(0, 1_000_000).toString().padStart(6, '0');
}
