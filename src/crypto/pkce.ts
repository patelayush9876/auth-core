import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';

/**
 * PKCE (Proof Key for Code Exchange) utilities.
 * Only S256 method is supported — plain is insecure and rejected.
 * RFC 7636: https://datatracker.ietf.org/doc/html/rfc7636
 */

/** Minimum and maximum verifier lengths per RFC 7636 §4.1 */
const VERIFIER_MIN_LENGTH = 43;
const VERIFIER_MAX_LENGTH = 128;

/**
 * Generate a cryptographically random PKCE code verifier.
 * Uses the unreserved character set: [A-Z a-z 0-9 - . _ ~]
 *
 * @returns Base64url-encoded verifier string (43–128 chars)
 */
export function generateCodeVerifier(): string {
  // 32 bytes → 43 base64url chars (meets minimum)
  return randomBytes(32).toString('base64url');
}

/**
 * Derive the S256 code challenge from a verifier.
 * challenge = BASE64URL(SHA256(ASCII(verifier)))
 *
 * @param verifier - The code verifier string
 * @returns Base64url-encoded SHA-256 challenge
 */
export function generateCodeChallenge(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

/**
 * Validate a PKCE code verifier against a stored challenge.
 * Recomputes the challenge and compares — no timing attack surface since
 * the challenge is not secret (it was sent to the auth server).
 *
 * @param verifier - The verifier submitted by the client
 * @param storedChallenge - The challenge stored at authorization time
 * @returns true if the verifier matches the challenge
 */
export function validateCodeVerifier(verifier: string, storedChallenge: string): boolean {
  if (
    verifier.length < VERIFIER_MIN_LENGTH ||
    verifier.length > VERIFIER_MAX_LENGTH
  ) {
    return false;
  }
  const derived = generateCodeChallenge(verifier);
  // Challenges are not secret but we use constant-time compare for defense in depth
  const a = Buffer.from(derived, 'utf8');
  const b = Buffer.from(storedChallenge, 'utf8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
