import { SignJWT, jwtVerify, importPKCS8, importSPKI, type KeyLike } from 'jose';
import type { AccessTokenConfig, JWTPayload } from '../types/index.js';
import { AuthError, Errors } from '../errors.js';

/**
 * JWT signing and verification.
 *
 * SECURITY INVARIANTS:
 * - Always validate the `alg` header on verify — prevents alg:none attacks.
 * - Short default expiry (15 min).
 * - RS256/ES256 require explicit key material — no implicit fallback to HS256.
 */

type SigningKey = KeyLike | Uint8Array;

/** Cache parsed keys to avoid re-importing on every request. */
const keyCache = new Map<string, SigningKey>();

async function getSigningKey(config: AccessTokenConfig): Promise<SigningKey> {
  const cacheKey = `sign:${config.algorithm}`;
  const cached = keyCache.get(cacheKey);
  if (cached !== undefined) return cached;

  let key: SigningKey;

  if (config.algorithm === 'HS256') {
    if (!config.privateKey && !('secret' in config)) {
      throw Errors.missingSecret();
    }
    // For HS256 the secret is passed in as privateKey field (set by resolveConfig)
    key = new TextEncoder().encode(config.privateKey ?? '');
  } else {
    if (!config.privateKey) {
      throw Errors.invalidConfig(`privateKey is required for ${config.algorithm}`);
    }
    key = await importPKCS8(config.privateKey, config.algorithm);
  }

  keyCache.set(cacheKey, key);
  return key;
}

async function getVerifyKey(config: AccessTokenConfig): Promise<SigningKey> {
  const cacheKey = `verify:${config.algorithm}`;
  const cached = keyCache.get(cacheKey);
  if (cached !== undefined) return cached;

  let key: SigningKey;

  if (config.algorithm === 'HS256') {
    key = new TextEncoder().encode(config.privateKey ?? '');
  } else {
    if (!config.publicKey) {
      throw Errors.invalidConfig(`publicKey is required for ${config.algorithm} verification`);
    }
    key = await importSPKI(config.publicKey, config.algorithm);
  }

  keyCache.set(cacheKey, key);
  return key;
}

/**
 * Sign a JWT access token.
 *
 * @param payload - Claims to embed (sub is required)
 * @param config - Access token configuration
 * @returns Signed JWT string
 */
export async function signAccessToken(
  payload: Omit<JWTPayload, 'iat' | 'exp'> & { sub: string },
  config: AccessTokenConfig,
): Promise<string> {
  const key = await getSigningKey(config);

  const builder = new SignJWT({ ...payload })
    .setProtectedHeader({ alg: config.algorithm })
    .setIssuedAt()
    .setExpirationTime(config.expiresIn)
    .setSubject(payload.sub);

  if (config.issuer) builder.setIssuer(config.issuer);
  if (config.audience) builder.setAudience(config.audience);

  return builder.sign(key);
}

/**
 * Verify and decode a JWT access token.
 *
 * SECURITY: `algorithms` option is explicitly set — jose rejects alg:none
 * and any algorithm not in the allowed list.
 *
 * @param token - JWT string
 * @param config - Access token configuration
 * @returns Decoded payload
 * @throws AuthError on invalid/expired token
 */
export async function verifyAccessToken(
  token: string,
  config: AccessTokenConfig,
): Promise<JWTPayload> {
  const key = await getVerifyKey(config);

  try {
    const { payload } = await jwtVerify(token, key, {
      algorithms: [config.algorithm], // ← alg:none prevention
      ...(config.issuer ? { issuer: config.issuer } : {}),
      ...(config.audience ? { audience: config.audience } : {}),
    });

    return payload as unknown as JWTPayload;
  } catch (err) {
    if (err instanceof Error) {
      if (err.name === 'JWTExpired' || (err as { code?: string }).code === 'ERR_JWT_EXPIRED') {
        throw Errors.tokenExpired();
      }
    }
    throw Errors.tokenInvalid();
  }
}

/**
 * Decode a JWT without verifying the signature.
 * Use only for non-security-sensitive inspection (e.g. logging, debugging).
 * NEVER use this for authentication decisions.
 */
export function decodeTokenUnsafe(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = parts[1];
    if (!payload) return null;
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Clear the key cache — useful in tests when rotating keys. */
export function clearKeyCache(): void {
  keyCache.clear();
}
