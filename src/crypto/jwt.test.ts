import { describe, it, expect, beforeEach } from 'vitest';
import { signAccessToken, verifyAccessToken, decodeTokenUnsafe, clearKeyCache } from './jwt.js';
import type { AccessTokenConfig } from '../types/index.js';

const HS256_CONFIG: AccessTokenConfig = {
  algorithm: 'HS256',
  expiresIn: '15m',
  privateKey: 'super-secret-key-that-is-at-least-32-chars-long',
};

beforeEach(() => {
  clearKeyCache();
});

describe('signAccessToken + verifyAccessToken (HS256)', () => {
  it('signs and verifies a token', async () => {
    const token = await signAccessToken({ sub: 'user-1', roles: ['user'] }, HS256_CONFIG);
    expect(typeof token).toBe('string');
    expect(token.split('.')).toHaveLength(3);

    const payload = await verifyAccessToken(token, HS256_CONFIG);
    expect(payload.sub).toBe('user-1');
    expect(payload['roles']).toEqual(['user']);
  });

  it('includes iat and exp claims', async () => {
    const before = Math.floor(Date.now() / 1000);
    const token = await signAccessToken({ sub: 'user-1' }, HS256_CONFIG);
    const payload = await verifyAccessToken(token, HS256_CONFIG);
    expect(payload.iat).toBeGreaterThanOrEqual(before);
    expect(payload.exp).toBeGreaterThan(payload.iat);
  });

  it('rejects a token signed with a different secret', async () => {
    const token = await signAccessToken({ sub: 'user-1' }, HS256_CONFIG);
    const wrongConfig: AccessTokenConfig = {
      ...HS256_CONFIG,
      privateKey: 'different-secret-key-that-is-at-least-32-chars',
    };
    clearKeyCache();
    await expect(verifyAccessToken(token, wrongConfig)).rejects.toMatchObject({
      code: 'TOKEN_INVALID',
    });
  });

  it('rejects an expired token', async () => {
    // Sign with a 1-second expiry and wait for it to expire
    const expiredConfig: AccessTokenConfig = { ...HS256_CONFIG, expiresIn: '1s' };
    clearKeyCache();
    const token = await signAccessToken({ sub: 'user-1' }, expiredConfig);
    // Wait 1.1s for the token to expire
    await new Promise((r) => setTimeout(r, 1100));
    await expect(verifyAccessToken(token, expiredConfig)).rejects.toMatchObject({
      code: 'TOKEN_EXPIRED',
    });
  });

  it('rejects a malformed token', async () => {
    await expect(verifyAccessToken('not.a.jwt', HS256_CONFIG)).rejects.toMatchObject({
      code: 'TOKEN_INVALID',
    });
  });

  it('rejects alg:none attack', async () => {
    // Craft a token with alg:none
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: 'attacker', exp: 9999999999 })).toString('base64url');
    const noneToken = `${header}.${payload}.`;

    await expect(verifyAccessToken(noneToken, HS256_CONFIG)).rejects.toMatchObject({
      code: 'TOKEN_INVALID',
    });
  });

  it('includes issuer and audience when configured', async () => {
    const config: AccessTokenConfig = {
      ...HS256_CONFIG,
      issuer: 'my-app',
      audience: 'my-client',
    };
    clearKeyCache();
    const token = await signAccessToken({ sub: 'user-1' }, config);
    const payload = await verifyAccessToken(token, config);
    expect(payload.iss).toBe('my-app');
    expect(payload.aud).toBe('my-client');
  });
});

describe('decodeTokenUnsafe', () => {
  it('decodes a valid JWT without verifying', async () => {
    const token = await signAccessToken({ sub: 'user-1', custom: 'value' }, HS256_CONFIG);
    const decoded = decodeTokenUnsafe(token);
    expect(decoded?.['sub']).toBe('user-1');
    expect(decoded?.['custom']).toBe('value');
  });

  it('returns null for invalid input', () => {
    expect(decodeTokenUnsafe('not-a-jwt')).toBeNull();
    expect(decodeTokenUnsafe('')).toBeNull();
    expect(decodeTokenUnsafe('a.b')).toBeNull();
  });
});
