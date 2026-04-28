import { describe, it, expect } from 'vitest';
import { AuthError, Errors } from './errors.js';

describe('AuthError', () => {
  it('is an instance of Error', () => {
    const err = new AuthError('TOKEN_INVALID', 'bad token', 401);
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(AuthError);
  });

  it('has correct properties', () => {
    const err = new AuthError('RATE_LIMITED', 'too many', 429, { retryAfterMs: 5000 });
    expect(err.code).toBe('RATE_LIMITED');
    expect(err.message).toBe('too many');
    expect(err.statusCode).toBe(429);
    expect(err.details).toEqual({ retryAfterMs: 5000 });
  });

  it('toJSON does not include stack trace', () => {
    const err = new AuthError('TOKEN_EXPIRED', 'expired', 401);
    const json = err.toJSON();
    expect(json).not.toHaveProperty('stack');
    expect(json).not.toHaveProperty('cause');
    expect(json).toEqual({ code: 'TOKEN_EXPIRED', message: 'expired', statusCode: 401 });
  });

  it('preserves cause for server-side logging', () => {
    const cause = new Error('SQL error: ...');
    const err = new AuthError('INVALID_CREDENTIALS', 'bad creds', 401, undefined, cause);
    expect(err.cause).toBe(cause);
    // But toJSON does not expose it
    expect(err.toJSON()).not.toHaveProperty('cause');
  });
});

describe('Errors factories', () => {
  it('invalidCredentials returns 401', () => {
    const err = Errors.invalidCredentials();
    expect(err.statusCode).toBe(401);
    expect(err.code).toBe('INVALID_CREDENTIALS');
  });

  it('accountLocked includes unlocksAt', () => {
    const date = new Date(Date.now() + 60_000);
    const err = Errors.accountLocked(date);
    expect(err.statusCode).toBe(423);
    expect(err.details?.['unlocksAt']).toBe(date.toISOString());
  });

  it('rateLimited includes retryAfterMs', () => {
    const err = Errors.rateLimited(5000);
    expect(err.statusCode).toBe(429);
    expect(err.details?.['retryAfterMs']).toBe(5000);
  });

  it('adapterNotConfigured names the adapter', () => {
    const err = Errors.adapterNotConfigured('mfa');
    expect(err.message).toContain('mfa');
    expect(err.statusCode).toBe(500);
  });
});
