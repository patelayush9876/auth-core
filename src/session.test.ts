import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createSession, rotateRefreshToken, revokeSession, revokeAllSessions } from './session.js';
import { InMemoryUserStore, InMemorySessionStore, InMemoryTokenStore } from './adapters/memory/index.js';
import { resolveConfig } from './config.js';
import { clearKeyCache } from './crypto/jwt.js';
import type { BaseUser } from './types/index.js';

interface TestUser extends BaseUser {
  passwordHash: string;
}

function makeUser(overrides: Partial<TestUser> = {}): TestUser {
  return {
    id: 'user-1',
    email: 'test@example.com',
    emailVerified: true,
    roles: ['user'],
    mfaEnabled: false,
    mfaEnforcement: 'optional',
    lockedUntil: null,
    failedLoginAttempts: 0,
    createdAt: new Date(),
    updatedAt: new Date(),
    passwordHash: 'hash',
    ...overrides,
  };
}

function makeConfig() {
  const userStore = new InMemoryUserStore<TestUser>();
  const sessionStore = new InMemorySessionStore();
  const tokenStore = new InMemoryTokenStore();

  const config = resolveConfig<TestUser>({
    secret: 'test-secret-that-is-at-least-32-characters-long',
    isDevelopment: true,
    adapters: { user: userStore, session: sessionStore, token: tokenStore },
  });

  return { config, userStore, sessionStore, tokenStore };
}

beforeEach(() => {
  clearKeyCache();
});

describe('createSession', () => {
  it('creates a session and returns a token pair', async () => {
    const { config, userStore, sessionStore } = makeConfig();
    const user = await userStore.create(makeUser());

    const { session, tokens } = await createSession(user, config);

    expect(session.userId).toBe(user.id);
    expect(session.refreshTokenHash).toBeTruthy();
    expect(tokens.accessToken).toBeTruthy();
    expect(tokens.refreshToken).toBeTruthy();
    expect(tokens.accessTokenExpiresAt).toBeInstanceOf(Date);
    expect(tokens.refreshTokenExpiresAt).toBeInstanceOf(Date);

    // Refresh token should be stored hashed, not plaintext
    expect(session.refreshTokenHash).not.toBe(tokens.refreshToken);

    const stored = await sessionStore.findById(session.id);
    expect(stored).not.toBeNull();
  });

  it('access token expires before refresh token', async () => {
    const { config, userStore } = makeConfig();
    const user = await userStore.create(makeUser());
    const { tokens } = await createSession(user, config);

    expect(tokens.accessTokenExpiresAt.getTime()).toBeLessThan(
      tokens.refreshTokenExpiresAt.getTime(),
    );
  });
});

describe('rotateRefreshToken', () => {
  it('issues new tokens and invalidates old refresh token', async () => {
    const { config, userStore } = makeConfig();
    const user = await userStore.create(makeUser());
    const { tokens: original } = await createSession(user, config);

    const { tokens: rotated } = await rotateRefreshToken(original.refreshToken, config);

    expect(rotated.accessToken).toBeTruthy();
    expect(rotated.refreshToken).toBeTruthy();
    expect(rotated.refreshToken).not.toBe(original.refreshToken);
  });

  it('rejects an invalid refresh token', async () => {
    const { config } = makeConfig();
    await expect(rotateRefreshToken('invalid-token', config)).rejects.toMatchObject({
      code: 'TOKEN_INVALID',
    });
  });

  it('detects refresh token reuse and revokes all sessions', async () => {
    const { config, userStore, sessionStore } = makeConfig();
    const user = await userStore.create(makeUser());
    const { tokens: original } = await createSession(user, config);

    // First rotation — valid
    await rotateRefreshToken(original.refreshToken, config);

    // Reuse the original token — should trigger reuse detection
    await expect(rotateRefreshToken(original.refreshToken, config)).rejects.toMatchObject({
      code: 'TOKEN_REUSE_DETECTED',
    });

    // All sessions should be revoked
    const sessions = await sessionStore.findByUserId(user.id);
    expect(sessions).toHaveLength(0);
  });
});

describe('revokeSession', () => {
  it('deletes the session', async () => {
    const { config, userStore, sessionStore } = makeConfig();
    const user = await userStore.create(makeUser());
    const { session } = await createSession(user, config);

    await revokeSession(session.id, config);

    const stored = await sessionStore.findById(session.id);
    expect(stored).toBeNull();
  });

  it('throws SESSION_NOT_FOUND for unknown session', async () => {
    const { config } = makeConfig();
    await expect(revokeSession('nonexistent', config)).rejects.toMatchObject({
      code: 'SESSION_NOT_FOUND',
    });
  });
});

describe('revokeAllSessions', () => {
  it('deletes all sessions for a user', async () => {
    const { config, userStore, sessionStore } = makeConfig();
    const user = await userStore.create(makeUser());

    await createSession(user, config);
    await createSession(user, config);
    await createSession(user, config);

    const before = await sessionStore.findByUserId(user.id);
    expect(before).toHaveLength(3);

    await revokeAllSessions(user.id, config);

    const after = await sessionStore.findByUserId(user.id);
    expect(after).toHaveLength(0);
  });
});

describe('token expiry', () => {
  it('rejects expired sessions during rotation', async () => {
    const { config, userStore } = makeConfig();
    const user = await userStore.create(makeUser());

    // Create config with very short refresh token TTL
    const shortConfig = resolveConfig<TestUser>({
      secret: 'test-secret-that-is-at-least-32-characters-long',
      isDevelopment: true,
      refreshToken: { expiresIn: '1ms' },
      adapters: config.adapters,
    });

    const { tokens } = await createSession(user, shortConfig);

    // Wait for expiry
    await new Promise((r) => setTimeout(r, 10));

    await expect(rotateRefreshToken(tokens.refreshToken, shortConfig)).rejects.toMatchObject({
      code: 'SESSION_EXPIRED',
    });
  });
});
