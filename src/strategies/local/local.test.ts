import { describe, it, expect, beforeEach } from 'vitest';
import { register, login, verifyEmail, forgotPassword, resetPassword } from './index.js';
import { InMemoryUserStore, InMemorySessionStore, InMemoryTokenStore } from '../../adapters/memory/index.js';
import { resolveConfig } from '../../config.js';
import type { BaseUser } from '../../types/index.js';

interface TestUser extends BaseUser {
  passwordHash: string;
}

function makeConfig() {
  const userStore = new InMemoryUserStore<TestUser>();
  const sessionStore = new InMemorySessionStore();
  const tokenStore = new InMemoryTokenStore();

  const config = resolveConfig<TestUser>({
    secret: 'test-secret-that-is-at-least-32-characters-long',
    isDevelopment: true,
    adapters: { user: userStore, session: sessionStore, token: tokenStore },
    password: { minStrengthScore: 0 }, // relax for tests
  });

  return { config, userStore, sessionStore, tokenStore };
}

describe('register', () => {
  it('creates a user and returns an email verification token', async () => {
    const { config, userStore } = makeConfig();
    const result = await register({ email: 'Alice@Example.com', password: 'correct-horse-battery' }, config);

    expect(result.user.email).toBe('alice@example.com'); // normalized
    expect(result.user.emailVerified).toBe(false);
    expect(result.emailVerificationToken).toBeTruthy();
    expect(result.emailVerificationToken).toHaveLength(64); // 32 bytes hex

    const stored = await userStore.findByEmail('alice@example.com');
    expect(stored).not.toBeNull();
    expect((stored as TestUser).passwordHash).not.toBe('correct-horse-battery'); // hashed
  });

  it('rejects duplicate email', async () => {
    const { config } = makeConfig();
    await register({ email: 'test@example.com', password: 'correct-horse-battery' }, config);
    await expect(
      register({ email: 'test@example.com', password: 'another-password-123' }, config),
    ).rejects.toMatchObject({ code: 'EMAIL_ALREADY_EXISTS' });
  });

  it('normalizes email case', async () => {
    const { config, userStore } = makeConfig();
    await register({ email: 'TEST@EXAMPLE.COM', password: 'correct-horse-battery' }, config);
    const user = await userStore.findByEmail('test@example.com');
    expect(user).not.toBeNull();
  });
});

describe('login', () => {
  it('returns tokens on valid credentials', async () => {
    const { config } = makeConfig();
    await register({ email: 'user@example.com', password: 'correct-horse-battery' }, config);
    const result = await login({ email: 'user@example.com', password: 'correct-horse-battery' }, config);

    expect(result.tokens.accessToken).toBeTruthy();
    expect(result.tokens.refreshToken).toBeTruthy();
    expect(result.user.email).toBe('user@example.com');
  });

  it('rejects wrong password', async () => {
    const { config } = makeConfig();
    await register({ email: 'user@example.com', password: 'correct-horse-battery' }, config);
    await expect(
      login({ email: 'user@example.com', password: 'wrong-password' }, config),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
  });

  it('rejects unknown email', async () => {
    const { config } = makeConfig();
    await expect(
      login({ email: 'nobody@example.com', password: 'any-password' }, config),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
  });

  it('locks account after 5 failed attempts', async () => {
    const { config } = makeConfig();
    await register({ email: 'user@example.com', password: 'correct-horse-battery' }, config);

    for (let i = 0; i < 5; i++) {
      await expect(
        login({ email: 'user@example.com', password: 'wrong' }, config),
      ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    }

    // 6th attempt should get ACCOUNT_LOCKED
    await expect(
      login({ email: 'user@example.com', password: 'correct-horse-battery' }, config),
    ).rejects.toMatchObject({ code: 'ACCOUNT_LOCKED' });
  });

  it('resets failed attempts on successful login', async () => {
    const { config, userStore } = makeConfig();
    await register({ email: 'user@example.com', password: 'correct-horse-battery' }, config);

    // 2 failed attempts
    for (let i = 0; i < 2; i++) {
      await expect(login({ email: 'user@example.com', password: 'wrong' }, config)).rejects.toThrow();
    }

    // Successful login
    await login({ email: 'user@example.com', password: 'correct-horse-battery' }, config);

    const user = await userStore.findByEmail('user@example.com');
    expect(user?.failedLoginAttempts).toBe(0);
  });
});

describe('verifyEmail', () => {
  it('marks email as verified', async () => {
    const { config, userStore } = makeConfig();
    const { emailVerificationToken } = await register(
      { email: 'user@example.com', password: 'correct-horse-battery' },
      config,
    );

    await verifyEmail({ token: emailVerificationToken }, config);
    const user = await userStore.findByEmail('user@example.com');
    expect(user?.emailVerified).toBe(true);
  });

  it('rejects invalid token', async () => {
    const { config } = makeConfig();
    await expect(verifyEmail({ token: 'invalid-token' }, config)).rejects.toMatchObject({
      code: 'TOKEN_INVALID',
    });
  });

  it('rejects token reuse', async () => {
    const { config } = makeConfig();
    const { emailVerificationToken } = await register(
      { email: 'user@example.com', password: 'correct-horse-battery' },
      config,
    );

    await verifyEmail({ token: emailVerificationToken }, config);
    await expect(verifyEmail({ token: emailVerificationToken }, config)).rejects.toMatchObject({
      code: 'TOKEN_INVALID',
    });
  });
});

describe('forgotPassword + resetPassword', () => {
  it('issues a reset token and allows password change', async () => {
    const { config } = makeConfig();
    await register({ email: 'user@example.com', password: 'correct-horse-battery' }, config);

    const result = await forgotPassword({ email: 'user@example.com' }, config);
    expect(result).not.toBeNull();
    expect(result!.resetToken).toBeTruthy();

    await resetPassword({ token: result!.resetToken, newPassword: 'new-correct-horse-battery' }, config);

    // Old password should no longer work
    await expect(
      login({ email: 'user@example.com', password: 'correct-horse-battery' }, config),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });

    // New password should work
    const loginResult = await login(
      { email: 'user@example.com', password: 'new-correct-horse-battery' },
      config,
    );
    expect(loginResult.tokens.accessToken).toBeTruthy();
  });

  it('returns null for unknown email (no enumeration)', async () => {
    const { config } = makeConfig();
    const result = await forgotPassword({ email: 'nobody@example.com' }, config);
    expect(result).toBeNull();
  });

  it('rejects reset token reuse', async () => {
    const { config } = makeConfig();
    await register({ email: 'user@example.com', password: 'correct-horse-battery' }, config);
    const result = await forgotPassword({ email: 'user@example.com' }, config);

    await resetPassword({ token: result!.resetToken, newPassword: 'new-password-123456' }, config);
    await expect(
      resetPassword({ token: result!.resetToken, newPassword: 'another-password-123' }, config),
    ).rejects.toMatchObject({ code: 'TOKEN_INVALID' });
  });

  it('revokes all sessions on password reset', async () => {
    const { config, sessionStore } = makeConfig();
    await register({ email: 'user@example.com', password: 'correct-horse-battery' }, config);
    const { user } = await login({ email: 'user@example.com', password: 'correct-horse-battery' }, config);

    const sessionsBefore = await sessionStore.findByUserId(user.id);
    expect(sessionsBefore).toHaveLength(1);

    const result = await forgotPassword({ email: 'user@example.com' }, config);
    await resetPassword({ token: result!.resetToken, newPassword: 'new-password-123456' }, config);

    const sessionsAfter = await sessionStore.findByUserId(user.id);
    expect(sessionsAfter).toHaveLength(0);
  });
});
