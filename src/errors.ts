import type { AuthErrorCode } from './types/index.js';

/**
 * Base error class for all node-auth-core errors.
 * Never leaks internal details (stack traces, SQL errors) to callers.
 * Log the `cause` server-side; return only `code` + `message` to clients.
 */
export class AuthError extends Error {
  readonly code: AuthErrorCode;
  readonly statusCode: number;
  readonly details?: Record<string, unknown>;

  constructor(
    code: AuthErrorCode,
    message: string,
    statusCode: number,
    details?: Record<string, unknown>,
    cause?: unknown,
  ) {
    super(message, { cause });
    this.name = 'AuthError';
    this.code = code;
    this.statusCode = statusCode;
    if (details !== undefined) {
      this.details = details;
    }
    // Maintain proper prototype chain in transpiled environments
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /** Safe representation to send to clients — no stack, no cause. */
  toJSON(): { code: AuthErrorCode; message: string; statusCode: number; details?: Record<string, unknown> } {
    return {
      code: this.code,
      message: this.message,
      statusCode: this.statusCode,
      ...(this.details !== undefined ? { details: this.details } : {}),
    };
  }
}

// ─── Error factories ──────────────────────────────────────────────────────────

export const Errors = {
  invalidCredentials: () =>
    new AuthError('INVALID_CREDENTIALS', 'Invalid email or password.', 401),

  accountLocked: (unlocksAt?: Date) =>
    new AuthError('ACCOUNT_LOCKED', 'Account is temporarily locked.', 423, {
      ...(unlocksAt ? { unlocksAt: unlocksAt.toISOString() } : {}),
    }),

  accountNotVerified: () =>
    new AuthError('ACCOUNT_NOT_VERIFIED', 'Email address has not been verified.', 403),

  tokenExpired: () =>
    new AuthError('TOKEN_EXPIRED', 'Token has expired.', 401),

  tokenInvalid: () =>
    new AuthError('TOKEN_INVALID', 'Token is invalid.', 401),

  tokenReuseDetected: () =>
    new AuthError(
      'TOKEN_REUSE_DETECTED',
      'Refresh token reuse detected. All sessions have been revoked.',
      401,
    ),

  mfaRequired: () =>
    new AuthError('MFA_REQUIRED', 'Multi-factor authentication is required.', 403),

  mfaInvalid: () =>
    new AuthError('MFA_INVALID', 'MFA code is invalid.', 401),

  otpExpired: () =>
    new AuthError('OTP_EXPIRED', 'OTP has expired.', 401),

  otpMaxAttempts: () =>
    new AuthError('OTP_MAX_ATTEMPTS', 'Maximum OTP attempts exceeded.', 429),

  rateLimited: (retryAfterMs?: number) =>
    new AuthError('RATE_LIMITED', 'Too many requests. Please try again later.', 429, {
      ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
    }),

  sessionNotFound: () =>
    new AuthError('SESSION_NOT_FOUND', 'Session not found.', 401),

  sessionExpired: () =>
    new AuthError('SESSION_EXPIRED', 'Session has expired.', 401),

  oauthStateMismatch: () =>
    new AuthError('OAUTH_STATE_MISMATCH', 'OAuth state parameter mismatch.', 400),

  oauthCodeInvalid: () =>
    new AuthError('OAUTH_CODE_INVALID', 'OAuth authorization code is invalid or expired.', 400),

  webAuthnChallengeFailed: () =>
    new AuthError('WEBAUTHN_CHALLENGE_FAILED', 'WebAuthn challenge verification failed.', 400),

  webAuthnCredentialNotFound: () =>
    new AuthError('WEBAUTHN_CREDENTIAL_NOT_FOUND', 'WebAuthn credential not found.', 404),

  adapterNotConfigured: (adapter: string) =>
    new AuthError(
      'ADAPTER_NOT_CONFIGURED',
      `The '${adapter}' adapter is required for this operation but was not configured.`,
      500,
    ),

  missingSecret: () =>
    new AuthError(
      'MISSING_SECRET',
      "A 'secret' is required for HS256 JWT signing. Set it in AuthConfig.",
      500,
    ),

  invalidConfig: (message: string) =>
    new AuthError('INVALID_CONFIG', message, 500),

  passwordTooWeak: (score: number) =>
    new AuthError('PASSWORD_TOO_WEAK', 'Password is too weak.', 400, { score }),

  emailAlreadyExists: () =>
    new AuthError('EMAIL_ALREADY_EXISTS', 'An account with this email already exists.', 409),

  userNotFound: () =>
    new AuthError('USER_NOT_FOUND', 'User not found.', 404),
} as const;
