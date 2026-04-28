/**
 * Core type definitions for node-auth-core.
 * All public-facing types are exported from this module.
 */

// ─── Base User ────────────────────────────────────────────────────────────────

/** Minimum shape every user record must satisfy. */
export interface BaseUser {
  id: string;
  email: string;
  emailVerified: boolean;
  roles: string[];
  mfaEnabled: boolean;
  mfaEnforcement: MFAEnforcement;
  lockedUntil?: Date | null;
  failedLoginAttempts: number;
  createdAt: Date;
  updatedAt: Date;
}

// ─── Session ──────────────────────────────────────────────────────────────────

/** A persisted session record. */
export interface Session {
  id: string;
  userId: string;
  /** Hashed refresh token — never store plaintext. */
  refreshTokenHash: string;
  /** Token family ID for reuse detection. */
  tokenFamily: string;
  deviceFingerprint?: string | null;
  userAgent?: string | null;
  ip?: string | null;
  mfaVerified: boolean;
  createdAt: Date;
  lastActiveAt: Date;
  expiresAt: Date;
}

// ─── Tokens ───────────────────────────────────────────────────────────────────

/** A stored opaque token (magic link, email verification, password reset, etc.). */
export interface StoredToken {
  /** The raw token value — store hashed in DB, compare with timingSafeEqual. */
  tokenHash: string;
  userId: string;
  type: TokenType;
  /** ISO string or Date — whichever the adapter prefers. */
  expiresAt: Date;
  consumed: boolean;
  createdAt: Date;
  /** Arbitrary metadata (e.g. redirect URL for magic links). */
  metadata?: Record<string, unknown>;
}

export type TokenType =
  | 'email_verification'
  | 'password_reset'
  | 'magic_link'
  | 'otp'
  | 'refresh';

/** Issued token pair returned to the caller. */
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: Date;
  refreshTokenExpiresAt: Date;
}

/** Decoded, validated JWT payload. */
export interface JWTPayload {
  sub: string;
  iat: number;
  exp: number;
  iss?: string;
  aud?: string | string[];
  sessionId?: string;
  roles?: string[];
  mfaVerified?: boolean;
  [key: string]: unknown;
}

// ─── WebAuthn ─────────────────────────────────────────────────────────────────

/** A stored WebAuthn credential. */
export interface WebAuthnCredential {
  id: string;
  userId: string;
  credentialId: string;
  publicKey: Uint8Array;
  counter: number;
  deviceType: string;
  backedUp: boolean;
  transports?: string[];
  createdAt: Date;
  lastUsedAt?: Date | null;
}

// ─── OAuth ────────────────────────────────────────────────────────────────────

/** Normalized profile returned by any OAuth provider. */
export interface OAuthProfile {
  provider: string;
  providerUserId: string;
  email?: string | null;
  emailVerified?: boolean;
  displayName?: string | null;
  avatarUrl?: string | null;
  raw: Record<string, unknown>;
}

/** Stored OAuth account link. */
export interface OAuthAccount {
  id: string;
  userId: string;
  provider: string;
  providerUserId: string;
  accessToken?: string | null;
  refreshToken?: string | null;
  expiresAt?: Date | null;
  createdAt: Date;
}

// ─── MFA ──────────────────────────────────────────────────────────────────────

export type MFAEnforcement = 'required' | 'optional' | 'disabled';

export interface TOTPSecret {
  userId: string;
  secret: string;
  /** Whether the user has completed TOTP setup (verified at least once). */
  verified: boolean;
  createdAt: Date;
}

export interface BackupCode {
  userId: string;
  /** bcrypt hash of the code. */
  codeHash: string;
  used: boolean;
  createdAt: Date;
}

// ─── Adapter Interfaces ───────────────────────────────────────────────────────

/**
 * Adapter for user persistence.
 * Implement this interface to connect any database.
 */
export interface UserStore<TUser extends BaseUser = BaseUser> {
  findById(id: string): Promise<TUser | null>;
  findByEmail(email: string): Promise<TUser | null>;
  create(data: Omit<TUser, 'id' | 'createdAt' | 'updatedAt'>): Promise<TUser>;
  update(id: string, data: Partial<Omit<TUser, 'id' | 'createdAt'>>): Promise<TUser>;
  delete(id: string): Promise<void>;
}

/**
 * Adapter for session persistence.
 */
export interface SessionStore {
  create(session: Omit<Session, 'id' | 'createdAt' | 'lastActiveAt'>): Promise<Session>;
  findById(id: string): Promise<Session | null>;
  findByUserId(userId: string): Promise<Session[]>;
  update(id: string, data: Partial<Omit<Session, 'id' | 'userId' | 'createdAt'>>): Promise<Session>;
  delete(id: string): Promise<void>;
  deleteAllForUser(userId: string): Promise<void>;
}

/**
 * Adapter for opaque token persistence (magic links, OTPs, email verification, etc.).
 */
export interface TokenStore {
  save(token: Omit<StoredToken, 'createdAt'>): Promise<StoredToken>;
  find(tokenHash: string, type: TokenType): Promise<StoredToken | null>;
  /**
   * Atomically mark a token as consumed.
   * Returns the token if it was valid and not yet consumed; null otherwise.
   */
  consume(tokenHash: string, type: TokenType): Promise<StoredToken | null>;
  deleteExpired(): Promise<void>;
}

/**
 * Adapter for WebAuthn credential persistence.
 */
export interface CredentialStore {
  save(credential: Omit<WebAuthnCredential, 'id' | 'createdAt'>): Promise<WebAuthnCredential>;
  findById(credentialId: string): Promise<WebAuthnCredential | null>;
  findByUserId(userId: string): Promise<WebAuthnCredential[]>;
  update(credentialId: string, data: Partial<Pick<WebAuthnCredential, 'counter' | 'lastUsedAt'>>): Promise<WebAuthnCredential>;
  delete(credentialId: string): Promise<void>;
}

/**
 * Adapter for OAuth account links.
 */
export interface OAuthStore {
  save(account: Omit<OAuthAccount, 'id' | 'createdAt'>): Promise<OAuthAccount>;
  findByProvider(provider: string, providerUserId: string): Promise<OAuthAccount | null>;
  findByUserId(userId: string): Promise<OAuthAccount[]>;
  delete(id: string): Promise<void>;
}

/**
 * Adapter for MFA secrets and backup codes.
 */
export interface MFAStore {
  saveTOTP(secret: TOTPSecret): Promise<void>;
  findTOTP(userId: string): Promise<TOTPSecret | null>;
  deleteTOTP(userId: string): Promise<void>;
  saveBackupCodes(codes: BackupCode[]): Promise<void>;
  findBackupCodes(userId: string): Promise<BackupCode[]>;
  consumeBackupCode(userId: string, codeHash: string): Promise<boolean>;
  deleteBackupCodes(userId: string): Promise<void>;
}

// ─── Rate Limiting ────────────────────────────────────────────────────────────

export interface RateLimitStore {
  increment(key: string, windowMs: number): Promise<{ count: number; resetAt: Date }>;
  reset(key: string): Promise<void>;
}

// ─── Audit Events ─────────────────────────────────────────────────────────────

export type AuditEventName =
  | 'user.registered'
  | 'user.login'
  | 'user.login_failed'
  | 'user.locked'
  | 'user.password_changed'
  | 'user.mfa_enabled'
  | 'user.mfa_disabled'
  | 'token.issued'
  | 'token.refreshed'
  | 'token.revoked'
  | 'session.created'
  | 'session.revoked'
  | 'session.revoked_all'
  | 'oauth.linked'
  | 'oauth.unlinked'
  | 'security.refresh_reuse_detected';

export interface AuditEvent {
  event: AuditEventName;
  userId?: string | null;
  sessionId?: string | null;
  ip?: string | null;
  userAgent?: string | null;
  timestamp: Date;
  metadata?: Record<string, unknown>;
}

// ─── Lifecycle Hooks ──────────────────────────────────────────────────────────

export interface LifecycleHooks<TUser extends BaseUser = BaseUser> {
  onBeforeRegister(data: Record<string, unknown>): Promise<void>;
  onAfterRegister(user: TUser): Promise<void>;
  onBeforeLogin(email: string, ip: string | null): Promise<void>;
  onAfterLogin(user: TUser, session: Session): Promise<void>;
  onLoginFailed(email: string, ip: string | null, reason: string): Promise<void>;
  onBeforeTokenRefresh(session: Session): Promise<void>;
  onAfterTokenRefresh(session: Session, newTokens: TokenPair): Promise<void>;
  onSessionRevoked(session: Session): Promise<void>;
}

// ─── Configuration ────────────────────────────────────────────────────────────

export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None';
  path?: string;
  domain?: string;
  maxAge?: number;
}

export interface AccessTokenConfig {
  algorithm: 'HS256' | 'RS256' | 'ES256';
  expiresIn: string;
  issuer?: string;
  audience?: string;
  /** Required for RS256/ES256 — PEM-encoded private key. */
  privateKey?: string;
  /** Required for RS256/ES256 verification — PEM-encoded public key. */
  publicKey?: string;
}

export interface RefreshTokenConfig {
  expiresIn: string;
  rotateOnUse: boolean;
  reuseDetection: boolean;
}

export interface PasswordConfig {
  algorithm: 'argon2id' | 'bcrypt';
  argon2: {
    memoryCost: number;
    timeCost: number;
    parallelism: number;
  };
  bcrypt: {
    rounds: number;
  };
  minStrengthScore: 0 | 1 | 2 | 3 | 4;
}

export interface SessionConfig {
  cookieName: string;
  cookie: CookieOptions;
  absoluteTimeout: string;
  idleTimeout: string;
}

export interface MFAConfig {
  enforcement: MFAEnforcement;
  issuer: string;
}

export interface RateLimitWindowConfig {
  windowMs: number;
  max: number;
}

export interface RateLimitConfig {
  enabled: boolean;
  store: 'memory' | 'redis';
  login: RateLimitWindowConfig;
  register: RateLimitWindowConfig;
  forgotPassword: RateLimitWindowConfig;
  verifyOtp: RateLimitWindowConfig;
}

/**
 * Full configuration for node-auth-core.
 * All fields are optional except `secret` (required for HS256).
 */
export interface AuthConfig<TUser extends BaseUser = BaseUser> {
  /** Required for HS256 JWT signing. Must be at least 32 chars in production. */
  secret?: string;
  accessToken?: Partial<AccessTokenConfig>;
  refreshToken?: Partial<RefreshTokenConfig>;
  password?: Partial<PasswordConfig>;
  session?: Partial<SessionConfig>;
  mfa?: Partial<MFAConfig>;
  rateLimit?: Partial<RateLimitConfig>;
  adapters: {
    user: UserStore<TUser>;
    session: SessionStore;
    token: TokenStore;
    credential?: CredentialStore;
    oauth?: OAuthStore;
    mfa?: MFAStore;
    rateLimit?: RateLimitStore;
  };
  hooks?: Partial<LifecycleHooks<TUser>>;
  /**
   * Set to true in development to disable Secure cookie and loosen some checks.
   * Defaults to `process.env.NODE_ENV === 'development'`.
   */
  isDevelopment?: boolean;
}

/** Resolved config with all defaults applied — internal use only. */
export interface ResolvedAuthConfig<TUser extends BaseUser = BaseUser>
  extends Required<Omit<AuthConfig<TUser>, 'secret'>> {
  secret: string;
  accessToken: AccessTokenConfig;
  refreshToken: RefreshTokenConfig;
  password: PasswordConfig;
  session: SessionConfig;
  mfa: MFAConfig;
  rateLimit: RateLimitConfig;
}

// ─── Request Context ──────────────────────────────────────────────────────────

/** Framework-agnostic request representation. */
export interface AuthRequest {
  headers: Record<string, string | string[] | undefined>;
  cookies: Record<string, string | undefined>;
  body: Record<string, unknown>;
  ip?: string | null;
  userAgent?: string | null;
}

/** Attached to the request context after successful authentication. */
export interface AuthContext<TUser extends BaseUser = BaseUser> {
  user: TUser;
  session: Session;
}

// ─── Error ────────────────────────────────────────────────────────────────────

export type AuthErrorCode =
  | 'INVALID_CREDENTIALS'
  | 'ACCOUNT_LOCKED'
  | 'ACCOUNT_NOT_VERIFIED'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_INVALID'
  | 'TOKEN_REUSE_DETECTED'
  | 'MFA_REQUIRED'
  | 'MFA_INVALID'
  | 'OTP_EXPIRED'
  | 'OTP_MAX_ATTEMPTS'
  | 'RATE_LIMITED'
  | 'SESSION_NOT_FOUND'
  | 'SESSION_EXPIRED'
  | 'OAUTH_STATE_MISMATCH'
  | 'OAUTH_CODE_INVALID'
  | 'WEBAUTHN_CHALLENGE_FAILED'
  | 'WEBAUTHN_CREDENTIAL_NOT_FOUND'
  | 'ADAPTER_NOT_CONFIGURED'
  | 'MISSING_SECRET'
  | 'INVALID_CONFIG'
  | 'PASSWORD_TOO_WEAK'
  | 'EMAIL_ALREADY_EXISTS'
  | 'USER_NOT_FOUND';
