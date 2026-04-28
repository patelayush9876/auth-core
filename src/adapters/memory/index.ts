/**
 * In-memory adapters — for development and testing ONLY.
 *
 * SECURITY WARNING: These adapters store all data in process memory.
 * Data is lost on restart. Never use in production.
 */

import type {
  BaseUser,
  UserStore,
  SessionStore,
  TokenStore,
  CredentialStore,
  OAuthStore,
  MFAStore,
  RateLimitStore,
  Session,
  StoredToken,
  TokenType,
  WebAuthnCredential,
  OAuthAccount,
  TOTPSecret,
  BackupCode,
} from '../../types/index.js';

function warnIfProduction(adapterName: string): void {
  if (process.env['NODE_ENV'] === 'production') {
    console.warn(
      `[node-auth-core] ⚠️  WARNING: InMemory${adapterName}Adapter is being used in production! ` +
        'This adapter is for development/testing only. Switch to a persistent adapter.',
    );
  }
}

function generateId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

// ─── InMemoryUserStore ────────────────────────────────────────────────────────

export class InMemoryUserStore<TUser extends BaseUser> implements UserStore<TUser> {
  private readonly users = new Map<string, TUser>();

  constructor() {
    warnIfProduction('User');
  }

  async findById(id: string): Promise<TUser | null> {
    return this.users.get(id) ?? null;
  }

  async findByEmail(email: string): Promise<TUser | null> {
    for (const user of this.users.values()) {
      if (user.email === email.toLowerCase().trim()) return user;
    }
    return null;
  }

  async create(data: Omit<TUser, 'id' | 'createdAt' | 'updatedAt'>): Promise<TUser> {
    const now = new Date();
    const user = { ...data, id: generateId(), createdAt: now, updatedAt: now } as TUser;
    this.users.set(user.id, user);
    return user;
  }

  async update(id: string, data: Partial<Omit<TUser, 'id' | 'createdAt'>>): Promise<TUser> {
    const existing = this.users.get(id);
    if (!existing) throw new Error(`User ${id} not found`);
    const updated = { ...existing, ...data, updatedAt: new Date() } as TUser;
    this.users.set(id, updated);
    return updated;
  }

  async delete(id: string): Promise<void> {
    this.users.delete(id);
  }

  /** Test helper — clear all users. */
  clear(): void {
    this.users.clear();
  }

  /** Test helper — get all users. */
  all(): TUser[] {
    return [...this.users.values()];
  }
}

// ─── InMemorySessionStore ─────────────────────────────────────────────────────

export class InMemorySessionStore implements SessionStore {
  private readonly sessions = new Map<string, Session>();
  /** Tracks recently consumed (rotated) refresh token hashes for reuse detection. */
  private readonly consumedHashes = new Map<string, { userId: string; tokenFamily: string; consumedAt: number }>();

  constructor() {
    warnIfProduction('Session');
  }

  async create(data: Omit<Session, 'id' | 'createdAt' | 'lastActiveAt'>): Promise<Session> {
    const now = new Date();
    const session: Session = {
      ...data,
      id: generateId(),
      createdAt: now,
      lastActiveAt: now,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  async findById(id: string): Promise<Session | null> {
    return this.sessions.get(id) ?? null;
  }

  async findByUserId(userId: string): Promise<Session[]> {
    return [...this.sessions.values()].filter((s) => s.userId === userId);
  }

  async update(id: string, data: Partial<Omit<Session, 'id' | 'userId' | 'createdAt'>>): Promise<Session> {
    const existing = this.sessions.get(id);
    if (!existing) throw new Error(`Session ${id} not found`);

    // Track old refresh token hash for reuse detection
    if (data.refreshTokenHash && data.refreshTokenHash !== existing.refreshTokenHash) {
      this.consumedHashes.set(existing.refreshTokenHash, {
        userId: existing.userId,
        tokenFamily: existing.tokenFamily,
        consumedAt: Date.now(),
      });
    }

    const updated = { ...existing, ...data };
    this.sessions.set(id, updated);
    return updated;
  }  async delete(id: string): Promise<void> {
    this.sessions.delete(id);
  }

  async deleteAllForUser(userId: string): Promise<void> {
    for (const [id, session] of this.sessions) {
      if (session.userId === userId) this.sessions.delete(id);
    }
  }

  /** Extended method for refresh token lookup — O(n) but acceptable for in-memory. */
  async findByRefreshTokenHash(hash: string): Promise<Session | null> {
    for (const session of this.sessions.values()) {
      if (session.refreshTokenHash === hash) return session;
    }
    return null;
  }

  /**
   * Check if a hash was recently consumed (rotated away).
   * Returns the userId + tokenFamily if found — used for reuse detection.
   */
  findConsumedHash(hash: string): { userId: string; tokenFamily: string } | null {
    return this.consumedHashes.get(hash) ?? null;
  }

  clear(): void {
    this.sessions.clear();
    this.consumedHashes.clear();
  }
}

// ─── InMemoryTokenStore ───────────────────────────────────────────────────────

export class InMemoryTokenStore implements TokenStore {
  private readonly tokens = new Map<string, StoredToken>();

  constructor() {
    warnIfProduction('Token');
  }

  async save(token: Omit<StoredToken, 'createdAt'>): Promise<StoredToken> {
    const stored: StoredToken = { ...token, createdAt: new Date() };
    this.tokens.set(`${token.type}:${token.tokenHash}`, stored);
    return stored;
  }

  async find(tokenHash: string, type: TokenType): Promise<StoredToken | null> {
    return this.tokens.get(`${type}:${tokenHash}`) ?? null;
  }

  async consume(tokenHash: string, type: TokenType): Promise<StoredToken | null> {
    const key = `${type}:${tokenHash}`;
    const token = this.tokens.get(key);
    if (!token || token.consumed) return null;
    const consumed = { ...token, consumed: true };
    this.tokens.set(key, consumed);
    return consumed;
  }

  async deleteExpired(): Promise<void> {
    const now = new Date();
    for (const [key, token] of this.tokens) {
      if (token.expiresAt < now) this.tokens.delete(key);
    }
  }

  clear(): void {
    this.tokens.clear();
  }
}

// ─── InMemoryCredentialStore ──────────────────────────────────────────────────

export class InMemoryCredentialStore implements CredentialStore {
  private readonly credentials = new Map<string, WebAuthnCredential>();

  constructor() {
    warnIfProduction('Credential');
  }

  async save(data: Omit<WebAuthnCredential, 'id' | 'createdAt'>): Promise<WebAuthnCredential> {
    const credential: WebAuthnCredential = { ...data, id: generateId(), createdAt: new Date() };
    this.credentials.set(credential.credentialId, credential);
    return credential;
  }

  async findById(credentialId: string): Promise<WebAuthnCredential | null> {
    return this.credentials.get(credentialId) ?? null;
  }

  async findByUserId(userId: string): Promise<WebAuthnCredential[]> {
    return [...this.credentials.values()].filter((c) => c.userId === userId);
  }

  async update(
    credentialId: string,
    data: Partial<Pick<WebAuthnCredential, 'counter' | 'lastUsedAt'>>,
  ): Promise<WebAuthnCredential> {
    const existing = this.credentials.get(credentialId);
    if (!existing) throw new Error(`Credential ${credentialId} not found`);
    const updated = { ...existing, ...data };
    this.credentials.set(credentialId, updated);
    return updated;
  }

  async delete(credentialId: string): Promise<void> {
    this.credentials.delete(credentialId);
  }

  clear(): void {
    this.credentials.clear();
  }
}

// ─── InMemoryOAuthStore ───────────────────────────────────────────────────────

export class InMemoryOAuthStore implements OAuthStore {
  private readonly accounts = new Map<string, OAuthAccount>();

  constructor() {
    warnIfProduction('OAuth');
  }

  async save(data: Omit<OAuthAccount, 'id' | 'createdAt'>): Promise<OAuthAccount> {
    const account: OAuthAccount = { ...data, id: generateId(), createdAt: new Date() };
    this.accounts.set(account.id, account);
    return account;
  }

  async findByProvider(provider: string, providerUserId: string): Promise<OAuthAccount | null> {
    for (const account of this.accounts.values()) {
      if (account.provider === provider && account.providerUserId === providerUserId) {
        return account;
      }
    }
    return null;
  }

  async findByUserId(userId: string): Promise<OAuthAccount[]> {
    return [...this.accounts.values()].filter((a) => a.userId === userId);
  }

  async delete(id: string): Promise<void> {
    this.accounts.delete(id);
  }

  clear(): void {
    this.accounts.clear();
  }
}

// ─── InMemoryMFAStore ─────────────────────────────────────────────────────────

export class InMemoryMFAStore implements MFAStore {
  private readonly totpSecrets = new Map<string, TOTPSecret>();
  private readonly backupCodes = new Map<string, BackupCode[]>();

  constructor() {
    warnIfProduction('MFA');
  }

  async saveTOTP(secret: TOTPSecret): Promise<void> {
    this.totpSecrets.set(secret.userId, secret);
  }

  async findTOTP(userId: string): Promise<TOTPSecret | null> {
    return this.totpSecrets.get(userId) ?? null;
  }

  async deleteTOTP(userId: string): Promise<void> {
    this.totpSecrets.delete(userId);
  }

  async saveBackupCodes(codes: BackupCode[]): Promise<void> {
    const userId = codes[0]?.userId;
    if (!userId) return;
    this.backupCodes.set(userId, codes);
  }

  async findBackupCodes(userId: string): Promise<BackupCode[]> {
    return this.backupCodes.get(userId) ?? [];
  }

  async consumeBackupCode(userId: string, codeHash: string): Promise<boolean> {
    const codes = this.backupCodes.get(userId) ?? [];
    const idx = codes.findIndex((c) => c.codeHash === codeHash && !c.used);
    if (idx === -1) return false;
    const code = codes[idx];
    if (code) {
      codes[idx] = { ...code, used: true };
    }
    this.backupCodes.set(userId, codes);
    return true;
  }

  async deleteBackupCodes(userId: string): Promise<void> {
    this.backupCodes.delete(userId);
  }

  clear(): void {
    this.totpSecrets.clear();
    this.backupCodes.clear();
  }
}

// ─── InMemoryRateLimitStore ───────────────────────────────────────────────────

export { MemoryRateLimitStore as InMemoryRateLimitStore } from '../../ratelimit.js';
