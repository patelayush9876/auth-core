/**
 * SQL adapter — compatible with Prisma, Drizzle, Knex, or any query executor.
 * You provide a query executor function; this adapter handles the mapping.
 *
 * @example
 * ```ts
 * // With Prisma
 * const userStore = new SqlUserStore(async (sql, params) => {
 *   return prisma.$queryRawUnsafe(sql, ...params);
 * });
 *
 * // With Knex
 * const userStore = new SqlUserStore(async (sql, params) => {
 *   return knex.raw(sql, params).then(r => r.rows);
 * });
 * ```
 */

import type {
  BaseUser,
  UserStore,
  SessionStore,
  TokenStore,
  Session,
  StoredToken,
  TokenType,
} from '../../types/index.js';

/** A function that executes a parameterized SQL query and returns rows. */
export type QueryExecutor = (
  sql: string,
  params: unknown[],
) => Promise<Record<string, unknown>[]>;

// ─── SqlUserStore ─────────────────────────────────────────────────────────────

/**
 * SQL-backed user store.
 * Assumes a `users` table with columns matching BaseUser fields.
 * Customize table/column names via the options parameter.
 */
export class SqlUserStore<TUser extends BaseUser> implements UserStore<TUser> {
  constructor(
    private readonly query: QueryExecutor,
    private readonly table = 'users',
  ) {}

  async findById(id: string): Promise<TUser | null> {
    const rows = await this.query(`SELECT * FROM ${this.table} WHERE id = $1 LIMIT 1`, [id]);
    return (rows[0] as TUser | undefined) ?? null;
  }

  async findByEmail(email: string): Promise<TUser | null> {
    const rows = await this.query(
      `SELECT * FROM ${this.table} WHERE email = $1 LIMIT 1`,
      [email.toLowerCase().trim()],
    );
    return (rows[0] as TUser | undefined) ?? null;
  }

  async create(data: Omit<TUser, 'id' | 'createdAt' | 'updatedAt'>): Promise<TUser> {
    const now = new Date();
    const keys = Object.keys(data);
    const values = Object.values(data);
    const placeholders = keys.map((_, i) => `$${i + 3}`).join(', ');
    const cols = ['id', 'created_at', 'updated_at', ...keys].join(', ');

    const id = generateSqlId();
    const rows = await this.query(
      `INSERT INTO ${this.table} (${cols}) VALUES ($1, $2, $2, ${placeholders}) RETURNING *`,
      [id, now, ...values],
    );
    return rows[0] as TUser;
  }

  async update(id: string, data: Partial<Omit<TUser, 'id' | 'createdAt'>>): Promise<TUser> {
    const entries = Object.entries(data);
    const sets = entries.map(([k, _], i) => `${toSnakeCase(k)} = $${i + 2}`).join(', ');
    const values = entries.map(([, v]) => v);

    const rows = await this.query(
      `UPDATE ${this.table} SET ${sets}, updated_at = NOW() WHERE id = $1 RETURNING *`,
      [id, ...values],
    );
    return rows[0] as TUser;
  }

  async delete(id: string): Promise<void> {
    await this.query(`DELETE FROM ${this.table} WHERE id = $1`, [id]);
  }
}

// ─── SqlSessionStore ──────────────────────────────────────────────────────────

export class SqlSessionStore implements SessionStore {
  constructor(
    private readonly query: QueryExecutor,
    private readonly table = 'sessions',
  ) {}

  async create(data: Omit<Session, 'id' | 'createdAt' | 'lastActiveAt'>): Promise<Session> {
    const now = new Date();
    const id = generateSqlId();
    const rows = await this.query(
      `INSERT INTO ${this.table}
        (id, user_id, refresh_token_hash, token_family, device_fingerprint,
         user_agent, ip, mfa_verified, expires_at, created_at, last_active_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10) RETURNING *`,
      [
        id,
        data.userId,
        data.refreshTokenHash,
        data.tokenFamily,
        data.deviceFingerprint ?? null,
        data.userAgent ?? null,
        data.ip ?? null,
        data.mfaVerified,
        data.expiresAt,
        now,
      ],
    );
    return mapSession(rows[0] as Record<string, unknown>);
  }

  async findById(id: string): Promise<Session | null> {
    const rows = await this.query(`SELECT * FROM ${this.table} WHERE id = $1`, [id]);
    return rows[0] ? mapSession(rows[0] as Record<string, unknown>) : null;
  }

  async findByUserId(userId: string): Promise<Session[]> {
    const rows = await this.query(`SELECT * FROM ${this.table} WHERE user_id = $1`, [userId]);
    return rows.map((r) => mapSession(r as Record<string, unknown>));
  }

  async findByRefreshTokenHash(hash: string): Promise<Session | null> {
    const rows = await this.query(
      `SELECT * FROM ${this.table} WHERE refresh_token_hash = $1 LIMIT 1`,
      [hash],
    );
    return rows[0] ? mapSession(rows[0] as Record<string, unknown>) : null;
  }

  async update(id: string, data: Partial<Omit<Session, 'id' | 'userId' | 'createdAt'>>): Promise<Session> {
    const entries = Object.entries(data);
    const sets = entries.map(([k, _], i) => `${toSnakeCase(k)} = $${i + 2}`).join(', ');
    const values = entries.map(([, v]) => v);

    const rows = await this.query(
      `UPDATE ${this.table} SET ${sets} WHERE id = $1 RETURNING *`,
      [id, ...values],
    );
    return mapSession(rows[0] as Record<string, unknown>);
  }

  async delete(id: string): Promise<void> {
    await this.query(`DELETE FROM ${this.table} WHERE id = $1`, [id]);
  }

  async deleteAllForUser(userId: string): Promise<void> {
    await this.query(`DELETE FROM ${this.table} WHERE user_id = $1`, [userId]);
  }
}

// ─── SqlTokenStore ────────────────────────────────────────────────────────────

export class SqlTokenStore implements TokenStore {
  constructor(
    private readonly query: QueryExecutor,
    private readonly table = 'auth_tokens',
  ) {}

  async save(token: Omit<StoredToken, 'createdAt'>): Promise<StoredToken> {
    const now = new Date();
    const rows = await this.query(
      `INSERT INTO ${this.table}
        (token_hash, user_id, type, expires_at, consumed, metadata, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (token_hash, type) DO UPDATE
         SET expires_at = EXCLUDED.expires_at, consumed = false
       RETURNING *`,
      [
        token.tokenHash,
        token.userId,
        token.type,
        token.expiresAt,
        token.consumed,
        token.metadata ? JSON.stringify(token.metadata) : null,
        now,
      ],
    );
    return mapToken(rows[0] as Record<string, unknown>);
  }

  async find(tokenHash: string, type: TokenType): Promise<StoredToken | null> {
    const rows = await this.query(
      `SELECT * FROM ${this.table} WHERE token_hash = $1 AND type = $2 LIMIT 1`,
      [tokenHash, type],
    );
    return rows[0] ? mapToken(rows[0] as Record<string, unknown>) : null;
  }

  async consume(tokenHash: string, type: TokenType): Promise<StoredToken | null> {
    // Atomic consume — only succeeds if not already consumed
    const rows = await this.query(
      `UPDATE ${this.table}
       SET consumed = true
       WHERE token_hash = $1 AND type = $2 AND consumed = false
       RETURNING *`,
      [tokenHash, type],
    );
    return rows[0] ? mapToken(rows[0] as Record<string, unknown>) : null;
  }

  async deleteExpired(): Promise<void> {
    await this.query(`DELETE FROM ${this.table} WHERE expires_at < NOW()`, []);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateSqlId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function toSnakeCase(str: string): string {
  return str.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
}

function mapSession(row: Record<string, unknown>): Session {
  return {
    id: row['id'] as string,
    userId: (row['user_id'] ?? row['userId']) as string,
    refreshTokenHash: (row['refresh_token_hash'] ?? row['refreshTokenHash']) as string,
    tokenFamily: (row['token_family'] ?? row['tokenFamily']) as string,
    deviceFingerprint: (row['device_fingerprint'] ?? row['deviceFingerprint'] ?? null) as string | null,
    userAgent: (row['user_agent'] ?? row['userAgent'] ?? null) as string | null,
    ip: (row['ip'] ?? null) as string | null,
    mfaVerified: Boolean(row['mfa_verified'] ?? row['mfaVerified']),
    createdAt: new Date(row['created_at'] as string | Date),
    lastActiveAt: new Date((row['last_active_at'] ?? row['lastActiveAt']) as string | Date),
    expiresAt: new Date((row['expires_at'] ?? row['expiresAt']) as string | Date),
  };
}

function mapToken(row: Record<string, unknown>): StoredToken {
  return {
    tokenHash: (row['token_hash'] ?? row['tokenHash']) as string,
    userId: (row['user_id'] ?? row['userId']) as string,
    type: (row['type']) as TokenType,
    expiresAt: new Date((row['expires_at'] ?? row['expiresAt']) as string | Date),
    consumed: Boolean(row['consumed']),
    createdAt: new Date((row['created_at'] ?? row['createdAt']) as string | Date),
    metadata: row['metadata']
      ? (typeof row['metadata'] === 'string'
          ? JSON.parse(row['metadata']) as Record<string, unknown>
          : row['metadata'] as Record<string, unknown>)
      : undefined,
  };
}
