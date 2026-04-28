/**
 * Redis adapter for session and token stores.
 * Compatible with ioredis and Upstash (via ioredis-compatible interface).
 *
 * @example
 * ```ts
 * import Redis from 'ioredis';
 * const redis = new Redis(process.env.REDIS_URL);
 * const sessionStore = new RedisSessionStore(redis);
 * ```
 */

import type {
  SessionStore,
  TokenStore,
  RateLimitStore,
  Session,
  StoredToken,
  TokenType,
} from '../../types/index.js';
import { parseDuration } from '../../config.js';

/** Minimal Redis interface — compatible with ioredis and Upstash. */
export interface RedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, exMode: 'EX', exSeconds: number): Promise<unknown>;
  set(key: string, value: string): Promise<unknown>;
  del(...keys: string[]): Promise<unknown>;
  keys(pattern: string): Promise<string[]>;
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<unknown>;
  ttl(key: string): Promise<number>;
  /** Optional — used for atomic consume. Falls back to GET+SET if unavailable. */
  eval?: (script: string, numkeys: number, ...args: string[]) => Promise<unknown>;
}

const SESSION_PREFIX = 'auth:session:';
const SESSION_USER_PREFIX = 'auth:session:user:';
const SESSION_TOKEN_PREFIX = 'auth:session:token:';
const TOKEN_PREFIX = 'auth:token:';
const RATE_PREFIX = 'auth:rate:';

// ─── RedisSessionStore ────────────────────────────────────────────────────────

export class RedisSessionStore implements SessionStore {
  constructor(private readonly redis: RedisClient) {}

  async create(data: Omit<Session, 'id' | 'createdAt' | 'lastActiveAt'>): Promise<Session> {
    const now = new Date();
    const id = generateRedisId();
    const session: Session = { ...data, id, createdAt: now, lastActiveAt: now };

    const ttlSeconds = Math.ceil((data.expiresAt.getTime() - now.getTime()) / 1000);
    await this.redis.set(
      `${SESSION_PREFIX}${id}`,
      JSON.stringify(session),
      'EX',
      ttlSeconds,
    );

    // Index by userId for findByUserId
    await this.redis.set(`${SESSION_USER_PREFIX}${data.userId}:${id}`, id, 'EX', ttlSeconds);

    // Index by refreshTokenHash for rotation
    await this.redis.set(
      `${SESSION_TOKEN_PREFIX}${data.refreshTokenHash}`,
      id,
      'EX',
      ttlSeconds,
    );

    return session;
  }

  async findById(id: string): Promise<Session | null> {
    const raw = await this.redis.get(`${SESSION_PREFIX}${id}`);
    return raw ? parseSession(raw) : null;
  }

  async findByUserId(userId: string): Promise<Session[]> {
    const keys = await this.redis.keys(`${SESSION_USER_PREFIX}${userId}:*`);
    const sessions: Session[] = [];
    for (const key of keys) {
      const sessionId = await this.redis.get(key);
      if (!sessionId) continue;
      const session = await this.findById(sessionId);
      if (session) sessions.push(session);
    }
    return sessions;
  }

  async findByRefreshTokenHash(hash: string): Promise<Session | null> {
    const sessionId = await this.redis.get(`${SESSION_TOKEN_PREFIX}${hash}`);
    if (!sessionId) return null;
    return this.findById(sessionId);
  }

  async update(id: string, data: Partial<Omit<Session, 'id' | 'userId' | 'createdAt'>>): Promise<Session> {
    const existing = await this.findById(id);
    if (!existing) throw new Error(`Session ${id} not found`);

    // Remove old token index if refreshTokenHash changed
    if (data.refreshTokenHash && data.refreshTokenHash !== existing.refreshTokenHash) {
      await this.redis.del(`${SESSION_TOKEN_PREFIX}${existing.refreshTokenHash}`);
    }

    const updated: Session = { ...existing, ...data };
    const ttlSeconds = Math.ceil((updated.expiresAt.getTime() - Date.now()) / 1000);

    if (ttlSeconds > 0) {
      await this.redis.set(`${SESSION_PREFIX}${id}`, JSON.stringify(updated), 'EX', ttlSeconds);

      if (data.refreshTokenHash) {
        await this.redis.set(
          `${SESSION_TOKEN_PREFIX}${data.refreshTokenHash}`,
          id,
          'EX',
          ttlSeconds,
        );
      }
    }

    return updated;
  }

  async delete(id: string): Promise<void> {
    const session = await this.findById(id);
    if (session) {
      await this.redis.del(
        `${SESSION_PREFIX}${id}`,
        `${SESSION_USER_PREFIX}${session.userId}:${id}`,
        `${SESSION_TOKEN_PREFIX}${session.refreshTokenHash}`,
      );
    }
  }

  async deleteAllForUser(userId: string): Promise<void> {
    const keys = await this.redis.keys(`${SESSION_USER_PREFIX}${userId}:*`);
    for (const key of keys) {
      const sessionId = await this.redis.get(key);
      if (sessionId) await this.delete(sessionId);
    }
  }
}

// ─── RedisTokenStore ──────────────────────────────────────────────────────────

export class RedisTokenStore implements TokenStore {
  constructor(private readonly redis: RedisClient) {}

  async save(token: Omit<StoredToken, 'createdAt'>): Promise<StoredToken> {
    const stored: StoredToken = { ...token, createdAt: new Date() };
    const ttlSeconds = Math.ceil((token.expiresAt.getTime() - Date.now()) / 1000);
    if (ttlSeconds > 0) {
      await this.redis.set(
        `${TOKEN_PREFIX}${token.type}:${token.tokenHash}`,
        JSON.stringify(stored),
        'EX',
        ttlSeconds,
      );
    }
    return stored;
  }

  async find(tokenHash: string, type: TokenType): Promise<StoredToken | null> {
    const raw = await this.redis.get(`${TOKEN_PREFIX}${type}:${tokenHash}`);
    return raw ? parseToken(raw) : null;
  }

  async consume(tokenHash: string, type: TokenType): Promise<StoredToken | null> {
    const key = `${TOKEN_PREFIX}${type}:${tokenHash}`;

    // Use Lua script for atomic consume if eval is available
    if (this.redis.eval) {
      const luaScript = `
        local val = redis.call('GET', KEYS[1])
        if not val then return nil end
        local token = cjson.decode(val)
        if token.consumed then return nil end
        token.consumed = true
        local ttl = redis.call('TTL', KEYS[1])
        if ttl > 0 then
          redis.call('SET', KEYS[1], cjson.encode(token), 'EX', ttl)
        end
        return cjson.encode(token)
      `;
      const result = await this.redis.eval(luaScript, 1, key) as string | null;
      return result ? parseToken(result) : null;
    }

    // Fallback: non-atomic (acceptable for single-instance Redis)
    const token = await this.find(tokenHash, type);
    if (!token || token.consumed) return null;
    const consumed = { ...token, consumed: true };
    const ttlSeconds = Math.ceil((token.expiresAt.getTime() - Date.now()) / 1000);
    if (ttlSeconds > 0) {
      await this.redis.set(key, JSON.stringify(consumed), 'EX', ttlSeconds);
    }
    return consumed;
  }

  async deleteExpired(): Promise<void> {
    // Redis TTL handles expiry automatically — this is a no-op
  }
}

// ─── RedisRateLimitStore ──────────────────────────────────────────────────────

export class RedisRateLimitStore implements RateLimitStore {
  constructor(private readonly redis: RedisClient) {}

  async increment(key: string, windowMs: number): Promise<{ count: number; resetAt: Date }> {
    const redisKey = `${RATE_PREFIX}${key}`;
    const count = await this.redis.incr(redisKey);

    if (count === 1) {
      // First increment — set expiry
      const windowSeconds = Math.ceil(windowMs / 1000);
      await this.redis.expire(redisKey, windowSeconds);
    }

    const ttl = await this.redis.ttl(redisKey);
    const resetAt = new Date(Date.now() + ttl * 1000);

    return { count, resetAt };
  }

  async reset(key: string): Promise<void> {
    await this.redis.del(`${RATE_PREFIX}${key}`);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateRedisId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function parseSession(raw: string): Session {
  const data = JSON.parse(raw) as Record<string, unknown>;
  return {
    ...data,
    createdAt: new Date(data['createdAt'] as string),
    lastActiveAt: new Date(data['lastActiveAt'] as string),
    expiresAt: new Date(data['expiresAt'] as string),
  } as Session;
}

function parseToken(raw: string): StoredToken {
  const data = JSON.parse(raw) as Record<string, unknown>;
  return {
    ...data,
    expiresAt: new Date(data['expiresAt'] as string),
    createdAt: new Date(data['createdAt'] as string),
  } as StoredToken;
}
