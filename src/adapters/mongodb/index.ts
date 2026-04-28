/**
 * MongoDB adapter — inject your Mongoose model or native Collection.
 *
 * @example
 * ```ts
 * // With Mongoose
 * const userStore = new MongoUserStore(UserModel);
 *
 * // With native driver
 * const userStore = new MongoUserStore(db.collection('users'));
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

/** Minimal MongoDB collection interface — compatible with native driver and Mongoose. */
export interface MongoCollection<T extends Record<string, unknown> = Record<string, unknown>> {
  findOne(filter: Partial<T> | Record<string, unknown>): Promise<T | null>;
  find(filter: Partial<T> | Record<string, unknown>): { toArray(): Promise<T[]> };
  insertOne(doc: T): Promise<{ insertedId: unknown }>;
  findOneAndUpdate(
    filter: Partial<T> | Record<string, unknown>,
    update: Record<string, unknown>,
    options?: { returnDocument?: 'after' | 'before'; upsert?: boolean },
  ): Promise<T | null>;
  deleteOne(filter: Partial<T> | Record<string, unknown>): Promise<unknown>;
  deleteMany(filter: Partial<T> | Record<string, unknown>): Promise<unknown>;
}

// ─── MongoUserStore ───────────────────────────────────────────────────────────

export class MongoUserStore<TUser extends BaseUser> implements UserStore<TUser> {
  constructor(private readonly collection: MongoCollection) {}

  async findById(id: string): Promise<TUser | null> {
    const doc = await this.collection.findOne({ _id: id } as Record<string, unknown>);
    return doc ? mapUser<TUser>(doc) : null;
  }

  async findByEmail(email: string): Promise<TUser | null> {
    const doc = await this.collection.findOne({ email: email.toLowerCase().trim() });
    return doc ? mapUser<TUser>(doc) : null;
  }

  async create(data: Omit<TUser, 'id' | 'createdAt' | 'updatedAt'>): Promise<TUser> {
    const now = new Date();
    const id = generateMongoId();
    const doc = { ...data, _id: id, createdAt: now, updatedAt: now } as Record<string, unknown>;
    await this.collection.insertOne(doc);
    return mapUser<TUser>(doc);
  }

  async update(id: string, data: Partial<Omit<TUser, 'id' | 'createdAt'>>): Promise<TUser> {
    const doc = await this.collection.findOneAndUpdate(
      { _id: id } as Record<string, unknown>,
      { $set: { ...data, updatedAt: new Date() } },
      { returnDocument: 'after' },
    );
    if (!doc) throw new Error(`User ${id} not found`);
    return mapUser<TUser>(doc);
  }

  async delete(id: string): Promise<void> {
    await this.collection.deleteOne({ _id: id } as Record<string, unknown>);
  }
}

// ─── MongoSessionStore ────────────────────────────────────────────────────────

export class MongoSessionStore implements SessionStore {
  constructor(private readonly collection: MongoCollection) {}

  async create(data: Omit<Session, 'id' | 'createdAt' | 'lastActiveAt'>): Promise<Session> {
    const now = new Date();
    const id = generateMongoId();
    const doc = { ...data, _id: id, createdAt: now, lastActiveAt: now } as Record<string, unknown>;
    await this.collection.insertOne(doc);
    return mapSession(doc);
  }

  async findById(id: string): Promise<Session | null> {
    const doc = await this.collection.findOne({ _id: id } as Record<string, unknown>);
    return doc ? mapSession(doc) : null;
  }

  async findByUserId(userId: string): Promise<Session[]> {
    const docs = await this.collection.find({ userId }).toArray();
    return docs.map(mapSession);
  }

  async findByRefreshTokenHash(hash: string): Promise<Session | null> {
    const doc = await this.collection.findOne({ refreshTokenHash: hash });
    return doc ? mapSession(doc) : null;
  }

  async update(id: string, data: Partial<Omit<Session, 'id' | 'userId' | 'createdAt'>>): Promise<Session> {
    const doc = await this.collection.findOneAndUpdate(
      { _id: id } as Record<string, unknown>,
      { $set: data },
      { returnDocument: 'after' },
    );
    if (!doc) throw new Error(`Session ${id} not found`);
    return mapSession(doc);
  }

  async delete(id: string): Promise<void> {
    await this.collection.deleteOne({ _id: id } as Record<string, unknown>);
  }

  async deleteAllForUser(userId: string): Promise<void> {
    await this.collection.deleteMany({ userId });
  }
}

// ─── MongoTokenStore ──────────────────────────────────────────────────────────

export class MongoTokenStore implements TokenStore {
  constructor(private readonly collection: MongoCollection) {}

  async save(token: Omit<StoredToken, 'createdAt'>): Promise<StoredToken> {
    const stored: StoredToken = { ...token, createdAt: new Date() };
    await this.collection.findOneAndUpdate(
      { tokenHash: token.tokenHash, type: token.type },
      { $set: stored },
      { upsert: true },
    );
    return stored;
  }

  async find(tokenHash: string, type: TokenType): Promise<StoredToken | null> {
    const doc = await this.collection.findOne({ tokenHash, type });
    return doc ? mapToken(doc) : null;
  }

  async consume(tokenHash: string, type: TokenType): Promise<StoredToken | null> {
    // Atomic: only update if consumed = false
    const doc = await this.collection.findOneAndUpdate(
      { tokenHash, type, consumed: false },
      { $set: { consumed: true } },
      { returnDocument: 'after' },
    );
    return doc ? mapToken(doc) : null;
  }

  async deleteExpired(): Promise<void> {
    await this.collection.deleteMany({ expiresAt: { $lt: new Date() } });
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateMongoId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function mapUser<TUser extends BaseUser>(doc: Record<string, unknown>): TUser {
  const { _id, ...rest } = doc;
  return { ...rest, id: String(_id) } as TUser;
}

function mapSession(doc: Record<string, unknown>): Session {
  const { _id, ...rest } = doc;
  return {
    ...rest,
    id: String(_id),
    createdAt: new Date(rest['createdAt'] as string | Date),
    lastActiveAt: new Date(rest['lastActiveAt'] as string | Date),
    expiresAt: new Date(rest['expiresAt'] as string | Date),
  } as Session;
}

function mapToken(doc: Record<string, unknown>): StoredToken {
  const { _id, ...rest } = doc;
  return {
    ...rest,
    expiresAt: new Date(rest['expiresAt'] as string | Date),
    createdAt: new Date(rest['createdAt'] as string | Date),
  } as StoredToken;
}
