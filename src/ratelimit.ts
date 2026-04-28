import type { RateLimitStore, RateLimitWindowConfig } from './types/index.js';
import { Errors } from './errors.js';

/**
 * In-memory sliding window rate limiter.
 * For distributed deployments, swap with the Redis adapter.
 *
 * SECURITY NOTE: In-memory store is per-process. Use Redis for multi-instance deployments.
 */

interface WindowEntry {
  count: number;
  resetAt: number;
}

export class MemoryRateLimitStore implements RateLimitStore {
  private readonly store = new Map<string, WindowEntry>();

  async increment(key: string, windowMs: number): Promise<{ count: number; resetAt: Date }> {
    const now = Date.now();
    const entry = this.store.get(key);

    if (!entry || now >= entry.resetAt) {
      const resetAt = now + windowMs;
      this.store.set(key, { count: 1, resetAt });
      return { count: 1, resetAt: new Date(resetAt) };
    }

    entry.count += 1;
    return { count: entry.count, resetAt: new Date(entry.resetAt) };
  }

  async reset(key: string): Promise<void> {
    this.store.delete(key);
  }
}

/**
 * Check a rate limit and throw RATE_LIMITED if exceeded.
 *
 * @param store - Rate limit store
 * @param key - Unique key (e.g. `login:ip:1.2.3.4`)
 * @param config - Window configuration
 */
export async function checkRateLimit(
  store: RateLimitStore,
  key: string,
  config: RateLimitWindowConfig,
): Promise<void> {
  const { count, resetAt } = await store.increment(key, config.windowMs);
  if (count > config.max) {
    const retryAfterMs = resetAt.getTime() - Date.now();
    throw Errors.rateLimited(retryAfterMs);
  }
}
