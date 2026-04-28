import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { MemoryRateLimitStore, checkRateLimit } from './ratelimit.js';

describe('MemoryRateLimitStore', () => {
  let store: MemoryRateLimitStore;

  beforeEach(() => {
    store = new MemoryRateLimitStore();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('increments count on each call', async () => {
    const { count: c1 } = await store.increment('key', 60_000);
    const { count: c2 } = await store.increment('key', 60_000);
    const { count: c3 } = await store.increment('key', 60_000);
    expect(c1).toBe(1);
    expect(c2).toBe(2);
    expect(c3).toBe(3);
  });

  it('resets count after window expires', async () => {
    await store.increment('key', 1_000);
    await store.increment('key', 1_000);

    vi.advanceTimersByTime(1_001);

    const { count } = await store.increment('key', 1_000);
    expect(count).toBe(1);
  });

  it('tracks different keys independently', async () => {
    await store.increment('key-a', 60_000);
    await store.increment('key-a', 60_000);
    const { count: b } = await store.increment('key-b', 60_000);
    expect(b).toBe(1);
  });

  it('reset() clears the key', async () => {
    await store.increment('key', 60_000);
    await store.increment('key', 60_000);
    await store.reset('key');
    const { count } = await store.increment('key', 60_000);
    expect(count).toBe(1);
  });
});

describe('checkRateLimit', () => {
  let store: MemoryRateLimitStore;

  beforeEach(() => {
    store = new MemoryRateLimitStore();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('does not throw when under the limit', async () => {
    await expect(
      checkRateLimit(store, 'key', { windowMs: 60_000, max: 5 }),
    ).resolves.not.toThrow();
  });

  it('throws RATE_LIMITED when limit is exceeded', async () => {
    const config = { windowMs: 60_000, max: 3 };
    await checkRateLimit(store, 'key', config);
    await checkRateLimit(store, 'key', config);
    await checkRateLimit(store, 'key', config);

    await expect(checkRateLimit(store, 'key', config)).rejects.toMatchObject({
      code: 'RATE_LIMITED',
      statusCode: 429,
    });
  });

  it('includes retryAfterMs in the error', async () => {
    const config = { windowMs: 60_000, max: 1 };
    await checkRateLimit(store, 'key', config);

    try {
      await checkRateLimit(store, 'key', config);
      expect.fail('Should have thrown');
    } catch (err: unknown) {
      expect((err as { details?: { retryAfterMs?: number } }).details?.retryAfterMs).toBeGreaterThan(0);
    }
  });

  it('resets after window expires', async () => {
    const config = { windowMs: 1_000, max: 1 };
    await checkRateLimit(store, 'key', config);

    vi.advanceTimersByTime(1_001);

    await expect(checkRateLimit(store, 'key', config)).resolves.not.toThrow();
  });
});
