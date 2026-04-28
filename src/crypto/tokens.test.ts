import { describe, it, expect } from 'vitest';
import {
  generateOpaqueToken,
  hashToken,
  safeCompare,
  safeCompareBuffers,
  generateOTP,
  secureRandomInt,
} from './tokens.js';

describe('generateOpaqueToken', () => {
  it('returns a hex string of the correct length', () => {
    const token = generateOpaqueToken(32);
    expect(token).toHaveLength(64); // 32 bytes → 64 hex chars
  });

  it('generates unique tokens', () => {
    const tokens = new Set(Array.from({ length: 100 }, () => generateOpaqueToken()));
    expect(tokens.size).toBe(100);
  });

  it('respects custom byte length', () => {
    expect(generateOpaqueToken(16)).toHaveLength(32);
    expect(generateOpaqueToken(48)).toHaveLength(96);
  });
});

describe('hashToken', () => {
  it('produces a 64-char hex SHA-256 hash', () => {
    const hash = hashToken('test-token');
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]+$/);
  });

  it('is deterministic', () => {
    expect(hashToken('abc')).toBe(hashToken('abc'));
  });

  it('produces different hashes for different inputs', () => {
    expect(hashToken('abc')).not.toBe(hashToken('abd'));
  });

  it('matches known SHA-256 vector', () => {
    // SHA-256('') = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    expect(hashToken('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});

describe('safeCompare', () => {
  it('returns true for equal strings', () => {
    expect(safeCompare('hello', 'hello')).toBe(true);
  });

  it('returns false for different strings of same length', () => {
    expect(safeCompare('hello', 'world')).toBe(false);
  });

  it('returns false for different-length strings', () => {
    expect(safeCompare('short', 'longer-string')).toBe(false);
  });

  it('returns false for empty vs non-empty', () => {
    expect(safeCompare('', 'a')).toBe(false);
  });

  it('returns true for empty strings', () => {
    expect(safeCompare('', '')).toBe(true);
  });

  it('handles unicode correctly', () => {
    expect(safeCompare('héllo', 'héllo')).toBe(true);
    expect(safeCompare('héllo', 'hello')).toBe(false);
  });
});

describe('safeCompareBuffers', () => {
  it('returns true for equal buffers', () => {
    const a = Buffer.from('secret', 'utf8');
    const b = Buffer.from('secret', 'utf8');
    expect(safeCompareBuffers(a, b)).toBe(true);
  });

  it('returns false for different buffers of same length', () => {
    const a = Buffer.from('aaaaaa', 'utf8');
    const b = Buffer.from('bbbbbb', 'utf8');
    expect(safeCompareBuffers(a, b)).toBe(false);
  });

  it('returns false for different-length buffers', () => {
    const a = Buffer.from('abc', 'utf8');
    const b = Buffer.from('abcd', 'utf8');
    expect(safeCompareBuffers(a, b)).toBe(false);
  });
});

describe('generateOTP', () => {
  it('generates a 6-digit string', () => {
    for (let i = 0; i < 50; i++) {
      const otp = generateOTP();
      expect(otp).toHaveLength(6);
      expect(otp).toMatch(/^\d{6}$/);
    }
  });

  it('zero-pads small values', () => {
    // We can't force a specific value, but we verify the format is always 6 digits
    const otps = Array.from({ length: 1000 }, () => generateOTP());
    for (const otp of otps) {
      expect(otp).toHaveLength(6);
    }
  });

  it('generates values in range [000000, 999999]', () => {
    const otps = Array.from({ length: 100 }, () => parseInt(generateOTP(), 10));
    for (const n of otps) {
      expect(n).toBeGreaterThanOrEqual(0);
      expect(n).toBeLessThan(1_000_000);
    }
  });
});

describe('secureRandomInt', () => {
  it('returns values in [0, max)', () => {
    for (let i = 0; i < 100; i++) {
      const n = secureRandomInt(10);
      expect(n).toBeGreaterThanOrEqual(0);
      expect(n).toBeLessThan(10);
    }
  });
});
