import { describe, it, expect } from 'vitest';
import { generateCodeVerifier, generateCodeChallenge, validateCodeVerifier } from './pkce.js';

describe('generateCodeVerifier', () => {
  it('returns a base64url string of at least 43 chars', () => {
    const verifier = generateCodeVerifier();
    expect(verifier.length).toBeGreaterThanOrEqual(43);
    expect(verifier.length).toBeLessThanOrEqual(128);
  });

  it('only contains base64url characters', () => {
    const verifier = generateCodeVerifier();
    expect(verifier).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  it('generates unique verifiers', () => {
    const verifiers = new Set(Array.from({ length: 50 }, () => generateCodeVerifier()));
    expect(verifiers.size).toBe(50);
  });
});

describe('generateCodeChallenge', () => {
  it('returns a base64url string', () => {
    const challenge = generateCodeChallenge('test-verifier');
    expect(challenge).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  it('is deterministic', () => {
    const v = generateCodeVerifier();
    expect(generateCodeChallenge(v)).toBe(generateCodeChallenge(v));
  });

  it('matches known S256 vector', () => {
    // RFC 7636 Appendix B
    // verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    // challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const expected = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
    expect(generateCodeChallenge(verifier)).toBe(expected);
  });
});

describe('validateCodeVerifier', () => {
  it('returns true for a valid verifier/challenge pair', () => {
    const verifier = generateCodeVerifier();
    const challenge = generateCodeChallenge(verifier);
    expect(validateCodeVerifier(verifier, challenge)).toBe(true);
  });

  it('returns false for a wrong verifier', () => {
    const verifier = generateCodeVerifier();
    const challenge = generateCodeChallenge(verifier);
    const wrongVerifier = generateCodeVerifier();
    expect(validateCodeVerifier(wrongVerifier, challenge)).toBe(false);
  });

  it('returns false for a verifier that is too short', () => {
    const challenge = generateCodeChallenge('short');
    expect(validateCodeVerifier('short', challenge)).toBe(false);
  });

  it('returns false for a verifier that is too long', () => {
    const longVerifier = 'a'.repeat(129);
    const challenge = generateCodeChallenge(longVerifier);
    expect(validateCodeVerifier(longVerifier, challenge)).toBe(false);
  });
});
