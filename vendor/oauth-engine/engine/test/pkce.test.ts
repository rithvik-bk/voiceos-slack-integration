/**
 * PKCE tests.
 *
 * The load-bearing one is the RFC 7636 Appendix-B vector: it is the only assertion here
 * that can tell "we hash the verifier STRING" apart from "we hash the random bytes",
 * and that distinction is invisible to any round-trip test we could write ourselves.
 */

import { describe, expect, it } from 'vitest';

import { PKCE_METHOD, codeChallenge, generatePkce } from '../src/pkce.ts';

/** RFC 7636 Appendix B, verbatim. */
const RFC_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const RFC_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

const BASE64URL_43 = /^[A-Za-z0-9_-]{43}$/;

describe('pkce', () => {
  it('reproduces the RFC 7636 Appendix-B S256 vector', () => {
    expect(codeChallenge(RFC_VERIFIER)).toBe(RFC_CHALLENGE);
  });

  it('announces S256 and nothing else', () => {
    expect(generatePkce().method).toBe('S256');
    expect(PKCE_METHOD).toBe('S256');
  });

  it('emits base64url with no padding and no URL-unsafe characters', () => {
    for (let i = 0; i < 200; i += 1) {
      const { verifier, challenge } = generatePkce();
      // 43 chars = the RFC's minimum verifier length and the fixed SHA-256 digest length.
      expect(verifier).toMatch(BASE64URL_43);
      expect(challenge).toMatch(BASE64URL_43);
      expect(verifier + challenge).not.toMatch(/[+/=]/);
    }
  });

  it('binds the challenge to its own verifier', () => {
    const a = generatePkce();
    const b = generatePkce();
    expect(codeChallenge(a.verifier)).toBe(a.challenge);
    expect(a.challenge).not.toBe(b.challenge);
  });

  it('draws fresh entropy every call', () => {
    // 1000 draws of 256 bits: a single collision here means the RNG is not an RNG.
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i += 1) seen.add(generatePkce().verifier);
    expect(seen.size).toBe(1000);

    // Cheap smoke test that the bytes are not structurally degenerate (all one char,
    // a counter, a timestamp): 1000 verifiers must cover most of the alphabet.
    const alphabet = new Set([...seen].join(''));
    expect(alphabet.size).toBeGreaterThan(50);
  });
});
