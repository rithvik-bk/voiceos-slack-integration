// ATTACK: PKCE downgrade to `plain`, and leakage of the verifier.
// SPEC §12 (PKCE downgrade; code interception). INV-PKCE-1/2.
import { describe, test, expect } from 'vitest';
import { generatePkce, codeChallenge, PKCE_METHOD } from '../../src/pkce.ts';
import { createHash } from 'node:crypto';

const s256 = (v: string) => createHash('sha256').update(v).digest('base64url');

describe('PKCE downgrade', () => {
  test('the engine advertises S256, never plain', () => {
    expect(PKCE_METHOD).toBe('S256');            // INV-PKCE-1
    expect(generatePkce().method).toBe('S256');
  });

  test('the challenge is the S256 hash of the verifier, NOT the raw verifier (plain downgrade)', () => {
    const { verifier, challenge } = generatePkce();
    // A `plain` downgrade would ship challenge === verifier. That must never happen.
    expect(challenge).not.toBe(verifier);        // INV-PKCE-1: plain is refused
    expect(challenge).toBe(s256(verifier));      // it is genuinely S256
  });

  test('codeChallenge() is a real S256 transform (an attacker cannot pass a plain verifier through)', () => {
    const verifier = 'attacker-controlled-verifier-1234567890-abcdefghijklmnop';
    const c = codeChallenge(verifier);
    expect(c).toBe(s256(verifier));
    expect(c).not.toBe(verifier);
  });

  test('the verifier and challenge are unlinkable without the hash (verifier confinement)', () => {
    // INV-PKCE-2: a stolen code is useless without the verifier. The challenge that
    // travels on the (interceptable) authorize URL must not reveal the verifier.
    const { verifier, challenge } = generatePkce();
    expect(challenge.includes(verifier)).toBe(false);
    expect(verifier.includes(challenge)).toBe(false);
    expect(verifier.length).toBeGreaterThanOrEqual(43); // >=32 bytes base64url
  });

  test('verifiers are unique per flow (no fixed/predictable verifier)', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const { verifier } = generatePkce();
      expect(seen.has(verifier)).toBe(false);
      seen.add(verifier);
    }
  });
});
