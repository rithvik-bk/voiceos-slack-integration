/**
 * PKCE — RFC 7636, S256 only (work item P1-I1).
 *
 * The one line of this file that is a *security* line rather than a plumbing line:
 * the challenge is SHA-256 over the ASCII octets of the verifier string itself
 * (RFC 7636 §4.2), NOT over the 32 random bytes we drew. Hashing the raw bytes
 * produces a challenge that is self-consistent, passes every local round-trip test,
 * and is rejected by every real authorization server — a failure that only shows up
 * on stage. `codeChallenge()` is exported so the RFC's Appendix-B vector can be run
 * against the exact function the engine uses, not a re-implementation in the test.
 *
 * `plain` is deliberately absent. Providers without PKCE (Reddit) carry
 * `pkce: 'none'` in their profile and are handled by named compensating controls;
 * downgrading to `method: 'plain'` would be worse than that, because it looks like
 * PKCE in the request and protects nothing.
 */

import { createHash, randomBytes } from 'node:crypto';

/** The only method this engine speaks. */
export const PKCE_METHOD = 'S256';

/**
 * 32 bytes → 43 base64url characters, the low end of RFC 7636 §4.1's 43..128 range
 * and 256 bits of entropy. The RFC's minimum length and our entropy floor coincide
 * here, so there is nothing to tune.
 */
const VERIFIER_BYTES = 32;

export interface Pkce {
  verifier: string;
  challenge: string;
  method: 'S256';
}

/**
 * S256 transform: BASE64URL(SHA256(ASCII(verifier))).
 *
 * base64url with no padding is the RFC's encoding; node's 'base64url' digest
 * encoding already strips `=` and uses `-`/`_`, so there is no post-processing
 * (a hand-rolled `.replace(/=/g,'')` chain is the classic place this breaks).
 */
export function codeChallenge(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

/** A fresh verifier/challenge pair. Never reuse one across two authorize requests. */
export function generatePkce(): Pkce {
  const verifier = randomBytes(VERIFIER_BYTES).toString('base64url');
  return { verifier, challenge: codeChallenge(verifier), method: 'S256' };
}
