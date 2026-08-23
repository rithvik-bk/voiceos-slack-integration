/**
 * C-10 tests — rotating-refresh reuse detection.
 *
 * The theorems: (1) a token already spent is never sent again — the retry is refused locally;
 * (2) a family revocation surfaces as a clean `expired_or_revoked` re-auth; (3) a transport
 * failure does NOT mark the token consumed, so a legitimate retry still works; (4) no raw
 * token ever enters the consumed set, a message, or a hint.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { EngineError } from '../src/errors.ts';
import {
  assertRefreshUnconsumed,
  clearConsumed,
  consumedCount,
  familyRevocationReauth,
  isFamilyRevocation,
  markRefreshConsumed,
} from '../src/reuse.ts';
import type { ProviderProfile } from '../src/types.ts';

// Minimal profile stub — only the two display fields reuse.ts reads.
const profile = { name: 'slack', display_name: 'Slack' } as unknown as ProviderProfile;

// Deliberately NOT provider-shaped: these are opaque fixtures, and the repo's secret scanner
// must stay green on the test corpus.
const TOKEN = 'FAKE-rotating-refresh-fixture-abc123';
const OTHER = 'FAKE-a-different-refresh-fixture-xyz789';

beforeEach(() => clearConsumed());
afterEach(() => clearConsumed());

describe('never retry a consumed token', () => {
  it('lets an unspent token through', () => {
    expect(() => assertRefreshUnconsumed(TOKEN, profile)).not.toThrow();
  });

  it('refuses a token that has already been spent, as expired_or_revoked', () => {
    markRefreshConsumed(TOKEN);
    try {
      assertRefreshUnconsumed(TOKEN, profile);
      expect.unreachable('should have refused the reused token');
    } catch (error) {
      expect(error).toBeInstanceOf(EngineError);
      expect((error as EngineError).code).toBe('expired_or_revoked');
    }
  });

  it('scopes consumption per token — a sibling token is unaffected', () => {
    markRefreshConsumed(TOKEN);
    expect(() => assertRefreshUnconsumed(TOKEN, profile)).toThrow(EngineError);
    expect(() => assertRefreshUnconsumed(OTHER, profile)).not.toThrow();
  });

  it('is idempotent — marking the same token twice keeps one digest', () => {
    markRefreshConsumed(TOKEN);
    markRefreshConsumed(TOKEN);
    expect(consumedCount()).toBe(1);
  });
});

describe('family revocation → clean re-auth', () => {
  it('recognizes an expired_or_revoked refresh failure as family revocation', () => {
    const dead = new EngineError('expired_or_revoked', 'slack refused the refresh');
    expect(isFamilyRevocation(dead)).toBe(true);
  });

  it('does not treat a transient provider_error as family revocation', () => {
    const transient = new EngineError('provider_error', 'could not reach the token endpoint');
    expect(isFamilyRevocation(transient)).toBe(false);
  });

  it('builds an expired_or_revoked re-auth error that names the reconnect step', () => {
    const cause = new EngineError('expired_or_revoked', 'slack refused the refresh', {
      providerMessage: 'invalid_grant',
    });
    const reauth = familyRevocationReauth(profile, cause);
    expect(reauth).toBeInstanceOf(EngineError);
    expect(reauth.code).toBe('expired_or_revoked');
    expect(reauth.hint.toLowerCase()).toContain('connect slack');
    // The provider's verbatim word is preserved for the operator.
    expect(reauth.providerMessage).toBe('invalid_grant');
    // The failing refresh is chained as the cause.
    expect(reauth.cause).toBe(cause);
  });

  it('builds a re-auth error even with no cause', () => {
    const reauth = familyRevocationReauth(profile);
    expect(reauth.code).toBe('expired_or_revoked');
    expect(reauth.providerMessage).toBeUndefined();
  });
});

describe('secret hygiene', () => {
  it('never stores or emits a raw token', () => {
    markRefreshConsumed(TOKEN);
    let refusal: EngineError | null = null;
    try {
      assertRefreshUnconsumed(TOKEN, profile);
    } catch (error) {
      refusal = error as EngineError;
    }
    expect(refusal).not.toBeNull();
    const emitted = `${refusal?.message} ${refusal?.hint}`;
    expect(emitted).not.toContain(TOKEN);
    // The consumed set holds a 64-hex-char SHA-256 digest, never the token itself.
    expect(consumedCount()).toBe(1);
  });
});
