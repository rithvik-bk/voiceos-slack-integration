// ATTACK: replaying a rotated (consumed) refresh token, and family-revocation handling.
// SPEC §8, §12 (refresh token replay). INV-REFRESH-3.
import { describe, test, expect, beforeEach } from 'vitest';
import {
  markRefreshConsumed,
  assertRefreshUnconsumed,
  isFamilyRevocation,
  familyRevocationReauth,
  clearConsumed,
} from '../../src/reuse.ts';

const profile = { name: 'slack' } as never;

describe('refresh token replay after rotation', () => {
  beforeEach(() => clearConsumed());

  test('a consumed (rotated-out) refresh token is refused on replay', () => {
    markRefreshConsumed('refresh-old');                     // provider rotated it away
    expect(() => assertRefreshUnconsumed('refresh-old', profile)).toThrow(); // INV-REFRESH-3
  });

  test('a fresh, never-used refresh token is allowed exactly once', () => {
    expect(() => assertRefreshUnconsumed('refresh-new', profile)).not.toThrow();
  });

  test('consumption is durable: a token stays refused across repeated replays', () => {
    markRefreshConsumed('rt');
    expect(() => assertRefreshUnconsumed('rt', profile)).toThrow();
    expect(() => assertRefreshUnconsumed('rt', profile)).toThrow(); // still refused
  });

  test('a family revocation is surfaced as a clean re-auth, not a cryptic failure', () => {
    // §8: replaying a consumed token may make the provider revoke the whole family.
    // The engine must recognize that and route the user to re-authorize. INV-REFRESH-3.
    const reauth = familyRevocationReauth(profile, { error: 'invalid_grant' });
    // A re-auth outcome names the recovery ("connect"/"re-authorize"), never a raw stack.
    const text = JSON.stringify(reauth).toLowerCase();
    expect(text).toMatch(/re-?auth|connect|revoked|expired/);
  });

  test('the family-revocation classifier is a total boolean function (no crash on hostile input)', () => {
    for (const bad of [null, undefined, 42, {}, { error: 'invalid_grant' }, 'x', { nested: { a: 1 } }]) {
      // isFamilyRevocation takes `unknown` by contract — every hostile input is a legal call.
      expect(typeof isFamilyRevocation(bad)).toBe('boolean');
    }
  });
});
