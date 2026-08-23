// ATTACK: multi-account confusion — one account's request resolving to another's
// credential, a display-name-derived identity, or a silent pick when ambiguous.
// SPEC §11 (multi-account & tenancy). INV-IDENT-2.
import { describe, test, expect } from 'vitest';
import { deriveAccountId, accountKey, AccountAmbiguousError } from '../../src/account.ts';

describe('multi-account confusion', () => {
  test('the account id derives from identity, not from a mutable display name', () => {
    // INV-IDENT-2: a stable identifier from the identity probe, not a display name.
    const id = deriveAccountId({ sub: 'U123', handle: 'Alice' } as never);
    expect(id).not.toBe('Alice');
    expect(id).not.toBe('U123');
    expect(typeof id).toBe('string');
    expect(id.length).toBeGreaterThanOrEqual(8);
  });

  test('two accounts with the same handle but different subjects must not collapse to one id', () => {
    // §11 motivating case: two Slack workspaces, or a personal + work Gmail, can carry the
    // same handle. The account id must incorporate the immutable subject so they stay
    // distinct; if it keys only on the (mutable, reusable) handle they share one vault key.
    const a1 = deriveAccountId({ sub: 'U1', handle: 'same-handle' } as never);
    const a2 = deriveAccountId({ sub: 'U1', handle: 'same-handle' } as never);
    const b = deriveAccountId({ sub: 'U2', handle: 'same-handle' } as never);
    expect(a1).toBe(a2);        // stable for one account (defended)
    expect(a1).not.toBe(b);     // two different subjects sharing a handle must NOT merge
  });

  test('distinct derived ids yield distinct vault keys, and a malformed id is refused', () => {
    // A key collision would let one account read another's stored token.
    const idA = deriveAccountId({ handle: 'workspace-alpha' } as never);
    const idB = deriveAccountId({ handle: 'workspace-beta' } as never);
    expect(accountKey('slack', idA)).not.toBe(accountKey('slack', idB));
    // account ids must be well-formed; empty or illegal-character ids are rejected
    expect(() => accountKey('slack', '')).toThrow();
    expect(() => accountKey('slack', 'ACCT-with-BAD-chars!')).toThrow();
  });

  test('the vault key namespaces by provider (no cross-provider read of the same account)', () => {
    const id = deriveAccountId({ handle: 'shared-handle' } as never);
    expect(accountKey('slack', id)).not.toBe(accountKey('notion', id));
  });

  test('an ambiguous account resolution is a typed, catchable error — never a silent pick', () => {
    // INV-IDENT-2: disambiguate rather than silently pick when an account is ambiguous.
    const err = new AccountAmbiguousError('slack', ['acct-A', 'acct-B'] as never);
    expect(err).toBeInstanceOf(Error);
    expect(String(err.message).length).toBeGreaterThan(0);
    // the error must name the provider so the caller can prompt for which account
    expect(JSON.stringify({ m: err.message, ...err }).toLowerCase()).toContain('slack');
  });
});
