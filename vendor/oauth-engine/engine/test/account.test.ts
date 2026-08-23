/**
 * account tests — SPEC Part 4 §11 (multi-account and tenancy), closing C-13.
 *
 * The two load-bearing proofs the brief names:
 *   1. two accounts of ONE provider coexist (two Slack workspaces, personal + work Gmail);
 *   2. an ambiguous resolution is SURFACED to the caller, never silently picked.
 *
 * Everything here is deterministic and offline: the account layer is pure logic over an
 * identity the probe already resolved plus a stored index. No Keychain, no network.
 */

import { describe, expect, it } from 'vitest';

import {
  AccountAmbiguousError,
  accountKey,
  deriveAccountId,
  describeAccount,
  emptyIndex,
  parseIndex,
  removeAccount,
  resolveAccount,
  resolveAccountOrThrow,
  serializeIndex,
  setDefaultAccount,
  toAccountRef,
  upsertAccount,
  type AccountRef,
} from '../src/account.ts';
import { EngineError } from '../src/errors.ts';
import type { Identity } from '../src/identity.ts';

/* ─────────────────────────────── fixtures ─────────────────────────────── */

// Two Slack workspaces for one human: same handle, different opaque account id + workspace.
const hq: Identity = { handle: 'rithvik', workspace: 'VoiceOS HQ', accountId: 'T-HQ-001' };
const acme: Identity = { handle: 'rithvik', workspace: 'Acme Corp', accountId: 'T-ACME-9' };
// A personal vs work Gmail: distinct opaque ids, distinct handles.
const gPersonal: Identity = { handle: 'rithvik@gmail.com', accountId: '11122233' };
const gWork: Identity = { handle: 'r@acme.com', accountId: '99988877' };

/* ─────────────────────────────── deriveAccountId ─────────────────────────────── */

describe('deriveAccountId — stable, probe-derived, never the display name', () => {
  it('is stable: the same identity always derives the same id', () => {
    expect(deriveAccountId(hq)).toBe(deriveAccountId({ ...hq }));
  });

  it('is a key-safe fixed-width token', () => {
    const id = deriveAccountId(hq);
    expect(id).toMatch(/^[0-9a-f]{20}$/);
  });

  it('keys on the opaque account id, NOT on the mutable display handle/workspace', () => {
    // Rename the workspace and the handle; the opaque account id is unchanged → same id.
    const renamed: Identity = { handle: 'someone-else', workspace: 'Renamed Space', accountId: 'T-HQ-001' };
    expect(deriveAccountId(renamed)).toBe(deriveAccountId(hq));
  });

  it('separates two accounts that differ only by opaque account id', () => {
    expect(deriveAccountId(hq)).not.toBe(deriveAccountId(acme));
    expect(deriveAccountId(gPersonal)).not.toBe(deriveAccountId(gWork));
  });

  it('falls back to workspace+handle when the provider exposes no opaque id', () => {
    const a: Identity = { handle: 'rithvik', workspace: 'VoiceOS HQ' };
    const b: Identity = { handle: 'rithvik', workspace: 'Acme Corp' };
    expect(deriveAccountId(a)).not.toBe(deriveAccountId(b));
    // still stable
    expect(deriveAccountId(a)).toBe(deriveAccountId({ handle: 'rithvik', workspace: 'VoiceOS HQ' }));
  });

  it('does not confuse handle/workspace field boundaries', () => {
    // (handle="ab", ws="") must not collide with (handle="a", ws="b").
    const ab: Identity = { handle: 'ab' };
    const a_b: Identity = { handle: 'a', workspace: 'b' };
    expect(deriveAccountId(ab)).not.toBe(deriveAccountId(a_b));
  });

  it('throws when there is no handle to derive from', () => {
    expect(() => deriveAccountId({ handle: '' })).toThrow(EngineError);
  });
});

/* ─────────────────────────────── accountKey ─────────────────────────────── */

describe('accountKey — the vault key is (provider + account)', () => {
  it('composes a Keychain-legal key', () => {
    const key = accountKey('slack', deriveAccountId(hq));
    // Same charset the vault enforces for its service name.
    expect(key).toMatch(/^[a-z0-9][a-z0-9._-]*$/i);
  });

  it('is distinct per account and per provider', () => {
    const kHq = accountKey('slack', deriveAccountId(hq));
    const kAcme = accountKey('slack', deriveAccountId(acme));
    const kZoom = accountKey('zoom', deriveAccountId(hq));
    expect(new Set([kHq, kAcme, kZoom]).size).toBe(3);
  });

  it('rejects an account id that is not key-safe (forcing deriveAccountId usage)', () => {
    expect(() => accountKey('slack', 'rithvik@gmail.com')).toThrow(EngineError);
  });

  it('rejects an illegal provider name', () => {
    expect(() => accountKey('sl ack', deriveAccountId(hq))).toThrow(EngineError);
  });
});

/* ─────────────────────────────── index helpers ─────────────────────────────── */

describe('account index — the display-safe list the resolver reads', () => {
  it('upserts, dedupes by account id, and updates identity in place', () => {
    let idx = emptyIndex();
    idx = upsertAccount(idx, toAccountRef('slack', hq));
    idx = upsertAccount(idx, toAccountRef('slack', hq)); // same account again
    expect(idx.accounts).toHaveLength(1);

    // Re-upsert with a renamed workspace (same opaque id) updates the label, no duplicate.
    idx = upsertAccount(idx, toAccountRef('slack', { ...hq, workspace: 'HQ Renamed' }));
    expect(idx.accounts).toHaveLength(1);
    expect(idx.accounts[0]!.workspace).toBe('HQ Renamed');
  });

  it('removes an account and clears the default when it pointed at it', () => {
    let idx = emptyIndex();
    idx = upsertAccount(idx, toAccountRef('slack', hq));
    idx = upsertAccount(idx, toAccountRef('slack', acme));
    idx = setDefaultAccount(idx, deriveAccountId(hq));
    expect(idx.defaultAccountId).toBe(deriveAccountId(hq));

    idx = removeAccount(idx, deriveAccountId(hq));
    expect(idx.accounts).toHaveLength(1);
    expect(idx.defaultAccountId).toBeUndefined();
  });

  it('refuses to default to an account it does not hold', () => {
    let idx = emptyIndex();
    idx = upsertAccount(idx, toAccountRef('slack', hq));
    expect(() => setDefaultAccount(idx, 'deadbeefdeadbeefdead')).toThrow(EngineError);
  });

  it('round-trips through serialize/parse and survives junk', () => {
    let idx = emptyIndex();
    idx = upsertAccount(idx, toAccountRef('slack', hq));
    idx = upsertAccount(idx, toAccountRef('slack', acme));
    idx = setDefaultAccount(idx, deriveAccountId(acme));

    const round = parseIndex(serializeIndex(idx));
    expect(round.accounts).toHaveLength(2);
    expect(round.defaultAccountId).toBe(deriveAccountId(acme));

    // Corrupt / empty payloads never throw — they resolve to an empty index.
    expect(parseIndex('not json').accounts).toEqual([]);
    expect(parseIndex('').accounts).toEqual([]);
    expect(parseIndex('{"accounts":"nope"}').accounts).toEqual([]);
  });
});

/* ─────────────────────────────── resolveAccount ─────────────────────────────── */

function twoWorkspaces(withDefault?: 'hq' | 'acme') {
  let idx = emptyIndex();
  idx = upsertAccount(idx, toAccountRef('slack', hq));
  idx = upsertAccount(idx, toAccountRef('slack', acme));
  if (withDefault === 'hq') idx = setDefaultAccount(idx, deriveAccountId(hq));
  if (withDefault === 'acme') idx = setDefaultAccount(idx, deriveAccountId(acme));
  return idx;
}

describe('resolveAccount — the defined default rule', () => {
  it('rule 2: a single stored account resolves with no selector', () => {
    let idx = emptyIndex();
    idx = upsertAccount(idx, toAccountRef('slack', hq));
    const r = resolveAccount(idx);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.account.accountId).toBe(deriveAccountId(hq));
  });

  it('rule 1: an explicit selector wins and picks exactly one', () => {
    const idx = twoWorkspaces();
    const byWorkspace = resolveAccount(idx, 'Acme Corp');
    expect(byWorkspace.ok).toBe(true);
    if (byWorkspace.ok) expect(byWorkspace.account.accountId).toBe(deriveAccountId(acme));

    const byId = resolveAccount(idx, deriveAccountId(hq));
    expect(byId.ok).toBe(true);
    if (byId.ok) expect(byId.account.accountId).toBe(deriveAccountId(hq));
  });

  it('rule 3: with multiple accounts and no selector, an explicit default resolves', () => {
    const r = resolveAccount(twoWorkspaces('acme'));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.account.accountId).toBe(deriveAccountId(acme));
  });

  it('rule 4 (THE surfacing): multiple accounts, no selector, no default → ambiguous, candidates surfaced', () => {
    const r = resolveAccount(twoWorkspaces());
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe('ambiguous');
      expect(r.candidates.map((c) => c.accountId).sort()).toEqual(
        [deriveAccountId(hq), deriveAccountId(acme)].sort(),
      );
    }
  });

  it('a selector wins even when a default is set', () => {
    const r = resolveAccount(twoWorkspaces('hq'), 'Acme Corp');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.account.accountId).toBe(deriveAccountId(acme));
  });

  it('a stale default (pointing at a removed account) does not silently pick — it surfaces', () => {
    let idx = twoWorkspaces();
    idx = { ...idx, defaultAccountId: 'deadbeefdeadbeefdead' };
    const r = resolveAccount(idx);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe('ambiguous');
  });

  it('an ambiguous SELECTOR (shared handle across workspaces) surfaces both matches', () => {
    const idx = twoWorkspaces();
    // both hq and acme share handle 'rithvik'
    const r = resolveAccount(idx, 'rithvik');
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe('ambiguous');
      expect(r.candidates).toHaveLength(2);
    }
  });

  it('a selector matching nothing reports none and lists what IS available', () => {
    const idx = twoWorkspaces();
    const r = resolveAccount(idx, 'Nonexistent Space');
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe('none');
      expect(r.candidates).toHaveLength(2); // everything available, so the caller can choose
    }
  });

  it('zero accounts reports none with an empty candidate list', () => {
    const r = resolveAccount(emptyIndex());
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe('none');
      expect(r.candidates).toEqual([]);
    }
  });

  it('matches a "handle@workspace" compound selector', () => {
    const idx = twoWorkspaces();
    const r = resolveAccount(idx, 'rithvik@Acme Corp');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.account.accountId).toBe(deriveAccountId(acme));
  });

  it('selector matching is case- and whitespace-insensitive', () => {
    const idx = twoWorkspaces();
    const r = resolveAccount(idx, '  acme corp  ');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.account.accountId).toBe(deriveAccountId(acme));
  });

  it('an empty/whitespace selector is treated as no selector', () => {
    const single = upsertAccount(emptyIndex(), toAccountRef('slack', hq));
    const r = resolveAccount(single, '   ');
    expect(r.ok).toBe(true);
  });
});

/* ─────────────────────────────── resolveAccountOrThrow ─────────────────────────────── */

describe('resolveAccountOrThrow — surfacing via a typed throw', () => {
  it('throws AccountAmbiguousError carrying the candidates', () => {
    try {
      resolveAccountOrThrow('slack', twoWorkspaces());
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(AccountAmbiguousError);
      expect(err).toBeInstanceOf(EngineError);
      const e = err as AccountAmbiguousError;
      expect(e.candidates).toHaveLength(2);
      // The disambiguation is human-readable and secret-free.
      expect(e.hint).toContain('Acme Corp');
      expect(e.hint).toContain('VoiceOS HQ');
    }
  });

  it('throws not_connected when nothing is vaulted for the provider', () => {
    try {
      resolveAccountOrThrow('slack', emptyIndex());
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(EngineError);
      expect((err as EngineError).code).toBe('not_connected');
    }
  });

  it('throws not_connected naming the unmatched selector', () => {
    try {
      resolveAccountOrThrow('slack', twoWorkspaces(), 'Nonexistent Space');
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as EngineError).code).toBe('not_connected');
      expect((err as EngineError).message).toContain('Nonexistent Space');
    }
  });

  it('returns the ref on a clean resolution', () => {
    const ref = resolveAccountOrThrow('slack', twoWorkspaces(), 'VoiceOS HQ');
    expect(ref.accountId).toBe(deriveAccountId(hq));
  });
});

/* ─────────────────────────────── coexistence proof ───────────────────────────────
 * Two accounts of ONE provider, side by side, each with its OWN vaulted token, addressed
 * by (provider + account). Modeled with an in-memory store standing in for the Keychain:
 * the account layer's contract is exactly that these keys never collide and the resolver
 * routes each read to the right one.
 */

describe('two accounts of one provider coexist (C-13)', () => {
  it('stores and reads two Slack workspace tokens without collision', () => {
    const store = new Map<string, string>(); // accountKey → access_token (Keychain stand-in)

    // Connect workspace 1.
    const id1 = deriveAccountId(hq);
    store.set(accountKey('slack', id1), 'mock-HQ-token');
    // Connect workspace 2 (does NOT overwrite workspace 1).
    const id2 = deriveAccountId(acme);
    store.set(accountKey('slack', id2), 'mock-ACME-token');

    expect(store.size).toBe(2);

    let idx = emptyIndex();
    idx = upsertAccount(idx, toAccountRef('slack', hq));
    idx = upsertAccount(idx, toAccountRef('slack', acme));

    // getToken('slack', 'VoiceOS HQ') routes to the HQ token…
    const hqRef = resolveAccountOrThrow('slack', idx, 'VoiceOS HQ');
    expect(store.get(accountKey('slack', hqRef.accountId))).toBe('mock-HQ-token');
    // …and getToken('slack', 'Acme Corp') routes to the other, unchanged.
    const acmeRef = resolveAccountOrThrow('slack', idx, 'Acme Corp');
    expect(store.get(accountKey('slack', acmeRef.accountId))).toBe('mock-ACME-token');
  });

  it('bot-vs-user is two accounts, not a Slack branch (token_shape stays in the profile)', () => {
    // The profile's token_path/token_shape decides WHICH token comes out of the exchange
    // (authed_user.* vs top-level). The account layer only sees the resolved identities and
    // treats them as two coexisting accounts — with zero provider-specific code here.
    const userIdentity: Identity = { handle: 'rithvik', workspace: 'VoiceOS HQ', accountId: 'U-USER-1' };
    const botIdentity: Identity = { handle: 'voiceos-bot', workspace: 'VoiceOS HQ', accountId: 'B-BOT-1' };
    let idx = emptyIndex();
    idx = upsertAccount(idx, toAccountRef('slack', userIdentity));
    idx = upsertAccount(idx, toAccountRef('slack', botIdentity));
    expect(idx.accounts).toHaveLength(2);
    expect(accountKey('slack', deriveAccountId(userIdentity))).not.toBe(
      accountKey('slack', deriveAccountId(botIdentity)),
    );
  });
});

/* ─────────────────────────────── describeAccount ─────────────────────────────── */

describe('describeAccount — display-safe label', () => {
  it('renders handle + workspace', () => {
    const ref: AccountRef = toAccountRef('slack', hq);
    const label = describeAccount(ref);
    expect(label).toContain('rithvik');
    expect(label).toContain('VoiceOS HQ');
  });

  it('renders handle alone when there is no workspace', () => {
    const ref: AccountRef = toAccountRef('google', gPersonal);
    expect(describeAccount(ref)).toContain('rithvik@gmail.com');
  });
});
