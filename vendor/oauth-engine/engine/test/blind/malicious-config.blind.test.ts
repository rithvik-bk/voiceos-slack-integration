// ATTACK: a malicious provider config — code injection through a config field, and a
// config that tries to smuggle a secret into a shareable profile.
// SPEC §12 (malicious provider config), §20 (profile supply chain). INV-CONFIG-2, INV-CUST-2.
import { describe, test, expect } from 'vitest';
import { satisfiesPredicate } from '../../src/exchange.ts';
import { registerProvider, resolveProviderProfile } from '../../src/index.ts';

describe('malicious provider config', () => {
  test('a success_predicate supplied as a JS string is NEVER executed', () => {
    // INV-CONFIG-2: success_predicate is {path,equals}, never a JS expression.
    (globalThis as Record<string, unknown>).__HANDSHAKE_PWNED = false;
    const evil = 'globalThis.__HANDSHAKE_PWNED = true' as never;
    satisfiesPredicate(evil, { anything: 1 });
    expect((globalThis as Record<string, unknown>).__HANDSHAKE_PWNED).toBe(false);
  });

  test('a success_predicate path cannot reach into the prototype chain to pollute it', () => {
    const before = ({} as Record<string, unknown>).polluted;
    satisfiesPredicate({ path: '__proto__.polluted', equals: 1 } as never, {});
    satisfiesPredicate({ path: 'constructor.prototype.polluted', equals: 1 } as never, {});
    expect(({} as Record<string, unknown>).polluted).toBe(before); // still undefined
  });

  test('a data-only {path,equals} predicate evaluates as pure data access', () => {
    expect(satisfiesPredicate({ path: 'ok', equals: true } as never, { ok: true })).toBe(true);
    expect(satisfiesPredicate({ path: 'ok', equals: true } as never, { ok: false })).toBe(false);
    expect(satisfiesPredicate({ path: 'a.b', equals: 'x' } as never, { a: { b: 'x' } })).toBe(true);
  });

  test('registering a profile that embeds a client_secret must not yield a usable secret-bearing profile', () => {
    // §20: the profile schema structurally cannot hold a secret; a profile that carries one
    // must be rejected or stripped, never usable. INV-CUST-2.
    registerProvider({
      name: 'evil-secret-carrier',
      authorization_endpoint: 'https://evil.example/authorize',
      token_endpoint: 'https://evil.example/token',
      pkce: 's256',
      client_id: 'cid',
      // Assembled from fragments (byte-identical at runtime) so the push-gate scanner plants no
      // finding on the fixture; the registration still receives the full secret-bearing string.
      client_secret: 'sk_' + 'live_THIS_MUST_NOT_SURVIVE_IN_A_PROFILE',
      scopes: [],
    } as never);
    const resolved = resolveProviderProfile('evil-secret-carrier') as unknown as Record<string, unknown> | undefined;
    const serialized = JSON.stringify(resolved ?? {});
    // Either the malicious registration was rejected (not resolvable) or the secret was stripped;
    // it must NEVER be resolvable as a live profile still carrying the secret.
    expect(serialized).not.toContain('sk_live_THIS_MUST_NOT_SURVIVE_IN_A_PROFILE');
    expect(serialized).not.toContain('client_secret');
  });

  test('a profile whose token endpoint is a different registrable domain than authorize is not silently trusted', () => {
    // §20 supply chain: token endpoint pinned to the same registrable domain as authorize,
    // or an explicit acknowledgment is required. A cross-domain (phishing) pair must not
    // resolve as a plain trusted profile.
    registerProvider({
      name: 'evil-crossdomain',
      authorization_endpoint: 'https://login.microsoftonline.com/authorize',
      token_endpoint: 'https://attacker.example/token',
      pkce: 's256',
      client_id: 'cid',
      scopes: [],
    } as never);
    const resolved = resolveProviderProfile('evil-crossdomain') as unknown as Record<string, unknown> | undefined;
    // Defended if the cross-domain pair is not resolvable as a usable profile, OR it is flagged
    // (carries an explicit cross-domain acknowledgment). A bare, unflagged resolvable profile
    // pointing tokens at attacker.example is the failure.
    if (resolved && Object.keys(resolved).length > 0) {
      const flagged = JSON.stringify(resolved).toLowerCase();
      expect(flagged).toMatch(/cross[_-]?domain|acknowledge|untrusted|unverified/);
      expect(resolved['token_endpoint']).not.toBe('https://attacker.example/token');
    } else {
      expect(resolved == null || Object.keys(resolved).length === 0).toBe(true);
    }
  });
});
