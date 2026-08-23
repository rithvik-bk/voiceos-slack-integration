/**
 * Scaffold tests for the engine's public boundary.
 *
 * These are placeholders in the sense that the engine is not built yet — they are NOT
 * placeholders in the sense of proving nothing. Each one pins a decision that would
 * otherwise be re-litigated or silently broken later:
 *
 *  - the three verbs exist, with those names, at that path
 *  - a stub FAILS LOUDLY rather than returning a fake success (the one behaviour that
 *    would be catastrophic to inherit: "connected" claimed by a function that did nothing)
 *  - the frozen ConnectStatus contract and copy-deck error codes are in the type surface
 *  - no engine error message can carry a credential
 */

import { describe, expect, it } from 'vitest';

import {
  EngineError,
  connect,
  disconnect,
  getConnectStatus,
  getToken,
  registerProvider,
  renderPage,
} from '../src/index.ts';
import type { ConnectErrorCode, ConnectStatus, ProviderProfile } from '../src/index.ts';

const PROFILE: ProviderProfile = {
  name: 'fixture',
  display_name: 'Fixture',
  authorize_url: 'https://example.com/oauth/authorize',
  token_url: 'https://example.com/api/oauth.access',
  client_id: '',
  client_type: 'public',
  pkce: 'S256',
  redirect_strategy: 'loopback',
  redirect_host: 'localhost',
  redirect_ports: [33418, 33419, 33420],
  scopes: ['read'],
  scope_param: 'scope',
  token_auth: 'none',
  refresh_auth: 'unknown',
  token_path: 'access_token',
  refresh: 'rotation',
  rotation: 'optional-enabled',
  identity_probe: { url: 'https://example.com/api/me', handle_path: 'user' },
};

describe('public API surface', () => {
  it('exposes exactly the three verbs plus the status poll', () => {
    expect(typeof connect).toBe('function');
    expect(typeof getToken).toBe('function');
    expect(typeof disconnect).toBe('function');
    expect(typeof getConnectStatus).toBe('function');
  });

  /**
   * This case was written against the Phase-0 stubs, where the whole point was that a stub
   * must FAIL rather than fake a success. The engine is implemented now, so the assertion
   * moves to the version of that rule that still bites: a verb with nothing behind it
   * returns a typed refusal, never a plausible-looking success. `connect()` is exercised
   * end-to-end in engine/test/connect-flow.test.ts, where it can be driven without opening
   * a real browser.
   */
  it('refuses, with a typed code, rather than faking a result', async () => {
    // Lazy thunks, not live promises: a promise that rejects before a handler is attached
    // is an unhandled rejection, and a test suite that emits those is a test suite people
    // learn to ignore.
    const calls: Array<[string, () => Promise<unknown>, string]> = [
      ['getToken', () => getToken('fixture-not-a-provider'), 'config_invalid'],
      ['getConnectStatus', () => getConnectStatus('c_never_minted'), 'not_connected'],
    ];

    for (const [name, call, code] of calls) {
      await expect(call(), `${name}() must reject`).rejects.toBeInstanceOf(EngineError);
      await expect(call()).rejects.toMatchObject({ code });
    }

    // …and the one verb that is idempotent by contract stays idempotent: a user who says
    // "forget my Slack" gets it forgotten, not an error about never having connected.
    await expect(disconnect('fixture-never-connected')).resolves.toBeUndefined();
  });

  it('never lets a credential reach an error string', async () => {
    const secret = 'xoxp-do-not-log-me';
    registerProvider({ ...PROFILE, client_id: secret });
    const error = await getToken(PROFILE.name).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(EngineError);
    const serialized = `${(error as EngineError).message} ${(error as EngineError).hint} ${(error as EngineError).stack ?? ''}`;
    expect(serialized).not.toContain(secret);
  });
});

describe('frozen product-surface contract', () => {
  it('carries every copy-deck error code', () => {
    // Compile-time exhaustiveness: adding a code to the union without adding it here
    // fails the typecheck, and dropping one fails this assertion.
    const codes: Record<ConnectErrorCode, true> = {
      denied_by_user: true,
      port_blocked: true,
      expired_or_revoked: true,
      state_mismatch: true,
      timeout: true,
      provider_error: true,
    };
    expect(Object.keys(codes).sort()).toEqual([
      'denied_by_user',
      'expired_or_revoked',
      'port_blocked',
      'provider_error',
      'state_mismatch',
      'timeout',
    ]);
  });

  it('models a connected status the way the demo speaks it', () => {
    const status: ConnectStatus = {
      phase: 'connected',
      connect_id: 'c_1',
      provider: 'slack',
      spoken: 'Connected as Rithvik in Bison HQ.',
      identity: { handle: 'Rithvik', workspace: 'Bison HQ' },
    };
    expect(status.phase).toBe('connected');
    expect(status.identity?.workspace).toBe('Bison HQ');
  });
});

describe('branded callback pages are reachable from the public API', () => {
  it('renders a self-contained page with no external requests', () => {
    const html = renderPage('success', { provider: 'Slack' });
    expect(html).toContain('Slack is connected.');
    expect(html).not.toMatch(/https?:\/\//);
  });

  /**
   * The copy deck shipped with two error codes that had a branded page but no spoken
   * line, and one (`provider_error`) routed at `mismatch.html`, whose words are
   * state-mismatch words — so a `pkce_not_allowed` would have put "that response didn't
   * match the request" on the projector. This map is the fix, and it is exhaustive by
   * type: adding a ConnectErrorCode without deciding its screen fails the typecheck.
   */
  const SCREEN: Record<ConnectErrorCode, 'denied' | 'mismatch' | 'timeout' | 'provider_error' | null> = {
    denied_by_user: 'denied',
    state_mismatch: 'mismatch',
    timeout: 'timeout',
    provider_error: 'provider_error',
    port_blocked: null, // no browser tab exists — the listener never bound
    expired_or_revoked: null, // the provider's own consent page is what the user sees
  };

  it('gives every error code its own words, and never borrows another state\'s', () => {
    for (const [code, state] of Object.entries(SCREEN)) {
      if (state === null) continue;
      const html = renderPage(state, { provider: 'Slack', providerMessage: `${code}: provider said so` });
      expect(html, `${code} page must render`).toContain('VoiceOS');
      expect(html).toContain(`${code}: provider said so`);
    }
    // The specific confusion that was live: these two pages must not share copy.
    expect(renderPage('mismatch')).not.toEqual(renderPage('provider_error'));
    expect(renderPage('provider_error', { provider: 'Slack' })).toContain('Slack turned that down.');
  });

  it('never renders a code, state or token into a page', () => {
    const html = renderPage('provider_error', {
      provider: '<img src=x onerror=alert(1)>',
      providerMessage: 'code=4/abc state=xyz',
    });
    expect(html).not.toContain('<img');
    expect(html).toContain('&lt;img');
  });
});
