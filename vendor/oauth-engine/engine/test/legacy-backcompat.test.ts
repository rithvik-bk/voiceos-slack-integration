/**
 * Wave-3 — legacy vault back-compat + the single-flight lows the wave-2 audit found.
 *
 * getToken() already falls through to a pre-wave-2 "bare slot" record (a token written under the
 * bare provider key, before the account index existed). Two OTHER read sites did NOT, which the
 * audit caught:
 *
 *   (a) connect()'s already-connected short-circuit resolved ONLY through the account index, so a
 *       live legacy credential was invisible → the user was pushed through a full re-consent for a
 *       connection they already held.
 *   (a) scopedProfile's granted-scope read had the same blind spot, so a step-up re-consent unioned
 *       against an EMPTY granted set and silently dropped the legacy token's already-granted scopes.
 *
 * And the single-flight slot keyed off the raw `options.account` selector STRING rather than the
 * RESOLVED account id, so two spellings of the same account (id vs handle) landed on two slots and
 * did not supersede each other (SPEC §14).
 *
 * These drive the REAL engine against the mock AS, exactly like connect-flow.test.ts. The device
 * grant's single-flight wiring (grant path 3) is proven in device.test.ts.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { connect, disconnect } from '../src/index.ts';
import type { ProviderProfile } from '../src/index.ts';
import { deriveAccountId } from '../src/account.ts';
import { clearFlows, live, pending } from '../src/singleflight.ts';
import { putToken, readAccountIndex } from '../src/vault.ts';
import { setPlatformHooks, resetPlatformHooks, getConnectStatus } from '../src/index.ts';
import type { ConnectStatus } from '../src/index.ts';
import { startMockAs, MOCK_IDENTITY } from './mock-as.ts';
import type { MockAs } from './mock-as.ts';

const SCRATCH = 'test-e2e-legacy-backcompat';

/** The stable account id the mock identity derives to. */
const MOCK_ACCOUNT_ID = deriveAccountId(MOCK_IDENTITY);

let mock: MockAs;
let opened: string[];

function profileFor(as: MockAs): ProviderProfile {
  return {
    name: SCRATCH,
    display_name: 'Slack',
    client_id: 'mock.client.id',
    client_type: 'public',
    pkce: 'S256',
    redirect_strategy: 'loopback',
    redirect_host: 'localhost',
    redirect_ports: [33418, 33419, 33420],
    authorize_url: as.authorizeUrl,
    token_url: as.tokenUrl,
    scopes: ['channels:read', 'channels:history', 'users:read'],
    scope_param: 'user_scope',
    scope_delimiter: ',',
    extra_authorize_params: { scope: '' },
    token_auth: 'none',
    refresh_auth: 'client_id_body',
    token_path: 'authed_user.access_token',
    refresh_token_path: 'authed_user.refresh_token',
    expires_in_path: 'authed_user.expires_in',
    success_predicate: { path: 'ok', equals: true },
    refresh: 'rotation',
    rotation: 'optional-enabled',
    access_token_ttl: 43_200,
    identity_probe: {
      url: as.identityUrl,
      method: 'POST',
      auth: 'bearer',
      success_predicate: { path: 'ok', equals: true },
      handle_path: 'user',
      workspace_path: 'team',
      account_id_path: 'user_id',
    },
  };
}

/** The scripted browser: what Safari does after Allow, so a lingering flow can be freed cleanly. */
async function browserRedirect(authorizeUrl: string, outcome: 'allow' | 'deny'): Promise<void> {
  const url = new URL(authorizeUrl);
  const callback = new URL(url.searchParams.get('redirect_uri') as string);
  const state = url.searchParams.get('state') as string;
  if (outcome === 'allow') {
    callback.searchParams.set('code', 'mock-auth-code');
  } else {
    callback.searchParams.set('error', 'access_denied');
  }
  callback.searchParams.set('state', state);
  await fetch(callback.toString());
}

async function waitForPhase(connectId: string, phases: string[], ms = 5000): Promise<ConnectStatus> {
  const deadline = Date.now() + ms;
  for (;;) {
    const status = await getConnectStatus(connectId);
    if (phases.includes(status.phase)) return status;
    if (Date.now() > deadline) throw new Error(`stuck in phase ${status.phase}`);
    await new Promise((r) => setTimeout(r, 15));
  }
}

/** Scopes the authorize URL carried (Slack's list rides `user_scope`, comma-delimited). */
function scopesOf(authorizeUrl: string): string[] {
  const raw = new URL(authorizeUrl).searchParams.get('user_scope') ?? '';
  return raw.split(',').filter((s) => s.length > 0);
}

beforeEach(async () => {
  mock = await startMockAs({ mode: 'slack' });
  opened = [];
  setPlatformHooks({
    openUrl: async (u) => {
      opened.push(u);
    },
    activateApp: async () => {},
  });
  clearFlows();
  await disconnect(SCRATCH).catch(() => undefined);
});

afterEach(async () => {
  clearFlows();
  resetPlatformHooks();
  await disconnect(SCRATCH).catch(() => undefined);
  await mock.close();
});

describe('legacy bare-slot back-compat (a)', () => {
  it('connect() short-circuits on a live legacy bare-slot record — no forced re-consent', async () => {
    // A pre-wave-2 credential: a token under the BARE provider key, with NO account index. This is
    // exactly what an install that predates C-13 left on disk.
    await putToken(SCRATCH, {
      provider: SCRATCH,
      access_token: 'mock-legacy-access',
      refresh_token: 'mock-legacy-refresh',
      scopes: ['channels:read'],
      identity: { handle: 'LegacyUser', workspace: 'Legacy HQ' },
      obtained_at: Date.now(),
    });
    // Sanity: there really is no index — the fallback is the only way to see this record.
    expect((await readAccountIndex(SCRATCH)).accounts).toEqual([]);

    const status = await connect(profileFor(mock));

    // It answered from the vault instead of opening a browser: no re-consent for a live connection.
    expect(status.phase).toBe('connected');
    expect(status.spoken).toBe('Connected as LegacyUser in Legacy HQ.');
    expect(status.identity).toEqual({ handle: 'LegacyUser', workspace: 'Legacy HQ' });
    expect(opened).toHaveLength(0);
  });

  it('a legacy bare-slot record with no identity still falls through to a real consent', async () => {
    // No identity → not a proven connection. The short-circuit must NOT fire; a real flow starts.
    await putToken(SCRATCH, {
      provider: SCRATCH,
      access_token: 'mock-legacy-access',
      refresh_token: 'mock-legacy-refresh',
      scopes: ['channels:read'],
      obtained_at: Date.now(),
    });
    const status = await connect(profileFor(mock));
    expect(status.phase).toBe('launching-browser');
    expect(opened).toHaveLength(1);
    await browserRedirect(opened[0] as string, 'deny'); // free the listener
    await waitForPhase(status.connect_id, ['error']);
  });

  it("a step-up union preserves a legacy bare-slot record's granted scopes (§9)", async () => {
    // The legacy record was granted `files:read` — a scope NOT in the base profile, so it can only
    // reach the authorize URL if scopedProfile read the legacy granted set.
    await putToken(SCRATCH, {
      provider: SCRATCH,
      access_token: 'mock-legacy-access',
      refresh_token: 'mock-legacy-refresh',
      scopes: ['files:read'],
      identity: { handle: 'LegacyUser', workspace: 'Legacy HQ' },
      obtained_at: Date.now(),
    });

    // force skips the short-circuit; scopes triggers the step-up union.
    const status = await connect(profileFor(mock), { force: true, scopes: ['chat:write'] });
    expect(status.phase).toBe('launching-browser');
    const requested = scopesOf(opened[0] as string);

    expect(requested).toContain('chat:write'); // the newly requested scope
    expect(requested).toContain('files:read'); // the legacy-granted scope — preserved, not dropped
    expect(requested).toContain('channels:read'); // and the base set is still there

    await browserRedirect(opened[0] as string, 'deny'); // free the listener
    await waitForPhase(status.connect_id, ['error']);
  });
});

describe('single-flight slot keys off the resolved account id (c)', () => {
  it('two spellings of the same connected account share ONE slot and supersede each other', async () => {
    // Connect the account for real so the index maps MOCK_ACCOUNT_ID ↔ handle/workspace.
    const first = await connect(profileFor(mock));
    await browserRedirect(opened[0] as string, 'allow');
    await waitForPhase(first.connect_id, ['connected']);

    clearFlows(); // isolate the pending() count from the completed flow above

    // Two step-up connects naming the SAME account two different ways: its stable id, then its
    // handle. Both must resolve to MOCK_ACCOUNT_ID and occupy ONE slot, so the second supersedes
    // the first rather than racing it in a separate slot.
    const a = await connect(profileFor(mock), { force: true, account: MOCK_ACCOUNT_ID });
    expect(pending()).toBe(1);
    expect(live(SCRATCH, MOCK_ACCOUNT_ID)?.token.state).toBeTruthy();

    const b = await connect(profileFor(mock), { force: true, account: MOCK_IDENTITY.handle });
    // STILL one live flow: the handle resolved to the same account id and superseded the id-spelled
    // flow. With the raw-selector bug these were two slots and pending() would be 2.
    expect(pending()).toBe(1);
    expect(live(SCRATCH, MOCK_ACCOUNT_ID)).not.toBeNull();

    // The superseded flow (a) is refused; the live one (b) completes. This also frees b's listener.
    await browserRedirect(opened[opened.length - 1] as string, 'allow');
    await waitForPhase(b.connect_id, ['connected', 'error']).then((s) =>
      expect(s.phase).toBe('connected'),
    );
    const aFinal = await getConnectStatus(a.connect_id);
    expect(aFinal.phase).not.toBe('connected');
  });
});
