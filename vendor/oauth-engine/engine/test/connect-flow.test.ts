/**
 * P1-I7 — the whole dance, end to end, with nothing stubbed but the human.
 *
 * `connect()` composes six modules (pkce · state · loopback · exchange · identity · vault),
 * and the seams between them are where a demo dies. So this suite drives the REAL engine
 * against the mock AS and a scripted "browser" — a `fetch` to the loopback callback,
 * exactly what Safari does after Allow — and asserts the things the run-of-show depends on:
 *
 *   - connect() RETURNS while the human is still deciding (D4: 60s tool timeout, 30s gate)
 *   - the token lands in the KEYCHAIN, not a file
 *   - `connected` is only ever produced by the identity probe (copy deck)
 *   - Cancel produces the branded denied page and the deck's denial line (D8, the beat that
 *     is deliberately performed on stage)
 *   - the authorize URL and the token exchange carry the SAME redirect_uri, byte for byte
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  EngineError,
  connect,
  disconnect,
  getConnectStatus,
  getToken,
  registerProvider,
  resetPlatformHooks,
  setPlatformHooks,
} from '../src/index.ts';
import type { ConnectStatus, ProviderProfile } from '../src/index.ts';
import { REDIRECT_URIS } from '../src/config.ts';
import { deriveAccountId } from '../src/account.ts';
import { readAccountIndex, readToken } from '../src/vault.ts';
import { startMockAs, MOCK_IDENTITY } from './mock-as.ts';
import type { MockAs } from './mock-as.ts';

const SCRATCH = 'test-e2e-scratch-connect';

/** The stable account id the mock identity derives to — the key the token is vaulted under. */
const MOCK_ACCOUNT_ID = deriveAccountId(MOCK_IDENTITY);

let mock: MockAs;
/** Every URL the engine tried to hand to a browser, in order. */
let opened: string[];
let activated: number;

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

/** The scripted browser: what Safari does after the user clicks Allow (or Cancel). */
async function browserRedirect(authorizeUrl: string, outcome: 'allow' | 'deny'): Promise<string> {
  const url = new URL(authorizeUrl);
  const redirectUri = url.searchParams.get('redirect_uri') as string;
  const state = url.searchParams.get('state') as string;
  const callback = new URL(redirectUri);
  if (outcome === 'allow') {
    callback.searchParams.set('code', 'mock-auth-code');
    callback.searchParams.set('state', state);
  } else {
    callback.searchParams.set('error', 'access_denied');
    callback.searchParams.set('state', state);
  }
  const page = await fetch(callback.toString());
  return page.text();
}

/** Poll the status board the way the integration's `auth_status` tool does. */
async function waitForPhase(connectId: string, phases: string[], ms = 5000): Promise<ConnectStatus> {
  const deadline = Date.now() + ms;
  for (;;) {
    const status = await getConnectStatus(connectId);
    if (phases.includes(status.phase)) return status;
    if (Date.now() > deadline) throw new Error(`stuck in phase ${status.phase}`);
    await new Promise((resolve) => setTimeout(resolve, 15));
  }
}

beforeEach(async () => {
  mock = await startMockAs({ mode: 'slack' });
  opened = [];
  activated = 0;
  setPlatformHooks({
    openUrl: async (url) => {
      opened.push(url);
    },
    activateApp: async () => {
      activated += 1;
    },
  });
  await disconnect(SCRATCH).catch(() => undefined);
});

afterEach(async () => {
  resetPlatformHooks();
  await disconnect(SCRATCH).catch(() => undefined);
  await mock.close();
});

describe('connect() — the 60-second run of show', () => {
  it('returns while the human is still deciding, then completes out of band', async () => {
    const profile = profileFor(mock);
    const seen: string[] = [];

    const started = Date.now();
    const first = await connect(profile, { onStatus: (s) => seen.push(s.phase) });
    const elapsed = Date.now() - started;

    // D4: their client gives a tool 60s and a connect gate of 30s. This returns in ms.
    expect(first.phase).toBe('launching-browser');
    expect(first.spoken).toBe('Opening Slack in your browser.');
    expect(elapsed).toBeLessThan(2000);
    expect(opened).toHaveLength(1);

    // …and nothing is vaulted yet, because nobody has approved anything.
    expect(await readToken(SCRATCH)).toBeNull();

    const page = await browserRedirect(opened[0] as string, 'allow');
    expect(page).toContain('Slack is connected.'); // the branded page on the projector

    const final = await waitForPhase(first.connect_id, ['connected', 'error']);
    expect(final.phase).toBe('connected');
    expect(final.spoken).toBe(`Connected as ${MOCK_IDENTITY.handle} in ${MOCK_IDENTITY.workspace}.`);
    expect(final.identity).toEqual({
      handle: MOCK_IDENTITY.handle,
      workspace: MOCK_IDENTITY.workspace,
    });
    expect(seen).toEqual(['launching-browser', 'awaiting-consent', 'exchanging', 'connected']);

    // The token is in the Keychain, keyed by (provider + account) — C-13. It is the USER
    // token, not Slack's bot token. The bare-provider key holds nothing: an account-aware
    // engine never writes the legacy single slot.
    expect(await readToken(SCRATCH)).toBeNull();
    const vaulted = await readToken(SCRATCH, MOCK_ACCOUNT_ID);
    expect(vaulted?.access_token).toBe(mock.current().access);
    expect(vaulted?.access_token).not.toBe('mock-bot-token-do-not-use');
    expect(vaulted?.refresh_token).toBe(mock.current().refresh);
    expect(vaulted?.identity?.workspace).toBe(MOCK_IDENTITY.workspace);
    expect(mock.violations).toEqual([]);

    // …and the account is registered in the index that routes getToken(provider, account?).
    const index = await readAccountIndex(SCRATCH);
    expect(index.accounts).toHaveLength(1);
    expect(index.accounts[0]?.accountId).toBe(MOCK_ACCOUNT_ID);

    // Design decision: the success page's "Open VoiceOS" button owns the return
    // trip; the engine never yanks focus automatically.
    expect(activated).toBe(0);
  });

  it('sends the SAME redirect_uri to the authorize URL and the token endpoint (§A8, D6)', async () => {
    const profile = profileFor(mock);
    const first = await connect(profile);
    const authorizeUri = new URL(opened[0] as string).searchParams.get('redirect_uri');

    await browserRedirect(opened[0] as string, 'allow');
    await waitForPhase(first.connect_id, ['connected', 'error']);

    const exchange = mock.requests.find((r) => r.grant === 'authorization_code');
    expect(exchange?.params.redirect_uri).toBe(authorizeUri);
    // And it is a ladder rung, spelled the one way config.ts spells it — asserted against
    // the sole source rather than against a second copy of the string in this file.
    expect(REDIRECT_URIS).toContain(authorizeUri);
  });

  it('builds an authorize URL with PKCE, state, and %20-free scope serialization', async () => {
    await connect(profileFor(mock));
    const url = new URL(opened[0] as string);

    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect((url.searchParams.get('code_challenge') ?? '').length).toBeGreaterThan(32);
    expect((url.searchParams.get('state') ?? '').length).toBeGreaterThan(20);
    // Slack's axes: user_scope carries the list, `scope` is present-and-empty [C-SL-03].
    expect(url.searchParams.get('user_scope')).toBe('channels:read,channels:history,users:read');
    expect(url.searchParams.get('scope')).toBe('');
    // Never `+` for a space — Zoom answers a `+`-serialized scope list with a 4700 [C-ZM-14].
    expect(opened[0]).not.toContain('+');
  });

  it('performs the deliberate Cancel beat: branded page, deck line, nothing stored (D8)', async () => {
    const profile = profileFor(mock);
    const first = await connect(profile);

    const page = await browserRedirect(opened[0] as string, 'deny');
    expect(page).toContain('Nothing was connected.');

    const final = await waitForPhase(first.connect_id, ['connected', 'error']);
    expect(final.phase).toBe('error');
    expect(final.error?.code).toBe('denied_by_user');
    expect(final.spoken).toBe(
      "You declined that one. Say 'connect Slack' whenever you want to retry.",
    );
    expect(await readToken(SCRATCH)).toBeNull();
    expect(mock.counts.exchange).toBe(0);

    // …and the retry immediately after works. That is the whole point of the beat.
    const second = await connect(profile);
    await browserRedirect(opened[1] as string, 'allow');
    const done = await waitForPhase(second.connect_id, ['connected', 'error']);
    expect(done.phase).toBe('connected');
  });

  it('never claims connected on a token endpoint 200 alone — the probe decides', async () => {
    const profile = profileFor(mock);
    // The exchange still returns HTTP 200 with ok:true and a perfectly good token — only
    // the identity probe can catch that we cannot actually prove who this token belongs to.
    const broken: ProviderProfile = {
      ...profile,
      identity_probe: { ...profile.identity_probe, url: `${mock.origin}/api/no-such-probe` },
    };
    const first = await connect(broken);
    await browserRedirect(opened[0] as string, 'allow');
    const final = await waitForPhase(first.connect_id, ['connected', 'error']);

    expect(mock.counts.exchange).toBe(1); // the exchange SUCCEEDED
    expect(final.phase).toBe('error'); // …and we still did not claim a connection
    expect(await readToken(SCRATCH)).toBeNull(); // nothing vaulted on an unverified token
  });

  it('times out without hanging the caller, and speaks the deck’s timeout line', async () => {
    const first = await connect(profileFor(mock), { timeoutMs: 120 });
    const final = await waitForPhase(first.connect_id, ['error']);

    expect(final.error?.code).toBe('timeout');
    expect(final.spoken).toBe(
      "I stopped waiting for that approval. Say 'connect Slack' when you're ready.",
    );
  });

  it('answers a second connect from the vault instead of re-consenting', async () => {
    const profile = profileFor(mock);
    const first = await connect(profile);
    await browserRedirect(opened[0] as string, 'allow');
    await waitForPhase(first.connect_id, ['connected']);

    const again = await connect(profile);
    expect(again.phase).toBe('connected');
    expect(opened).toHaveLength(1); // no second browser window
    expect(again.spoken).toBe(`Connected as ${MOCK_IDENTITY.handle} in ${MOCK_IDENTITY.workspace}.`);
  });
});

describe('getToken / disconnect — what an integration actually calls', () => {
  it('hands a live token to a tool that knows only the provider name', async () => {
    const profile = profileFor(mock);
    registerProvider(profile);

    const first = await connect(profile);
    await browserRedirect(opened[0] as string, 'allow');
    await waitForPhase(first.connect_id, ['connected']);

    await expect(getToken(SCRATCH)).resolves.toBe(mock.current().access);
    expect(mock.counts.refresh).toBe(0); // fresh: nothing to do
  });

  it('throws not_connected — never a fake token — when nothing is vaulted', async () => {
    registerProvider(profileFor(mock));
    const error = await getToken(SCRATCH).catch((e: unknown) => e as EngineError);
    expect(error).toBeInstanceOf(EngineError);
    expect((error as EngineError).code).toBe('not_connected');
  });

  it('disconnects idempotently and leaves nothing behind — token, account key, and index', async () => {
    const profile = profileFor(mock);
    const first = await connect(profile);
    await browserRedirect(opened[0] as string, 'allow');
    await waitForPhase(first.connect_id, ['connected']);

    await disconnect(SCRATCH);
    // Every trace is gone: the bare slot, the account-keyed token, and the routing index.
    expect(await readToken(SCRATCH)).toBeNull();
    expect(await readToken(SCRATCH, MOCK_ACCOUNT_ID)).toBeNull();
    expect((await readAccountIndex(SCRATCH)).accounts).toEqual([]);
    await expect(disconnect(SCRATCH)).resolves.toBeUndefined();
  });

  it('rejects an unknown connect_id rather than inventing a status', async () => {
    const error = await getConnectStatus('c_nope').catch((e: unknown) => e as EngineError);
    expect(error).toBeInstanceOf(EngineError);
    expect((error as EngineError).code).toBe('not_connected');
  });
});

/* ─────────────────────────── C-13: multi-account, end to end ───────────────────────────
 * The wave-1 MEDIUM: a second account of one provider silently clobbered the first because the
 * vault was keyed by provider alone. These drive TWO Slack workspaces through the real connect
 * flow (flipping the mock's identity between them) and prove both tokens coexist and route.
 */

describe('multi-account (C-13) — two accounts of one provider coexist', () => {
  const HQ = MOCK_IDENTITY; // handle 'Rithvik' in 'VoiceOS HQ', accountId 'U04F2K9'
  const ACME = { handle: 'Rithvik', workspace: 'Acme Corp', accountId: 'U-ACME-9' };

  async function connectAs(identity: { handle: string; workspace?: string; accountId: string }) {
    mock.setIdentity(identity);
    const before = opened.length;
    const started = await connect(profileFor(mock), { force: true });
    await browserRedirect(opened[before] as string, 'allow');
    await waitForPhase(started.connect_id, ['connected', 'error']);
  }

  it('stores two workspace tokens without collision and routes getToken(provider, account)', async () => {
    await connectAs(HQ);
    await connectAs(ACME);

    // Two distinct Keychain items — the second connect did NOT overwrite the first.
    const hqRec = await readToken(SCRATCH, deriveAccountId(HQ));
    const acmeRec = await readToken(SCRATCH, deriveAccountId(ACME));
    expect(hqRec).not.toBeNull();
    expect(acmeRec).not.toBeNull();
    expect(hqRec?.access_token).not.toBe(acmeRec?.access_token);
    expect(hqRec?.identity?.workspace).toBe('VoiceOS HQ');
    expect(acmeRec?.identity?.workspace).toBe('Acme Corp');

    // Both are in the index, and getToken selects the right one by workspace selector.
    const index = await readAccountIndex(SCRATCH);
    expect(index.accounts).toHaveLength(2);

    const hqTok = await getToken(SCRATCH, 'VoiceOS HQ');
    const acmeTok = await getToken(SCRATCH, 'Acme Corp');
    expect(hqTok).toBe(hqRec?.access_token);
    expect(acmeTok).toBe(acmeRec?.access_token);
    expect(hqTok).not.toBe(acmeTok);
  });

  it('getToken(provider) with no selector surfaces the ambiguity — never a silent pick', async () => {
    await connectAs(HQ);
    await connectAs(ACME);

    const error = await getToken(SCRATCH).catch((e: unknown) => e as EngineError);
    expect(error).toBeInstanceOf(EngineError);
    // AccountAmbiguousError is an EngineError; its hint names both accounts to disambiguate.
    expect(`${(error as EngineError).message} ${(error as EngineError).hint}`).toContain('Acme Corp');
    expect(`${(error as EngineError).message} ${(error as EngineError).hint}`).toContain('VoiceOS HQ');
  });

  it('a re-connect of the SAME account (stable opaque id) updates in place, not a duplicate', async () => {
    await connectAs(HQ);
    // Same opaque accountId, renamed workspace label — the id is stable, so one entry updates.
    await connectAs({ handle: 'Rithvik', workspace: 'HQ Renamed', accountId: 'U04F2K9' });

    const index = await readAccountIndex(SCRATCH);
    expect(index.accounts).toHaveLength(1);
    expect(index.accounts[0]?.workspace).toBe('HQ Renamed');
  });
});

/* ─────────────────────────── C-11: scope step-up at authorize ───────────────────────────
 * §9's union rule, wired into the authorize URL: re-consenting to add a scope must re-request
 * the UNION of what was granted and what is newly needed, never the new scope alone (which many
 * providers read as "drop the rest").
 */

describe('scope step-up (C-11) — the authorize request applies the union rule', () => {
  function scopesOf(authorizeUrl: string): string[] {
    // Slack carries its scope list under user_scope with a comma delimiter (profileFor).
    const raw = new URL(authorizeUrl).searchParams.get('user_scope') ?? '';
    return raw.split(',').filter((s) => s.length > 0);
  }

  it('a non-incremental provider re-requests base ∪ granted ∪ new, dropping nothing', async () => {
    // First connect grants the base scopes and vaults them for the account.
    const first = await connect(profileFor(mock));
    await browserRedirect(opened[0] as string, 'allow');
    await waitForPhase(first.connect_id, ['connected']);

    // Step-up: force a re-consent that ADDS chat:write. The mock profile declares no
    // scope_grant → treated conservatively as union.
    await connect(profileFor(mock), { force: true, scopes: ['chat:write'] });
    const stepUpScopes = scopesOf(opened[1] as string);

    // The added scope is present…
    expect(stepUpScopes).toContain('chat:write');
    // …and every previously-granted/base scope is still there — none dropped.
    for (const base of ['channels:read', 'channels:history', 'users:read']) {
      expect(stepUpScopes).toContain(base);
    }
  });

  it('leaves the authorize scopes untouched (and in authored order) when no step-up is asked', async () => {
    await connect(profileFor(mock));
    // No options.scopes → verbatim profile order, the %20/comma serialization test still holds.
    expect(new URL(opened[0] as string).searchParams.get('user_scope')).toBe(
      'channels:read,channels:history,users:read',
    );
  });
});
