/**
 * P1-I6 — silent refresh, against the mock AS and the real Keychain.
 *
 * The headline test is the concurrency one. It is not a nicety: Slack's refresh token is
 * single-use under rotation, VoiceOS runs one MCP process per integration, and two of them
 * refreshing the same grant at the same moment permanently bricks auth — the failure lands
 * at T+12h, i.e. potentially between the rehearsal and the room. So "two concurrent
 * getFreshToken calls hit the authorization server exactly ONCE" is the invariant, asserted
 * against the AS's own counter rather than against our intentions.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { authorizedFetch, getFreshToken, isFresh } from '../src/refresh.ts';
import { clearConsumed } from '../src/reuse.ts';
import { deleteToken, putToken, readToken } from '../src/vault.ts';
import { EngineError } from '../src/errors.ts';
import type { ProviderProfile, TokenRecord } from '../src/types.ts';
import { startMockAs } from './mock-as.ts';
import type { MockAs } from './mock-as.ts';

const SCRATCH = 'test-e2e-scratch-refresh';
const LOCK = join(tmpdir(), `voiceos-connect-${SCRATCH}.refresh.lock`);

let mock: MockAs;

function profileFor(as: MockAs): ProviderProfile {
  return {
    name: SCRATCH,
    display_name: 'Scratch',
    client_id: 'mock.client.id',
    client_type: 'public',
    pkce: 'S256',
    redirect_strategy: 'loopback',
    redirect_host: 'localhost',
    redirect_ports: [33418],
    authorize_url: as.authorizeUrl,
    token_url: as.tokenUrl,
    scopes: ['channels:read'],
    scope_param: 'user_scope',
    scope_delimiter: ',',
    token_auth: 'none',
    refresh_auth: 'client_id_body',
    token_path: 'authed_user.access_token',
    refresh_token_path: 'authed_user.refresh_token',
    expires_in_path: 'authed_user.expires_in',
    success_predicate: { path: 'ok', equals: true },
    refresh: 'rotation',
    rotation: 'optional-enabled',
    access_token_ttl: 43_200,
    identity_probe: { url: as.identityUrl, handle_path: 'user', workspace_path: 'team' },
  };
}

/** Seed the vault with a record that is already inside the refresh window. */
async function seedStale(as: MockAs, overrides: Partial<TokenRecord> = {}): Promise<void> {
  const record: TokenRecord = {
    provider: SCRATCH,
    access_token: as.current().access,
    refresh_token: as.current().refresh,
    expires_at: Date.now() + 30_000, // well inside REFRESH_SKEW_MS (10 min)
    scopes: ['channels:read'],
    identity: { handle: 'Rithvik', workspace: 'VoiceOS HQ' },
    obtained_at: Date.now() - 43_000_000,
    ...overrides,
  };
  await putToken(SCRATCH, record);
}

beforeEach(async () => {
  // The C-10 consumed-token set is process-global and now live in getFreshToken. The mock AS
  // resets its token generation to mock-refresh-0 for each instance, so without this the
  // deterministic fixture names collide across tests (a real provider's tokens never repeat).
  clearConsumed();
  mock = await startMockAs({ mode: 'slack' });
  await rm(LOCK, { force: true });
});

afterEach(async () => {
  await deleteToken(SCRATCH).catch(() => undefined);
  await rm(LOCK, { force: true });
  await mock.close();
});

describe('getFreshToken — edge-triggered, never a poll', () => {
  it('returns the vaulted token untouched while it is fresh', async () => {
    await seedStale(mock, { expires_at: Date.now() + 11 * 60_000 });
    const token = await getFreshToken(profileFor(mock));

    expect(token).toBe(mock.current().access);
    expect(mock.counts.refresh).toBe(0); // the whole point of "edge-triggered"
  });

  it('refreshes inside the skew window and persists the rotated pair', async () => {
    await seedStale(mock);
    const before = mock.current();

    const token = await getFreshToken(profileFor(mock));

    expect(mock.counts.refresh).toBe(1);
    expect(token).toBe(mock.current().access);
    expect(token).not.toBe(before.access);

    const vaulted = await readToken(SCRATCH);
    expect(vaulted?.access_token).toBe(token);
    expect(vaulted?.refresh_token).toBe(mock.current().refresh);
    expect(vaulted?.refresh_token).not.toBe(before.refresh);
    // The identity survives a refresh: the copy deck speaks it on every status.
    expect(vaulted?.identity).toEqual({ handle: 'Rithvik', workspace: 'VoiceOS HQ' });
    expect(mock.violations).toEqual([]);
  });

  it('throws not_connected when nothing is vaulted', async () => {
    const error = await getFreshToken(profileFor(mock)).catch((e: unknown) => e as EngineError);
    expect(error).toBeInstanceOf(EngineError);
    expect((error as EngineError).code).toBe('not_connected');
  });

  it('surfaces a dead grant as expired_or_revoked, not as a retryable blip', async () => {
    await seedStale(mock);
    mock.failNext('refresh', 'invalid_refresh_token');

    const error = await getFreshToken(profileFor(mock)).catch((e: unknown) => e as EngineError);
    expect((error as EngineError).code).toBe('expired_or_revoked');
    // And the old record is still there — we do not destroy a user's connection on one 4xx.
    expect(await readToken(SCRATCH)).not.toBeNull();
  });

  it('treats a record with no expiry as fresh rather than refreshing on every call', () => {
    const record: TokenRecord = {
      provider: SCRATCH,
      access_token: 'a',
      scopes: [],
      obtained_at: 0,
    };
    expect(isFresh(record)).toBe(true);
  });
});

describe('getFreshToken — the single-use rotation race', () => {
  it('serialises two concurrent calls into exactly ONE refresh at the AS', async () => {
    // Latency makes the race real rather than theoretical: without the lock, both calls
    // would be in flight to /oauth/token at the same instant.
    await mock.close();
    mock = await startMockAs({ mode: 'slack', tokenDelayMs: 120 });
    await seedStale(mock);
    const profile = profileFor(mock);

    const [a, b] = await Promise.all([getFreshToken(profile), getFreshToken(profile)]);

    expect(mock.counts.refresh).toBe(1);
    expect(a).toBe(b);
    expect(a).toBe(mock.current().access);
    expect((await readToken(SCRATCH))?.access_token).toBe(a);
    expect(mock.violations).toEqual([]);
  });

  it('holds five callers to one refresh (one MCP process per integration)', async () => {
    await mock.close();
    mock = await startMockAs({ mode: 'slack', tokenDelayMs: 60 });
    await seedStale(mock);
    const profile = profileFor(mock);

    const tokens = await Promise.all([1, 2, 3, 4, 5].map(() => getFreshToken(profile)));

    expect(mock.counts.refresh).toBe(1);
    expect(new Set(tokens).size).toBe(1);
  });

  it('never writes token bytes into the lock file', async () => {
    await mock.close();
    mock = await startMockAs({ mode: 'slack', tokenDelayMs: 150 });
    await seedStale(mock);
    const secret = mock.current().refresh;

    const inFlight = getFreshToken(profileFor(mock));
    await new Promise((resolve) => setTimeout(resolve, 60));
    const lockBody = await readFile(LOCK, 'utf8').catch(() => '');
    await inFlight;

    expect(lockBody).not.toBe('');
    expect(lockBody).not.toContain(secret);
    expect(JSON.parse(lockBody).pid).toBe(process.pid);
  });

  it('takes over a stale lock instead of deadlocking the demo', async () => {
    await seedStale(mock);
    // A lock left behind by a process that died: unowned pid, old timestamp.
    await writeFile(LOCK, JSON.stringify({ pid: 999_999, at: Date.now() - 120_000 }));

    const token = await getFreshToken(profileFor(mock));
    expect(token).toBe(mock.current().access);
    expect(mock.counts.refresh).toBe(1);
  });

  it('releases the lock even when the refresh fails', async () => {
    await seedStale(mock);
    mock.failNext('refresh', 'invalid_refresh_token');
    await getFreshToken(profileFor(mock)).catch(() => undefined);

    await expect(readFile(LOCK, 'utf8')).rejects.toThrow();
  });
});

describe('authorizedFetch — the on-401 hook', () => {
  it('retries Slack’s 200 + {"ok": false, "error": "invalid_auth"} exactly once', async () => {
    await seedStale(mock, { expires_at: Date.now() + 60 * 60_000 }); // fresh: no proactive refresh
    const profile = profileFor(mock);

    // The mock's identity endpoint 401s anything that is not the CURRENT access token, so
    // pointing the vault at a stale-but-unexpired token reproduces a revoked-token 401.
    await putToken(SCRATCH, {
      ...((await readToken(SCRATCH)) as TokenRecord),
      access_token: 'stale-tok',
    });

    const response = await authorizedFetch(profile, mock.identityUrl, { method: 'GET' });
    const body = (await response.json()) as { ok?: boolean; user?: string };

    expect(response.status).toBe(200);
    // Without the body-level check this reads `{ok:false}` and the demo says "not connected".
    expect(body.ok).toBe(true);
    expect(body.user).toBe('Rithvik');
    expect(mock.counts.refresh).toBe(1); // exactly one — the retry, not a loop
    expect(mock.counts.identity).toBe(2); // the failure and the retry
  });

  it('does not burn a rotation on a non-auth failure', async () => {
    await seedStale(mock, { expires_at: Date.now() + 60 * 60_000 });
    // A 404 is a bad request, not a dead token. Refreshing here would spend a single-use
    // refresh token to fix a typo.
    const response = await authorizedFetch(profileFor(mock), `${mock.origin}/nope`, {
      method: 'GET',
    });
    expect(response.status).toBe(404);
    expect(mock.counts.refresh).toBe(0);
  });

  it('does not refresh at all when the call succeeds', async () => {
    await seedStale(mock, { expires_at: Date.now() + 60 * 60_000 });
    const response = await authorizedFetch(profileFor(mock), mock.identityUrl, { method: 'GET' });

    expect(response.status).toBe(200);
    expect(mock.counts.refresh).toBe(0);
  });
});
