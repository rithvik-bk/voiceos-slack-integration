/**
 * C-21 — `auth.client()`, the zero-auth-code wrapper (SPEC §18).
 *
 * These prove every promise the wrapper makes, against the same asserting mock AS the refresh
 * suite uses (200-ok:false dialect, single-use rotation, a token-bound identity endpoint):
 *   - injects the credential and returns the provider's own Response on success;
 *   - JSON-encodes a plain-object body and resolves a path against `api_base`;
 *   - refreshes silently and retries EXACTLY ONCE on a 401 after a successful refresh;
 *   - throws the closed 9-code taxonomy on auth/availability failures, and RETURNS the
 *     Response on a caller-domain 4xx (a 404 is the tool's problem, not ours);
 *   - applies the DPoP sender-constraint (RFC 9449) — a real proof per request, an `ath`
 *     bound to the token, and a nonce challenge answered WITHOUT spending a refresh;
 *   - applies the mTLS constraint's honest limit (needs a client-cert transport);
 *   - raises the scope step-up card BEFORE dispatch, with the union rule, and refuses a
 *     content-triggered escalation;
 *   - resolves multi-account exactly as getToken does.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  auth,
  client as makeClient,
  getToken,
  registerProvider,
  TaxonomyError,
} from '../src/index.ts';
import { createAuthClient } from '../src/client.ts';
import { createDpopSigner } from '../src/dpop.ts';
import { deriveAccountId, toAccountRef } from '../src/account.ts';
import { clearConsumed } from '../src/reuse.ts';
import { deleteAccountIndex, deleteToken, putToken, writeAccountIndex } from '../src/vault.ts';
import type { ProviderProfile, TokenRecord } from '../src/types.ts';
import { startMockAs } from './mock-as.ts';
import type { MockAs } from './mock-as.ts';

const SCRATCH = 'test-e2e-scratch-client';
const LOCK = join(tmpdir(), `voiceos-connect-${SCRATCH}.refresh.lock`);

let mock: MockAs;

function genericProfile(as: MockAs, overrides: Partial<ProviderProfile> = {}): ProviderProfile {
  return {
    name: SCRATCH,
    display_name: 'Scratch',
    client_id: 'mock.client.id',
    client_type: 'public',
    pkce: 'S256',
    redirect_strategy: 'loopback',
    redirect_host: 'localhost',
    redirect_ports: [33419],
    authorize_url: as.authorizeUrl,
    token_url: as.tokenUrl,
    api_base: as.origin,
    scopes: ['read'],
    scope_param: 'scope',
    token_auth: 'none',
    refresh_auth: 'client_id_body',
    token_path: 'access_token',
    refresh: 'rotation',
    rotation: 'optional-enabled',
    access_token_ttl: 3600,
    identity_probe: { url: as.identityUrl, handle_path: 'display_name' },
    ...overrides,
  };
}

function slackProfile(as: MockAs, overrides: Partial<ProviderProfile> = {}): ProviderProfile {
  return genericProfile(as, {
    token_path: 'authed_user.access_token',
    refresh_token_path: 'authed_user.refresh_token',
    expires_in_path: 'authed_user.expires_in',
    scope_param: 'user_scope',
    scope_delimiter: ',',
    success_predicate: { path: 'ok', equals: true },
    identity_probe: { url: as.identityUrl, handle_path: 'user', workspace_path: 'team' },
    ...overrides,
  });
}

async function seed(
  as: MockAs,
  overrides: Partial<TokenRecord> = {},
  accountId?: string,
): Promise<void> {
  const record: TokenRecord = {
    provider: SCRATCH,
    access_token: as.current().access,
    refresh_token: as.current().refresh,
    expires_at: Date.now() + 3_600_000,
    scopes: ['read'],
    identity: { handle: 'Rithvik', workspace: 'VoiceOS HQ' },
    obtained_at: Date.now(),
    ...overrides,
  };
  await putToken(SCRATCH, record, accountId);
}

/** A `fetch` that records the request and answers with a scripted Response. */
function capture(scripted: (call: number) => Response): {
  fetchImpl: typeof fetch;
  calls: Array<{ url: string; init: RequestInit }>;
} {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchImpl = (async (url: string | URL | Request, init: RequestInit = {}) => {
    calls.push({ url: String(url), init });
    return scripted(calls.length);
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

function decodeJwtPart(part: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as Record<string, unknown>;
}

function authHeaderOf(init: RequestInit): string {
  const headers = (init.headers ?? {}) as Record<string, string>;
  return headers.authorization ?? headers.Authorization ?? '';
}

/** Await a call that must reject with a {@link TaxonomyError}; returns it, narrowed. */
async function rejects(p: Promise<unknown>): Promise<TaxonomyError> {
  try {
    await p;
  } catch (e) {
    return e as TaxonomyError;
  }
  throw new Error('expected the call to throw a TaxonomyError, but it resolved');
}

beforeEach(async () => {
  clearConsumed();
  mock = await startMockAs({ mode: 'generic' });
  await rm(LOCK, { force: true });
});

afterEach(async () => {
  await deleteToken(SCRATCH).catch(() => undefined);
  await deleteAccountIndex(SCRATCH).catch(() => undefined);
  await rm(LOCK, { force: true });
  await mock.close();
});

/* ─────────────────────────────── the happy path ─────────────────────────────── */

describe('auth.client — the fetch-shaped surface', () => {
  it('injects the credential and returns the provider Response on success', async () => {
    await seed(mock);
    const api = createAuthClient({ resolveProfile: async () => genericProfile(mock) }, SCRATCH);

    const res = await api.get('/api/identity');
    const body = (await res.json()) as { display_name?: string };

    expect(res.status).toBe(200);
    expect(body.display_name).toBe('Rithvik');
    expect(mock.counts.refresh).toBe(0);
    expect(mock.violations).toEqual([]);
  });

  it('resolves a relative path against api_base and JSON-encodes a plain-object body', async () => {
    await seed(mock);
    const { fetchImpl, calls } = capture(() => new Response('{"ok":true}', { status: 200 }));
    const api = createAuthClient(
      { resolveProfile: async () => genericProfile(mock) },
      SCRATCH,
      undefined,
      { fetchImpl },
    );

    await api.post('/api/things', { name: 'widget' });

    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(`${mock.origin}/api/things`);
    expect(calls[0]!.init.method).toBe('POST');
    expect(calls[0]!.init.body).toBe(JSON.stringify({ name: 'widget' }));
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers['content-type']).toBe('application/json');
    expect(authHeaderOf(calls[0]!.init)).toBe(`Bearer ${mock.current().access}`);
  });

  it('passes an absolute URL through untouched', async () => {
    await seed(mock);
    const { fetchImpl, calls } = capture(() => new Response('{}', { status: 200 }));
    const api = createAuthClient(
      { resolveProfile: async () => genericProfile(mock) },
      SCRATCH,
      undefined,
      { fetchImpl },
    );

    await api.get('https://example.test/v1/me');
    expect(calls[0]!.url).toBe('https://example.test/v1/me');
  });
});

/* ─────────────────────────── silent refresh + one retry ─────────────────────────── */

describe('auth.client — silent refresh, retry once on 401', () => {
  it('refreshes and retries exactly once when the access token is dead', async () => {
    // Fresh expiry (no proactive refresh) but a stale access token → a real 401 on first use.
    await seed(mock, { access_token: 'stale-tok' });
    const api = createAuthClient({ resolveProfile: async () => genericProfile(mock) }, SCRATCH);

    const res = await api.get('/api/identity');
    const body = (await res.json()) as { display_name?: string };

    expect(res.status).toBe(200);
    expect(body.display_name).toBe('Rithvik');
    expect(mock.counts.refresh).toBe(1); // one, not a loop
    expect(mock.counts.identity).toBe(2); // the failure and the retry
  });

  it('throws REVOKED (normalized) when the refresh grant is dead', async () => {
    mock = await startMockAs({ mode: 'slack' });
    await seed(mock, { access_token: 'stale-tok' });
    mock.failNext('refresh', 'invalid_refresh_token');
    const api = createAuthClient({ resolveProfile: async () => slackProfile(mock) }, SCRATCH);

    const error = await rejects(api.get('/api/identity'));
    expect(error).toBeInstanceOf(TaxonomyError);
    expect(error.code).toBe('REVOKED');
  });
});

/* ─────────────────────────── the taxonomy throw/return line ─────────────────────────── */

describe('auth.client — normalized taxonomy errors', () => {
  it('throws NOT_CONNECTED when nothing is vaulted', async () => {
    const api = createAuthClient({ resolveProfile: async () => genericProfile(mock) }, SCRATCH);
    const error = await rejects(api.get('/api/identity'));
    expect(error).toBeInstanceOf(TaxonomyError);
    expect(error.code).toBe('NOT_CONNECTED');
  });

  it('throws RATE_LIMITED on a 429', async () => {
    await seed(mock);
    const { fetchImpl } = capture(() => new Response('{"error":"rate_limited"}', { status: 429 }));
    const api = createAuthClient(
      { resolveProfile: async () => genericProfile(mock) },
      SCRATCH,
      undefined,
      { fetchImpl },
    );
    const error = await rejects(api.get('/x'));
    expect(error.code).toBe('RATE_LIMITED');
    expect(error.status).toBe(429);
  });

  it('throws PROVIDER_UNAVAILABLE on a 5xx', async () => {
    await seed(mock);
    const { fetchImpl } = capture(() => new Response('boom', { status: 503 }));
    const api = createAuthClient(
      { resolveProfile: async () => genericProfile(mock) },
      SCRATCH,
      undefined,
      { fetchImpl },
    );
    const error = await rejects(api.get('/x'));
    expect(error.code).toBe('PROVIDER_UNAVAILABLE');
  });

  it('throws SCOPE_INSUFFICIENT on a 403 and carries the raw provider error', async () => {
    await seed(mock);
    const { fetchImpl } = capture(
      () => new Response('{"error":"insufficient_scope"}', { status: 403 }),
    );
    const api = createAuthClient(
      { resolveProfile: async () => genericProfile(mock) },
      SCRATCH,
      undefined,
      { fetchImpl },
    );
    const error = await rejects(api.get('/x'));
    expect(error.code).toBe('SCOPE_INSUFFICIENT');
    expect(error.rawProviderError).toBe('insufficient_scope');
  });

  it('RETURNS a caller-domain 404 as a Response instead of throwing', async () => {
    await seed(mock);
    const { fetchImpl } = capture(() => new Response('{"error":"not_found"}', { status: 404 }));
    const api = createAuthClient(
      { resolveProfile: async () => genericProfile(mock) },
      SCRATCH,
      undefined,
      { fetchImpl },
    );
    const res = await api.get('/x');
    expect(res.status).toBe(404);
  });

  it('honors throwOnErrorResponses:false — returns even a 500', async () => {
    await seed(mock);
    const { fetchImpl } = capture(() => new Response('boom', { status: 500 }));
    const api = createAuthClient(
      { resolveProfile: async () => genericProfile(mock) },
      SCRATCH,
      undefined,
      { fetchImpl, throwOnErrorResponses: false },
    );
    const res = await api.get('/x');
    expect(res.status).toBe(500);
  });
});

/* ─────────────────────────────── DPoP (RFC 9449) ─────────────────────────────── */

describe('auth.client — DPoP sender-constraint', () => {
  it('signs each request with a DPoP proof bound to the token, not Bearer', async () => {
    await seed(mock);
    const { fetchImpl, calls } = capture(() => new Response('{"ok":true}', { status: 200 }));
    const signer = createDpopSigner();
    const api = createAuthClient(
      { resolveProfile: async () => genericProfile(mock, { sender_constraint: 'dpop' }) },
      SCRATCH,
      undefined,
      { fetchImpl, dpopSigner: signer },
    );

    await api.get('/api/identity?verbose=1');

    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers.authorization).toBe(`DPoP ${mock.current().access}`);
    expect(headers.authorization).not.toMatch(/Bearer/);
    const proof = headers.dpop!;
    const [h, p] = proof.split('.');
    const header = decodeJwtPart(h!);
    const payload = decodeJwtPart(p!);
    expect(header.typ).toBe('dpop+jwt');
    expect(header.alg).toBe('ES256');
    expect((header.jwk as { kty?: string }).kty).toBe('EC');
    expect(payload.htm).toBe('GET');
    // htu strips the query string.
    expect(payload.htu).toBe(`${mock.origin}/api/identity`);
    // ath binds the proof to THIS access token.
    expect(typeof payload.ath).toBe('string');
    expect((payload.ath as string).length).toBeGreaterThan(0);
  });

  it('answers a DPoP-Nonce challenge without spending a refresh', async () => {
    await seed(mock);
    const { fetchImpl, calls } = capture((n) =>
      n === 1
        ? new Response('{"error":"use_dpop_nonce"}', {
            status: 401,
            headers: { 'DPoP-Nonce': 'nonce-xyz', 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"' },
          })
        : new Response('{"ok":true}', { status: 200 }),
    );
    const api = createAuthClient(
      { resolveProfile: async () => genericProfile(mock, { sender_constraint: 'dpop' }) },
      SCRATCH,
      undefined,
      { fetchImpl },
    );

    const res = await api.get('/api/identity');
    expect(res.status).toBe(200);
    expect(calls).toHaveLength(2); // challenge, then the nonce'd retry — no third
    // The retry carried the server nonce, and re-used the SAME token (no refresh).
    const retryProof = (calls[1]!.init.headers as Record<string, string>).dpop!;
    expect(decodeJwtPart(retryProof.split('.')[1]!).nonce).toBe('nonce-xyz');
    expect(authHeaderOf(calls[0]!.init)).toBe(authHeaderOf(calls[1]!.init));
    expect(mock.counts.refresh).toBe(0);
  });
});

/* ─────────────────────────────── mTLS (RFC 8705) ─────────────────────────────── */

describe('auth.client — mTLS sender-constraint', () => {
  it('throws CONFIG_INVALID when no client-certificate transport is supplied', async () => {
    await seed(mock);
    const api = createAuthClient(
      { resolveProfile: async () => genericProfile(mock, { sender_constraint: 'mtls' }) },
      SCRATCH,
    );
    const error = await rejects(api.get('/x'));
    expect(error.code).toBe('CONFIG_INVALID');
    expect(error.action).toMatch(/client-certificate transport/i);
  });

  it('sends the token as Bearer over the supplied transport (RFC 8705)', async () => {
    await seed(mock);
    const { fetchImpl, calls } = capture(() => new Response('{}', { status: 200 }));
    const api = createAuthClient(
      { resolveProfile: async () => genericProfile(mock, { sender_constraint: 'mtls' }) },
      SCRATCH,
      undefined,
      { fetchImpl },
    );
    await api.get('/x');
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers.authorization).toBe(`Bearer ${mock.current().access}`);
    expect(headers.dpop).toBeUndefined();
  });
});

/* ─────────────────────────────── scope step-up (§9) ─────────────────────────────── */

describe('auth.client — scope step-up, before dispatch', () => {
  const noFetch = (() => {
    throw new Error('must not dispatch when a step-up is pending');
  }) as unknown as typeof fetch;

  it('raises a union step-up card and does not dispatch', async () => {
    await seed(mock, { scopes: ['read'] });
    const api = createAuthClient(
      { resolveProfile: async () => genericProfile(mock, { scope_grant: 'exact' }) },
      SCRATCH,
      undefined,
      { fetchImpl: noFetch },
    );

    const error = await rejects(
      api.post('/api/things', { name: 'x' }, { requiresScopes: ['write'] }),
    );

    expect(error.code).toBe('SCOPE_INSUFFICIENT');
    expect(error.stepUp).toBeDefined();
    expect(error.stepUp!.mode).toBe('union');
    expect(error.stepUp!.addedScopes).toEqual(['write']);
    expect(error.stepUp!.requestScopes).toEqual(['read', 'write']); // union, not the delta alone
  });

  it('requests the delta alone for an incremental provider', async () => {
    await seed(mock, { scopes: ['read'] });
    const api = createAuthClient(
      { resolveProfile: async () => genericProfile(mock, { scope_grant: 'incremental' }) },
      SCRATCH,
      undefined,
      { fetchImpl: noFetch },
    );
    const error = await rejects(api.get('/x', { requiresScopes: ['write'] }));
    expect(error.stepUp!.mode).toBe('incremental');
    expect(error.stepUp!.requestScopes).toEqual(['write']);
  });

  it('refuses a content-triggered escalation (privilege-escalation guard)', async () => {
    await seed(mock, { scopes: ['read'] });
    const api = createAuthClient(
      { resolveProfile: async () => genericProfile(mock) },
      SCRATCH,
      undefined,
      { fetchImpl: noFetch },
    );
    const error = await rejects(
      api.get('/x', { requiresScopes: ['write'], trigger: { attribution: 'assistant_content' } }),
    );
    expect(error.code).toBe('SCOPE_INSUFFICIENT');
    expect(error.stepUp).toBeUndefined();
    expect(error.action).toMatch(/not initiated by the user/i);
  });

  it('dispatches normally when the required scope is already granted', async () => {
    await seed(mock, { scopes: ['read', 'write'] });
    const { fetchImpl, calls } = capture(() => new Response('{}', { status: 200 }));
    const api = createAuthClient(
      { resolveProfile: async () => genericProfile(mock) },
      SCRATCH,
      undefined,
      { fetchImpl },
    );
    const res = await api.get('/x', { requiresScopes: ['write'] });
    expect(res.status).toBe(200);
    expect(calls).toHaveLength(1);
  });
});

/* ─────────────────────────────── multi-account (C-13) ─────────────────────────────── */

describe('auth.client — multi-account resolution', () => {
  async function seedTwoAccounts(): Promise<void> {
    const idA = { handle: 'work', workspace: 'Acme', accountId: 'acct-A' };
    const idB = { handle: 'home', workspace: 'Personal', accountId: 'acct-B' };
    const refA = toAccountRef(SCRATCH, idA);
    const refB = toAccountRef(SCRATCH, idB);
    await seed(mock, { access_token: 'tokA' }, deriveAccountId(idA));
    await seed(mock, { access_token: 'tokB' }, deriveAccountId(idB));
    await writeAccountIndex(SCRATCH, { accounts: [refA, refB] });
  }

  it('routes a selector to the right account token', async () => {
    await seedTwoAccounts();
    const { fetchImpl, calls } = capture(() => new Response('{}', { status: 200 }));
    const api = createAuthClient(
      { resolveProfile: async () => genericProfile(mock) },
      SCRATCH,
      'work',
      { fetchImpl },
    );
    await api.get('/x');
    expect(authHeaderOf(calls[0]!.init)).toBe('Bearer tokA');
  });

  it('surfaces ambiguity as CONFIG_INVALID with candidates rather than guessing', async () => {
    await seedTwoAccounts();
    const api = createAuthClient({ resolveProfile: async () => genericProfile(mock) }, SCRATCH);
    const error = await rejects(api.get('/x'));
    expect(error.code).toBe('CONFIG_INVALID');
    expect(error.candidates).toHaveLength(2);
  });
});

/* ─────────────────────────────── public wiring ─────────────────────────────── */

describe('auth.client — public API surface (index.ts)', () => {
  afterEach(() => {
    // registerProvider mutates a module-global registry; leave it as we found it enough for the
    // next test by overwriting with a fresh profile is not possible, so we just rely on unique
    // names. SCRATCH is reused, but each test re-registers before use.
  });

  it('auth.client() and the standalone client() both work end to end', async () => {
    await seed(mock);
    registerProvider(genericProfile(mock));

    const viaNamespace = await auth.client(SCRATCH).get('/api/identity');
    expect(viaNamespace.status).toBe(200);

    const viaStandalone = await makeClient(SCRATCH).get('/api/identity');
    expect(viaStandalone.status).toBe(200);
  });

  it('auth.token is the getToken accessor', async () => {
    await seed(mock);
    registerProvider(genericProfile(mock));
    expect(auth.token).toBe(getToken);
    expect(await auth.token(SCRATCH)).toBe(mock.current().access);
  });
});
