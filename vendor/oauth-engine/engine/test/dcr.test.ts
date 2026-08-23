/**
 * Custody Class C — RFC 7591 dynamic client registration (C-8). Tests for `dcr.ts`.
 *
 * Three layers, matching byos.test.ts's split of risk:
 *   1. The registration CALL against an injected `fetch` — body shape, response parsing, and the
 *      failure classifications, deterministically and offline.
 *   2. On-device custody against an injected `security` — the same fakeKeychain byos uses — so
 *      the assertions that a returned client_secret never reaches argv, is read from one path
 *      only, and is mirrored into the confidential store, are inspectable.
 *   3. A REAL macOS Keychain round trip for the transport we did not write.
 *
 * Plus a full connect() wiring proof: a dcr-capable profile ships with NO client_id, and the
 * engine self-registers one, threads it into the authorize URL, and completes the exchange — the
 * whole point of "a dcr-capable provider needs no pre-registered client_id."
 */

import { createServer } from 'node:http';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  DCR_ACCOUNT,
  applyRegisteredClient,
  dcrService,
  deleteRegisteredClient,
  ensureRegisteredClient,
  readRegisteredClient,
  registerClient,
  secretsOf,
  storeRegisteredClient,
  type RegisteredClient,
} from '../src/dcr.ts';
import { BYOC_ACCOUNT, byocService, readClientCredentials, type RunResult, type SecurityRunner } from '../src/byos.ts';
import { EngineError } from '../src/errors.ts';
import { redact } from '../src/redact.ts';
import type { ProviderProfile } from '../src/types.ts';
import {
  connect,
  disconnect,
  getConnectStatus,
  getToken,
  resetPlatformHooks,
  setPlatformHooks,
} from '../src/index.ts';
import type { ConnectStatus } from '../src/index.ts';
import { REDIRECT_URIS } from '../src/config.ts';
import { startMockAs, MOCK_IDENTITY } from './mock-as.ts';
import type { MockAs } from './mock-as.ts';

const runReal = promisify(execFile);
const SCRATCH = 'test-dcr-scratch';
const SECRET = 'dcr-sh!p_$$_"q"_\\slash_ end'; // shell-hostile on purpose

/* ─────────────────── an in-memory `security` that records every call ─────────────────── */

interface Call {
  args: readonly string[];
  stdin: string | undefined;
}

function fakeKeychain(): { runner: SecurityRunner; calls: Call[]; store: Map<string, string> } {
  const store = new Map<string, string>();
  const calls: Call[] = [];
  const runner: SecurityRunner = async (args, stdin) => {
    calls.push({ args, stdin });
    const ok = (stdout = ''): RunResult => ({ code: 0, stdout, stderr: '' });
    const notFound = (): RunResult => ({ code: 44, stdout: '', stderr: 'could not be found' });
    if (args.length === 1 && args[0] === '-i') {
      const cmd = stdin ?? '';
      const svc = /-s (\S+)/.exec(cmd)?.[1];
      const hex = /-X (\S+)/.exec(cmd)?.[1];
      if (svc === undefined || hex === undefined) return { code: 2, stdout: '', stderr: 'bad -i command' };
      store.set(svc, Buffer.from(hex, 'hex').toString('utf8'));
      return ok();
    }
    const svc = (() => {
      const i = args.indexOf('-s');
      return i >= 0 ? args[i + 1] : undefined;
    })();
    if (args[0] === 'find-generic-password') {
      if (svc === undefined || !store.has(svc)) return notFound();
      return ok(`${store.get(svc)}\n`);
    }
    if (args[0] === 'delete-generic-password') {
      if (svc === undefined || !store.delete(svc)) return notFound();
      return ok();
    }
    return { code: 2, stdout: '', stderr: `unhandled: ${args.join(' ')}` };
  };
  return { runner, calls, store };
}

function allArgv(calls: Call[]): string {
  return calls.flatMap((c) => [...c.args]).join(' ');
}

/** A minimal dcr-capable profile — no client_id, endpoints point wherever the test needs. */
function dcrProfile(overrides: Partial<ProviderProfile> = {}): ProviderProfile {
  return {
    name: SCRATCH,
    display_name: 'Scratch',
    client_id: '',
    client_type: 'public',
    pkce: 'S256',
    dcr: 'rfc7591',
    registration_url: 'https://example.test/register',
    authorize_url: 'https://example.test/authorize',
    token_url: 'https://example.test/token',
    redirect_strategy: 'loopback',
    redirect_host: 'localhost',
    redirect_ports: [33418, 33419, 33420],
    scopes: ['read', 'write'],
    scope_param: 'scope',
    token_auth: 'none',
    refresh_auth: 'client_id_body',
    token_path: 'access_token',
    refresh: 'rotation',
    rotation: 'optional-enabled',
    identity_probe: { url: 'https://example.test/me', handle_path: 'user' },
    ...overrides,
  };
}

/** A `fetch` double that answers the registration POST with a scripted status + body. */
function regFetch(
  status: number,
  body: unknown,
): { fetchImpl: typeof fetch; calls: Array<{ url: string; body: unknown }> } {
  const calls: Array<{ url: string; body: unknown }> = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    let parsed: unknown;
    try {
      parsed = JSON.parse(String(init?.body ?? ''));
    } catch {
      parsed = init?.body;
    }
    calls.push({ url, body: parsed });
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

/* ───────────────────────────────── key derivation ───────────────────────────────── */

describe('dcr — key derivation', () => {
  it('namespaces Class C credentials away from the vault and the B1 store', () => {
    expect(dcrService('slack')).toBe('com.voiceos.dcr.slack');
    expect(dcrService('slack')).not.toContain('connect');
    expect(dcrService('slack')).not.toContain('byoc');
  });
  it('rejects an illegal provider name before it reaches a Keychain path', () => {
    expect(() => dcrService('../evil')).toThrow(EngineError);
    expect(() => dcrService('a b')).toThrow(/legal vault key/);
  });
});

/* ─────────────────────────────── the registration call ─────────────────────────────── */

describe('dcr — registerClient (RFC 7591)', () => {
  it('POSTs a public client-metadata body derived from the profile, and parses the client_id', async () => {
    const f = regFetch(201, { client_id: 'minted-123' });
    const client = await registerClient(dcrProfile(), {
      redirectUris: [...REDIRECT_URIS],
      http: { fetchImpl: f.fetchImpl },
    });
    expect(client.client_id).toBe('minted-123');
    expect(client.client_secret).toBeUndefined();

    expect(f.calls).toHaveLength(1);
    expect(f.calls[0]?.url).toBe('https://example.test/register');
    const sent = f.calls[0]?.body as Record<string, unknown>;
    expect(sent.token_endpoint_auth_method).toBe('none'); // public — PKCE available
    expect(sent.response_types).toEqual(['code']);
    expect(sent.grant_types).toEqual(['authorization_code', 'refresh_token']);
    expect(sent.redirect_uris).toEqual([...REDIRECT_URIS]);
    expect(sent.scope).toBe('read write');
  });

  it('requests a confidential client when PKCE is unavailable, and keeps a returned secret', async () => {
    const f = regFetch(201, { client_id: 'minted-c', client_secret: SECRET });
    const client = await registerClient(dcrProfile({ pkce: 'none' }), {
      redirectUris: [...REDIRECT_URIS],
      http: { fetchImpl: f.fetchImpl },
    });
    expect((f.calls[0]?.body as Record<string, unknown>).token_endpoint_auth_method).toBe('client_secret_post');
    expect(client.client_secret).toBe(SECRET);
  });

  it('omits refresh_token from grant_types when the provider issues none', async () => {
    const f = regFetch(201, { client_id: 'x' });
    await registerClient(dcrProfile({ refresh: 'none' }), {
      redirectUris: [...REDIRECT_URIS],
      http: { fetchImpl: f.fetchImpl },
    });
    expect((f.calls[0]?.body as Record<string, unknown>).grant_types).toEqual(['authorization_code']);
  });

  it('accepts HTTP 200 as well as 201', async () => {
    const f = regFetch(200, { client_id: 'ok200' });
    const client = await registerClient(dcrProfile(), { redirectUris: [...REDIRECT_URIS], http: { fetchImpl: f.fetchImpl } });
    expect(client.client_id).toBe('ok200');
  });

  it('refuses a profile that is not dcr-capable', async () => {
    await expect(
      registerClient(dcrProfile({ dcr: 'none' }), { redirectUris: [...REDIRECT_URIS] }),
    ).rejects.toThrow(/not marked dcr/);
  });

  it('refuses a dcr profile with no registration_url', async () => {
    const { registration_url: _omit, ...noReg } = dcrProfile();
    await expect(
      registerClient(noReg as ProviderProfile, { redirectUris: [...REDIRECT_URIS] }),
    ).rejects.toThrow(/no registration_url/);
  });

  it('refuses to register with no redirect_uri', async () => {
    await expect(registerClient(dcrProfile(), { redirectUris: [] })).rejects.toThrow(/redirect_uri/);
  });

  it('classifies a non-2xx as provider_error and surfaces the provider error verbatim', async () => {
    const f = regFetch(400, { error: 'invalid_redirect_uri' });
    let thrown: unknown;
    try {
      await registerClient(dcrProfile(), { redirectUris: [...REDIRECT_URIS], http: { fetchImpl: f.fetchImpl } });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(EngineError);
    expect((thrown as EngineError).code).toBe('provider_error');
    expect((thrown as EngineError).providerMessage).toBe('invalid_redirect_uri');
  });

  it('rejects a non-JSON body without echoing it', async () => {
    const f = regFetch(201, '<html>not json</html>');
    await expect(
      registerClient(dcrProfile(), { redirectUris: [...REDIRECT_URIS], http: { fetchImpl: f.fetchImpl } }),
    ).rejects.toThrow(/non-JSON/);
  });

  it('rejects a 2xx that carries no client_id', async () => {
    const f = regFetch(201, { note: 'no id here' });
    await expect(
      registerClient(dcrProfile(), { redirectUris: [...REDIRECT_URIS], http: { fetchImpl: f.fetchImpl } }),
    ).rejects.toThrow(/no client_id/);
  });
});

/* ─────────────────────────── on-device custody (injected Keychain) ─────────────────────────── */

describe('dcr — on-device custody of the registered client', () => {
  const CLIENT: RegisteredClient = {
    client_id: 'minted-abc',
    client_secret: SECRET,
    registration_access_token: 'reg-tok-xyz',
    redirect_uris: [...REDIRECT_URIS],
  };

  it('never puts the secret (or its hex) in argv; the payload rides stdin', async () => {
    const kc = fakeKeychain();
    await storeRegisteredClient(SCRATCH, CLIENT, { runner: kc.runner });
    const argv = allArgv(kc.calls);
    expect(argv).not.toContain(SECRET);
    expect(argv).not.toContain(Buffer.from(SECRET, 'utf8').toString('hex'));
    const write = kc.calls.find((c) => c.args.length === 1 && c.args[0] === '-i');
    expect(write?.args).toEqual(['-i']);
  });

  it('round-trips the full record through the store', async () => {
    const kc = fakeKeychain();
    await storeRegisteredClient(SCRATCH, CLIENT, { runner: kc.runner });
    const read = await readRegisteredClient(SCRATCH, { runner: kc.runner });
    expect(read).toEqual(CLIENT);
  });

  it('returns null when no client is registered', async () => {
    const kc = fakeKeychain();
    expect(await readRegisteredClient(SCRATCH, { runner: kc.runner })).toBeNull();
  });

  it('is stored under the dcr account, distinct from the B1 store', async () => {
    const kc = fakeKeychain();
    await storeRegisteredClient(SCRATCH, CLIENT, { runner: kc.runner });
    expect(kc.store.has(dcrService(SCRATCH))).toBe(true);
    expect(kc.store.has(byocService(SCRATCH))).toBe(false);
  });

  it('delete removes the item and is idempotent', async () => {
    const kc = fakeKeychain();
    await storeRegisteredClient(SCRATCH, CLIENT, { runner: kc.runner });
    await deleteRegisteredClient(SCRATCH, { runner: kc.runner });
    expect(await readRegisteredClient(SCRATCH, { runner: kc.runner })).toBeNull();
    await expect(deleteRegisteredClient(SCRATCH, { runner: kc.runner })).resolves.toBeUndefined();
  });

  it('rejects an empty client_id', async () => {
    const kc = fakeKeychain();
    await expect(
      storeRegisteredClient(SCRATCH, { client_id: '' }, { runner: kc.runner }),
    ).rejects.toThrow(/client_id/);
  });

  it('fails loudly when the write does not survive a read-back', async () => {
    const kc = fakeKeychain();
    const amnesiac: SecurityRunner = async (args, stdin) => {
      if (args.length === 1 && args[0] === '-i') return { code: 0, stdout: '', stderr: '' };
      return kc.runner(args, stdin);
    };
    await expect(
      storeRegisteredClient(SCRATCH, CLIENT, { runner: amnesiac }),
    ).rejects.toThrow(/did not survive a read-back/);
  });

  it('no console channel ever sees the secret across a store→read cycle', async () => {
    const kc = fakeKeychain();
    const seen: string[] = [];
    const spies = (['log', 'info', 'warn', 'error', 'debug', 'trace'] as const).map((m) =>
      vi.spyOn(console, m).mockImplementation((...a: unknown[]) => {
        seen.push(a.map(String).join(' '));
      }),
    );
    try {
      await storeRegisteredClient(SCRATCH, CLIENT, { runner: kc.runner });
      const read = await readRegisteredClient(SCRATCH, { runner: kc.runner });
      expect(read?.client_secret).toBe(SECRET);
    } finally {
      for (const s of spies) s.mockRestore();
    }
    expect(seen.join('\n')).not.toContain(SECRET);
  });

  it('exposes its secret-shaped fields for redaction, and redact() scrubs them', () => {
    const secrets = secretsOf(CLIENT);
    expect(secrets).toContain(SECRET);
    expect(secrets).toContain('reg-tok-xyz');
    const cleaned = redact(`server said client_secret=${SECRET}`, secrets);
    expect(cleaned).not.toContain(SECRET);
    expect(cleaned).toContain('[redacted]');
  });
});

/* ───────────────────────── ensureRegisteredClient — cache or register ───────────────────────── */

describe('dcr — ensureRegisteredClient', () => {
  it('registers on first use and caches on the second (no second network call)', async () => {
    const kc = fakeKeychain();
    const f = regFetch(201, { client_id: 'once-only' });
    const input = { redirectUris: [...REDIRECT_URIS], http: { fetchImpl: f.fetchImpl }, runner: kc.runner };

    const first = await ensureRegisteredClient(dcrProfile(), input);
    expect(first.client_id).toBe('once-only');
    const second = await ensureRegisteredClient(dcrProfile(), input);
    expect(second.client_id).toBe('once-only');
    expect(f.calls).toHaveLength(1); // the second call was served from the on-device cache
  });

  it('re-registers when the stored client does not cover a needed redirect_uri', async () => {
    const kc = fakeKeychain();
    // Pre-store a client that only covers ONE of the ladder URIs.
    await storeRegisteredClient(SCRATCH, { client_id: 'stale', redirect_uris: [REDIRECT_URIS[0]!] }, { runner: kc.runner });
    const f = regFetch(201, { client_id: 'fresh' });
    const client = await ensureRegisteredClient(dcrProfile(), {
      redirectUris: [...REDIRECT_URIS],
      http: { fetchImpl: f.fetchImpl },
      runner: kc.runner,
    });
    expect(client.client_id).toBe('fresh');
    expect(f.calls).toHaveLength(1);
  });

  it('mirrors a registered secret into the B1 store so the confidential exchange path can read it', async () => {
    const kc = fakeKeychain();
    const f = regFetch(201, { client_id: 'conf-id', client_secret: SECRET });
    await ensureRegisteredClient(dcrProfile({ pkce: 'none' }), {
      redirectUris: [...REDIRECT_URIS],
      http: { fetchImpl: f.fetchImpl },
      runner: kc.runner,
    });
    const mirrored = await readClientCredentials(SCRATCH, { runner: kc.runner });
    expect(mirrored).toEqual({ client_id: 'conf-id', client_secret: SECRET });
  });
});

/* ─────────────────────────────── applyRegisteredClient ─────────────────────────────── */

describe('dcr — applyRegisteredClient', () => {
  it('threads the minted client_id into a public profile, leaving the wire modes untouched', () => {
    const eff = applyRegisteredClient(dcrProfile(), { client_id: 'minted-pub' });
    expect(eff.client_id).toBe('minted-pub');
    expect(eff.token_auth).toBe('none');
    expect(eff.client_type).toBe('public');
  });

  it('flips to confidential wire modes when the provider issued a secret', () => {
    const eff = applyRegisteredClient(dcrProfile({ pkce: 'none' }), { client_id: 'minted-conf', client_secret: SECRET });
    expect(eff.client_id).toBe('minted-conf');
    expect(eff.client_type).toBe('confidential');
    expect(eff.token_auth).toBe('secret_post');
    expect(eff.refresh_auth).toBe('secret_post');
  });
});

/* ──────────────────────────── real macOS Keychain round trip ──────────────────────────── */

describe('dcr — real Keychain (transport we did not write)', () => {
  afterEach(async () => {
    await runReal('/usr/bin/security', ['delete-generic-password', '-a', DCR_ACCOUNT, '-s', dcrService(SCRATCH)]).catch(() => undefined);
  });
  it('stores, reads back and deletes a real record with shell-hostile bytes intact', async () => {
    const client: RegisteredClient = { client_id: 'real-id', client_secret: SECRET, redirect_uris: [...REDIRECT_URIS] };
    expect(await readRegisteredClient(SCRATCH)).toBeNull();
    await storeRegisteredClient(SCRATCH, client);
    expect(await readRegisteredClient(SCRATCH)).toEqual(client);
    await deleteRegisteredClient(SCRATCH);
    expect(await readRegisteredClient(SCRATCH)).toBeNull();
  });
});

/* ─────────────────────── connect() wiring: self-register, then use it ─────────────────────── */

/** A tiny RFC 7591 registration endpoint that mints a fixed client_id and counts calls. */
async function startRegServer(clientId: string): Promise<{
  url: string;
  count: () => number;
  close: () => Promise<void>;
}> {
  let count = 0;
  const server: Server = createServer((_req, res) => {
    count += 1;
    const body = JSON.stringify({ client_id: clientId });
    res.writeHead(201, { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) });
    res.end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}/register`,
    count: () => count,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

describe('dcr — connect() self-registers when the profile ships no client_id (C-8)', () => {
  const WIRE = 'test-dcr-wire';
  let mock: MockAs;
  let reg: Awaited<ReturnType<typeof startRegServer>>;
  let opened: string[];

  function wireProfile(): ProviderProfile {
    return {
      name: WIRE,
      display_name: 'Scratch',
      client_id: '', // the whole point: no pre-registered client id
      client_type: 'public',
      pkce: 'S256',
      dcr: 'rfc7591',
      registration_url: reg.url,
      authorize_url: mock.authorizeUrl,
      token_url: mock.tokenUrl,
      redirect_strategy: 'loopback',
      redirect_host: 'localhost',
      redirect_ports: [33418, 33419, 33420],
      scopes: ['channels:read', 'users:read'],
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
        url: mock.identityUrl,
        method: 'POST',
        auth: 'bearer',
        success_predicate: { path: 'ok', equals: true },
        handle_path: 'user',
        workspace_path: 'team',
        account_id_path: 'user_id',
      },
    };
  }

  async function browserRedirect(authorizeUrl: string): Promise<void> {
    const url = new URL(authorizeUrl);
    const callback = new URL(url.searchParams.get('redirect_uri') as string);
    callback.searchParams.set('code', 'mock-auth-code');
    callback.searchParams.set('state', url.searchParams.get('state') as string);
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

  beforeEach(async () => {
    mock = await startMockAs({ mode: 'slack' });
    reg = await startRegServer('dcr-minted-client');
    opened = [];
    setPlatformHooks({ openUrl: async (u) => { opened.push(u); }, activateApp: async () => {} });
    await disconnect(WIRE).catch(() => undefined);
  });

  afterEach(async () => {
    await disconnect(WIRE).catch(() => undefined);
    await runReal('/usr/bin/security', ['delete-generic-password', '-a', DCR_ACCOUNT, '-s', dcrService(WIRE)]).catch(() => undefined);
    await runReal('/usr/bin/security', ['delete-generic-password', '-a', BYOC_ACCOUNT, '-s', byocService(WIRE)]).catch(() => undefined);
    resetPlatformHooks();
    await mock.close();
    await reg.close();
  });

  it('mints a client_id, puts it in the authorize URL, exchanges, and connects', async () => {
    const start = await connect(wireProfile());
    expect(start.phase).toBe('launching-browser');

    // The registration happened before the browser opened, and the minted id is in the URL.
    expect(reg.count()).toBe(1);
    expect(opened).toHaveLength(1);
    const authorizeUrl = new URL(opened[0]!);
    expect(authorizeUrl.searchParams.get('client_id')).toBe('dcr-minted-client');

    await browserRedirect(opened[0]!);
    const done = await waitForPhase(start.connect_id, ['connected', 'error']);
    expect(done.phase).toBe('connected');
    expect(done.identity?.handle).toBe(MOCK_IDENTITY.handle);

    // The token is usable, and the self-registered client is on-device.
    expect(await getToken(WIRE)).toBeTruthy();
    const stored = await readRegisteredClient(WIRE);
    expect(stored?.client_id).toBe('dcr-minted-client');

    // The mock asserts no client_secret ever reached the token endpoint (public DCR client).
    expect(mock.violations).toEqual([]);
  });

  it('does not re-register on a reconnect that finds a live token', async () => {
    const start = await connect(wireProfile());
    await browserRedirect(opened[0]!);
    await waitForPhase(start.connect_id, ['connected', 'error']);
    expect(reg.count()).toBe(1);

    // Second connect with a live, recoverable token short-circuits — no browser, no registration.
    opened.length = 0;
    const again = await connect(wireProfile());
    expect(again.phase).toBe('connected');
    expect(opened).toHaveLength(0);
    expect(reg.count()).toBe(1);
  });

  it('disconnect forgets the self-registered client', async () => {
    const start = await connect(wireProfile());
    await browserRedirect(opened[0]!);
    await waitForPhase(start.connect_id, ['connected', 'error']);
    expect(await readRegisteredClient(WIRE)).not.toBeNull();
    await disconnect(WIRE);
    expect(await readRegisteredClient(WIRE)).toBeNull();
  });
});
