/**
 * Grant path 3 — the RFC 8628 device authorization grant (C-17). Tests for `device.ts`.
 *
 * Four layers:
 *   1. `selectGrantPath` — the capability-driven choice between loopback and device.
 *   2. `requestDeviceAuthorization` against an injected `fetch` — body shape, response parsing,
 *      the aliases (verification_url), and the failure classifications, offline and deterministic.
 *   3. `pollForDeviceToken` against an injected `fetch` + injected `sleep`/`now` — the mandated
 *      backoff (§3.5: honor interval, +5s on slow_down), and every terminal outcome, with no real
 *      time spent waiting.
 *   4. A full `connect({ headless: true })` wiring proof against a real device mock server: connect
 *      returns fast with the user code (never the device_code), opens NO browser, and completes the
 *      whole grant out of band into a vaulted token.
 *
 * No provider-shaped token literals: every mock secret is a plain `mock-…` value, the same rule the
 * rest of the suite holds (tools/scan-secrets.mjs would be right to fail otherwise).
 */

import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  pollForDeviceToken,
  requestDeviceAuthorization,
  runDeviceGrant,
  selectGrantPath,
  type DeviceAuthorization,
} from '../src/device.ts';
import { EngineError } from '../src/errors.ts';
import {
  connect,
  disconnect,
  getConnectStatus,
  getToken,
  resetPlatformHooks,
  setPlatformHooks,
} from '../src/index.ts';
import type { ConnectStatus, ProviderProfile } from '../src/index.ts';
import { readToken } from '../src/vault.ts';

/* ─────────────────────────────── fixtures + fetch doubles ─────────────────────────────── */

/** A minimal device-flow-capable profile; endpoints point wherever the injected fetch listens. */
function deviceProfile(overrides: Partial<ProviderProfile> = {}): ProviderProfile {
  return {
    name: 'test-device-scratch',
    display_name: 'Scratch',
    client_id: 'mock.client.id',
    client_type: 'public',
    pkce: 'S256',
    device_flow: 'rfc8628',
    device_authorization_url: 'https://example.test/device',
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

/** A `fetch` double answering the device-authorization POST with a scripted status + body. */
function authzFetch(
  status: number,
  body: unknown,
): { fetchImpl: typeof fetch; calls: Array<{ url: string; body: string }> } {
  const calls: Array<{ url: string; body: string }> = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(input), body: String(init?.body ?? '') });
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

/** A `fetch` double that replays a queue of token-endpoint responses, one per poll. */
function pollFetch(
  responses: Array<{ status: number; body: unknown }>,
): { fetchImpl: typeof fetch; bodies: string[] } {
  const bodies: string[] = [];
  let i = 0;
  const fetchImpl = (async (_input: string | URL | Request, init?: RequestInit) => {
    bodies.push(String(init?.body ?? ''));
    const r = responses[Math.min(i, responses.length - 1)]!;
    i += 1;
    return new Response(typeof r.body === 'string' ? r.body : JSON.stringify(r.body), {
      status: r.status,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  return { fetchImpl, bodies };
}

/* ───────────────────────────────── selectGrantPath ───────────────────────────────── */

describe('selectGrantPath (SPEC §3)', () => {
  it('picks the loopback path for an ordinary connect', () => {
    expect(selectGrantPath(deviceProfile(), {})).toBe('loopback');
    expect(selectGrantPath(deviceProfile(), { headless: false })).toBe('loopback');
  });

  it('picks the device path for a headless connect when the provider advertises RFC 8628', () => {
    expect(selectGrantPath(deviceProfile(), { headless: true })).toBe('device');
  });

  it('refuses a headless connect when the provider has no device grant — no silent browser fallback', () => {
    const noDevice = deviceProfile({ device_flow: 'none' });
    let thrown: unknown;
    try {
      selectGrantPath(noDevice, { headless: true });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(EngineError);
    expect((thrown as EngineError).code).toBe('config_invalid');
  });

  it('does not branch on provider identity — the choice is a capability + context', () => {
    // Same context, two different provider names, identical result: proves the decision is the
    // capability value, not the name.
    expect(selectGrantPath(deviceProfile({ name: 'slack' }), { headless: true })).toBe('device');
    expect(selectGrantPath(deviceProfile({ name: 'github' }), { headless: true })).toBe('device');
  });
});

/* ─────────────────────────── requestDeviceAuthorization (§3.1) ─────────────────────────── */

describe('requestDeviceAuthorization (RFC 8628 §3.1)', () => {
  it('POSTs client_id + scope and parses the authorization response', async () => {
    const f = authzFetch(200, {
      device_code: 'mock-device-code-1',
      user_code: 'WDJB-MJHT',
      verification_uri: 'https://example.test/activate',
      verification_uri_complete: 'https://example.test/activate?user_code=WDJB-MJHT',
      expires_in: 900,
      interval: 5,
    });
    const auth = await requestDeviceAuthorization(deviceProfile(), { fetchImpl: f.fetchImpl });

    expect(auth.deviceCode).toBe('mock-device-code-1');
    expect(auth.userCode).toBe('WDJB-MJHT');
    expect(auth.verificationUri).toBe('https://example.test/activate');
    expect(auth.verificationUriComplete).toBe('https://example.test/activate?user_code=WDJB-MJHT');
    expect(auth.interval).toBe(5);
    expect(auth.expiresAt).toBeGreaterThan(Date.now());

    expect(f.calls).toHaveLength(1);
    expect(f.calls[0]?.url).toBe('https://example.test/device');
    const sent = new URLSearchParams(f.calls[0]?.body);
    expect(sent.get('client_id')).toBe('mock.client.id'); // public client id in the body
    expect(sent.get('scope')).toBe('read write');
  });

  it('accepts the verification_url spelling and defaults the interval to 5', async () => {
    const f = authzFetch(200, {
      device_code: 'mock-device-code-2',
      user_code: 'ABCD-EFGH',
      verification_url: 'https://example.test/g', // Google's spelling
      expires_in: 600,
      // no interval
    });
    const auth = await requestDeviceAuthorization(deviceProfile(), { fetchImpl: f.fetchImpl });
    expect(auth.verificationUri).toBe('https://example.test/g');
    expect(auth.interval).toBe(5);
  });

  it('refuses a profile that is not device-flow capable', async () => {
    await expect(
      requestDeviceAuthorization(deviceProfile({ device_flow: 'none' })),
    ).rejects.toThrow(/not marked device_flow/);
  });

  it('refuses a device profile with no device_authorization_url', async () => {
    const { device_authorization_url: _omit, ...noUrl } = deviceProfile();
    await expect(
      requestDeviceAuthorization(noUrl as ProviderProfile),
    ).rejects.toThrow(/no device_authorization_url/);
  });

  it('classifies a non-2xx as provider_error and surfaces the provider error verbatim', async () => {
    const f = authzFetch(400, { error: 'invalid_scope', error_description: 'unknown scope xyz' });
    let thrown: unknown;
    try {
      await requestDeviceAuthorization(deviceProfile(), { fetchImpl: f.fetchImpl });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(EngineError);
    expect((thrown as EngineError).code).toBe('provider_error');
    expect((thrown as EngineError).providerMessage).toContain('unknown scope');
  });

  it('rejects an incomplete authorization (missing user_code) as provider_error', async () => {
    const f = authzFetch(200, { device_code: 'mock-x', verification_uri: 'https://example.test/a' });
    await expect(
      requestDeviceAuthorization(deviceProfile(), { fetchImpl: f.fetchImpl }),
    ).rejects.toThrow(/incomplete device authorization/);
  });

  it('rejects a non-JSON body without echoing it', async () => {
    const f = authzFetch(200, '<html>not json</html>');
    await expect(
      requestDeviceAuthorization(deviceProfile(), { fetchImpl: f.fetchImpl }),
    ).rejects.toThrow(/non-JSON/);
  });
});

/* ─────────────────────────── pollForDeviceToken (§3.4 / §3.5) ─────────────────────────── */

function authFixture(overrides: Partial<DeviceAuthorization> = {}): DeviceAuthorization {
  return {
    deviceCode: 'mock-device-code',
    userCode: 'WDJB-MJHT',
    verificationUri: 'https://example.test/activate',
    expiresAt: Date.now() + 900_000,
    interval: 5,
    ...overrides,
  };
}

describe('pollForDeviceToken (RFC 8628 §3.4/§3.5)', () => {
  it('polls at the interval through authorization_pending, then returns the token', async () => {
    const f = pollFetch([
      { status: 400, body: { error: 'authorization_pending' } },
      { status: 400, body: { error: 'authorization_pending' } },
      { status: 200, body: { access_token: 'mock-access-1', token_type: 'bearer', expires_in: 3600 } },
    ]);
    const slept: number[] = [];
    const record = await pollForDeviceToken(deviceProfile(), authFixture({ interval: 5 }), {
      http: { fetchImpl: f.fetchImpl },
      sleep: async (ms) => {
        slept.push(ms);
      },
    });

    expect(record.access_token).toBe('mock-access-1');
    expect(f.bodies).toHaveLength(3);
    // Each poll carries the device-code grant + the device_code.
    const first = new URLSearchParams(f.bodies[0]);
    expect(first.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:device_code');
    expect(first.get('device_code')).toBe('mock-device-code');
    // It waited the provider's interval (5s) before each poll — never faster.
    expect(slept).toEqual([5000, 5000, 5000]);
  });

  it('adds five seconds to the interval on slow_down (§3.5)', async () => {
    const f = pollFetch([
      { status: 400, body: { error: 'slow_down' } },
      { status: 400, body: { error: 'authorization_pending' } },
      { status: 200, body: { access_token: 'mock-access-2', token_type: 'bearer' } },
    ]);
    const slept: number[] = [];
    await pollForDeviceToken(deviceProfile(), authFixture({ interval: 5 }), {
      http: { fetchImpl: f.fetchImpl },
      sleep: async (ms) => {
        slept.push(ms);
      },
    });
    // First wait 5s, slow_down bumps to 10s for every subsequent wait.
    expect(slept).toEqual([5000, 10_000, 10_000]);
  });

  it('maps access_denied to denied_by_user', async () => {
    const f = pollFetch([{ status: 400, body: { error: 'access_denied' } }]);
    const err = await pollForDeviceToken(deviceProfile(), authFixture(), {
      http: { fetchImpl: f.fetchImpl },
      sleep: async () => {},
    }).catch((e: unknown) => e as EngineError);
    expect(err).toBeInstanceOf(EngineError);
    expect((err as EngineError).code).toBe('denied_by_user');
  });

  it('maps expired_token to expired_or_revoked', async () => {
    const f = pollFetch([{ status: 400, body: { error: 'expired_token' } }]);
    const err = await pollForDeviceToken(deviceProfile(), authFixture(), {
      http: { fetchImpl: f.fetchImpl },
      sleep: async () => {},
    }).catch((e: unknown) => e as EngineError);
    expect((err as EngineError).code).toBe('expired_or_revoked');
  });

  it('gives up at the code’s own expiry rather than polling forever', async () => {
    const f = pollFetch([{ status: 400, body: { error: 'authorization_pending' } }]);
    // now() jumps past expiresAt on the second loop turn.
    let t = 1_000_000;
    const err = await pollForDeviceToken(deviceProfile(), authFixture({ expiresAt: 1_000_500 }), {
      http: { fetchImpl: f.fetchImpl },
      sleep: async () => {
        t += 1_000; // one poll happens, then the clock is past expiry
      },
      now: () => t,
    }).catch((e: unknown) => e as EngineError);
    expect((err as EngineError).code).toBe('expired_or_revoked');
  });

  it('honors an abort signal with a timeout error', async () => {
    const controller = new AbortController();
    const f = pollFetch([{ status: 400, body: { error: 'authorization_pending' } }]);
    const err = await pollForDeviceToken(deviceProfile(), authFixture(), {
      http: { fetchImpl: f.fetchImpl },
      signal: controller.signal,
      sleep: async () => {
        controller.abort();
      },
    }).catch((e: unknown) => e as EngineError);
    expect((err as EngineError).code).toBe('timeout');
  });

  it('handles a Slack-style {ok:false, error} at HTTP 200 via the success predicate', async () => {
    const profile = deviceProfile({ success_predicate: { path: 'ok', equals: true } });
    const f = pollFetch([
      { status: 200, body: { ok: false, error: 'authorization_pending' } },
      { status: 200, body: { ok: true, access_token: 'mock-access-3' } },
    ]);
    const record = await pollForDeviceToken(profile, authFixture(), {
      http: { fetchImpl: f.fetchImpl },
      sleep: async () => {},
    });
    expect(record.access_token).toBe('mock-access-3');
  });
});

/* ─────────────────── runDeviceGrant — the two phases composed ─────────────────── */

describe('runDeviceGrant', () => {
  it('requests a code, hands it to the callback, then polls to a token', async () => {
    // One fetch double serving BOTH endpoints by URL.
    let polls = 0;
    const fetchImpl = (async (input: string | URL | Request) => {
      const url = String(input);
      if (url.endsWith('/device')) {
        return new Response(
          JSON.stringify({
            device_code: 'mock-dc',
            user_code: 'ZZZZ-YYYY',
            verification_uri: 'https://example.test/a',
            expires_in: 900,
            interval: 0,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      polls += 1;
      const body =
        polls < 2
          ? { error: 'authorization_pending' }
          : { access_token: 'mock-access-run', token_type: 'bearer' };
      return new Response(JSON.stringify(body), {
        status: polls < 2 ? 400 : 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;

    let shown: DeviceAuthorization | undefined;
    const record = await runDeviceGrant(
      deviceProfile(),
      (auth) => {
        shown = auth;
      },
      { http: { fetchImpl }, sleep: async () => {} },
    );
    expect(shown?.userCode).toBe('ZZZZ-YYYY');
    expect(record.access_token).toBe('mock-access-run');
  });
});

/* ─────────────────── connect({ headless: true }) — full wiring against a real server ─────────────────── */

interface DeviceMock {
  origin: string;
  counts: { authz: number; poll: number; identity: number };
  current: () => string;
  close: () => Promise<void>;
}

/** A real RFC 8628 provider: device-authorization, a token poll that pends once then succeeds, and identity. */
async function startDeviceMock(): Promise<DeviceMock> {
  const counts = { authz: 0, poll: 0, identity: 0 };
  let access = 'mock-access-server';

  async function readBody(req: IncomingMessage): Promise<string> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    return Buffer.concat(chunks).toString('utf8');
  }
  function json(res: ServerResponse, status: number, payload: unknown): void {
    const body = JSON.stringify(payload);
    res.writeHead(status, { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) });
    res.end(body);
  }

  let origin = '';
  const server: Server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', origin || 'http://127.0.0.1');
      if (url.pathname === '/device') {
        counts.authz += 1;
        json(res, 200, {
          device_code: 'mock-device-code-server',
          user_code: 'PROJ-ECTR',
          verification_uri: `${origin}/activate`,
          expires_in: 900,
          interval: 0, // poll fast in-test; real providers send 5
        });
        return;
      }
      if (url.pathname === '/token') {
        const params = new URLSearchParams(await readBody(req));
        counts.poll += 1;
        if (params.get('grant_type') !== 'urn:ietf:params:oauth:grant-type:device_code') {
          json(res, 400, { error: 'unsupported_grant_type' });
          return;
        }
        if (counts.poll < 2) {
          json(res, 400, { error: 'authorization_pending' });
          return;
        }
        access = `mock-access-server-${counts.poll}`;
        json(res, 200, { access_token: access, token_type: 'bearer', refresh_token: 'mock-refresh-server', expires_in: 3600 });
        return;
      }
      if (url.pathname === '/me') {
        counts.identity += 1;
        const presented = (req.headers.authorization ?? '').replace(/^Bearer /i, '');
        if (presented !== access) {
          json(res, 401, { message: 'bad token' });
          return;
        }
        json(res, 200, { user: 'Rithvik', id: 'device-user-1' });
        return;
      }
      json(res, 404, { error: 'not_found' });
    })().catch(() => {
      try {
        json(res, 500, { error: 'mock_failure' });
      } catch {
        /* socket gone */
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  origin = `http://127.0.0.1:${port}`;
  return {
    origin,
    counts,
    current: () => access,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((e) => (e ? reject(e) : resolve()));
      }),
  };
}

describe('connect({ headless: true }) — the device grant, end to end (C-17)', () => {
  const NAME = 'test-device-wire';
  let mock: DeviceMock;
  let opened: string[];

  function wireProfile(): ProviderProfile {
    return {
      name: NAME,
      display_name: 'Scratch',
      client_id: 'mock.client.id',
      client_type: 'public',
      pkce: 'S256',
      device_flow: 'rfc8628',
      device_authorization_url: `${mock.origin}/device`,
      authorize_url: `${mock.origin}/authorize`,
      token_url: `${mock.origin}/token`,
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
      access_token_ttl: 3600,
      identity_probe: {
        url: `${mock.origin}/me`,
        method: 'GET',
        auth: 'bearer',
        handle_path: 'user',
        account_id_path: 'id',
      },
    };
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
    mock = await startDeviceMock();
    opened = [];
    setPlatformHooks({
      openUrl: async (u) => {
        opened.push(u);
      },
      activateApp: async () => {},
    });
    await disconnect(NAME).catch(() => undefined);
  });

  afterEach(async () => {
    await disconnect(NAME).catch(() => undefined);
    resetPlatformHooks();
    await mock.close();
  });

  it('returns fast with the user code and URL, opens NO browser, then connects out of band', async () => {
    const seen: string[] = [];
    const started = Date.now();
    const first = await connect(wireProfile(), { headless: true, onStatus: (s) => seen.push(s.phase) });
    const elapsed = Date.now() - started;

    // Fast return with the code to show — and no browser was opened (the whole point of headless).
    expect(first.phase).toBe('awaiting-consent');
    expect(elapsed).toBeLessThan(2000);
    expect(opened).toHaveLength(0);
    expect(mock.counts.authz).toBe(1);

    // The user code + verification URL are surfaced…
    expect(first.device?.user_code).toBe('PROJ-ECTR');
    expect(first.device?.verification_uri).toBe(`${mock.origin}/activate`);
    expect(first.spoken).toContain('PROJ-ECTR');
    // …and the SECRET device_code is nowhere on the status.
    expect(JSON.stringify(first)).not.toContain('mock-device-code-server');

    // Nothing vaulted until the poll succeeds.
    expect(await readToken(NAME)).toBeNull();

    const final = await waitForPhase(first.connect_id, ['connected', 'error']);
    expect(final.phase).toBe('connected');
    expect(final.identity?.handle).toBe('Rithvik');
    expect(seen).toEqual(['awaiting-consent', 'exchanging', 'connected']);

    // The token is vaulted and readable by a tool that knows only the provider name.
    expect(await getToken(NAME)).toBe(mock.current());
    expect(mock.counts.poll).toBeGreaterThanOrEqual(2); // pended at least once
  });

  it('a headless connect against a provider with no device grant fails with a config error', async () => {
    const first = await connect({ ...wireProfile(), device_flow: 'none' }, { headless: true });
    expect(first.phase).toBe('error');
    // config_invalid maps to the provider_error render code (the frozen six), spoken honestly.
    expect(first.error?.code).toBe('provider_error');
    expect(opened).toHaveLength(0);
    expect(mock.counts.authz).toBe(0);
  });
});

/* ─────────── device single-flight + supersession — grant path 3 (C-16 / SPEC §14, wave-3 /b) ───────────
 * The wave-2 audit LOW: the device path registered NO single-flight slot, so two concurrent device
 * connects for one (provider, account) both ran to `finalizeConnected` and RACED the vault write.
 * connectDevice now begins/admits/completes the slot exactly as the loopback path does. This proves
 * a second device connect supersedes the first, and the superseded flow is refused at admission —
 * before its identity probe and its vault write — so only ONE flow ever reaches the vault.
 */

/** A device provider whose token endpoint always approves, with a poll interval that leaves a
 *  deterministic window for a second connect to supersede the first before it polls. */
async function startSupersedeMock(): Promise<{
  origin: string;
  counts: { authz: number; poll: number; identity: number };
  close: () => Promise<void>;
}> {
  const counts = { authz: 0, poll: 0, identity: 0 };
  const ACCESS = 'mock-access-sf';

  function json(res: ServerResponse, status: number, payload: unknown): void {
    const body = JSON.stringify(payload);
    res.writeHead(status, { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) });
    res.end(body);
  }

  let origin = '';
  const server: Server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', origin || 'http://127.0.0.1');
      if (url.pathname === '/device') {
        counts.authz += 1;
        json(res, 200, {
          device_code: `mock-device-code-sf-${counts.authz}`,
          user_code: 'SFSF-SFSF',
          verification_uri: `${origin}/activate`,
          expires_in: 900,
          interval: 1, // a 1s pre-poll wait: long enough for the 2nd connect to supersede the 1st
        });
        return;
      }
      if (url.pathname === '/token') {
        counts.poll += 1;
        json(res, 200, { access_token: ACCESS, token_type: 'bearer', refresh_token: 'mock-refresh-sf', expires_in: 3600 });
        return;
      }
      if (url.pathname === '/me') {
        counts.identity += 1;
        const presented = (req.headers.authorization ?? '').replace(/^Bearer /i, '');
        if (presented !== ACCESS) {
          json(res, 401, { message: 'bad token' });
          return;
        }
        json(res, 200, { user: 'Rithvik', id: 'device-user-sf' });
        return;
      }
      json(res, 404, { error: 'not_found' });
    })().catch(() => {
      try {
        json(res, 500, { error: 'mock_failure' });
      } catch {
        /* socket gone */
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  origin = `http://127.0.0.1:${port}`;
  return {
    origin,
    counts,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((e) => (e ? reject(e) : resolve()));
      }),
  };
}

describe('connect({ headless: true }) — supersession on the device path (C-16, wave-3 /b)', () => {
  const NAME = 'test-device-singleflight';
  let sf: Awaited<ReturnType<typeof startSupersedeMock>>;

  function sfProfile(): ProviderProfile {
    return {
      name: NAME,
      display_name: 'Scratch',
      client_id: 'mock.client.id',
      client_type: 'public',
      pkce: 'S256',
      device_flow: 'rfc8628',
      device_authorization_url: `${sf.origin}/device`,
      authorize_url: `${sf.origin}/authorize`,
      token_url: `${sf.origin}/token`,
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
      access_token_ttl: 3600,
      identity_probe: { url: `${sf.origin}/me`, method: 'GET', auth: 'bearer', handle_path: 'user', account_id_path: 'id' },
    };
  }

  async function waitFor(connectId: string, phases: string[], ms = 5000): Promise<ConnectStatus> {
    const deadline = Date.now() + ms;
    for (;;) {
      const status = await getConnectStatus(connectId);
      if (phases.includes(status.phase)) return status;
      if (Date.now() > deadline) throw new Error(`stuck in phase ${status.phase}`);
      await new Promise((r) => setTimeout(r, 15));
    }
  }

  beforeEach(async () => {
    sf = await startSupersedeMock();
    setPlatformHooks({ openUrl: async () => {}, activateApp: async () => {} });
    await disconnect(NAME).catch(() => undefined);
  });

  afterEach(async () => {
    await disconnect(NAME).catch(() => undefined);
    resetPlatformHooks();
    await sf.close();
  });

  it('a second concurrent device connect supersedes the first — only one reaches the vault', async () => {
    // The first connect registers the slot and parks for ~1s before its first poll. The second
    // connect, for the same (provider, default account), supersedes it in that window.
    const a = await connect(sfProfile(), { headless: true });
    const b = await connect(sfProfile(), { headless: true });
    expect(a.phase).toBe('awaiting-consent');
    expect(b.phase).toBe('awaiting-consent');

    const bFinal = await waitFor(b.connect_id, ['connected', 'error']);
    const aFinal = await waitFor(a.connect_id, ['connected', 'error']);

    // The live (second) flow connects; the superseded (first) flow is refused, not connected.
    expect(bFinal.phase).toBe('connected');
    expect(bFinal.identity?.handle).toBe('Rithvik');
    expect(aFinal.phase).toBe('error');
    expect(aFinal.error?.code).toBe('timeout');

    // Only ONE flow ran past admission into finalizeConnected — so the identity probe (and the
    // vault write it precedes) happened exactly once. Without single-flight both would probe.
    expect(sf.counts.identity).toBe(1);
    expect(await getToken(NAME)).toBe('mock-access-sf');
  });
});
