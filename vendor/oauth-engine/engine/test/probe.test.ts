/**
 * Conformance probe — C-1 / C-18 (SPEC Part 1 §2, §20 rung 2).
 *
 * The truths this suite buys, each of which the probe would otherwise re-litigate:
 *   1. RFC 8414 / OIDC discovery populates the capability fields (§2 bullet 1).
 *   2. client_auth is MEASURED by a doomed unauthenticated exchange: 401/invalid_client ⇒
 *      confidential, 400/invalid_grant ⇒ public (§2 bullet 3, "the whole ballgame").
 *   3. Redirect + loopback-host tolerance is measured per host literal, not assumed (§2 b4, §7).
 *   4. Token shape / expiry / scope grant / refresh rotation are read from a real response,
 *      and the C-SL-07 two-access_token trap is handled by preferring the nested path (§2 b5).
 *   5. INV-CONFIG-5: anything undeterminable is emitted as `unknown`, with a receipt.
 *   6. Custody class is DERIVED from the measured profile (§4, §5b).
 *   7. Every field has a receipt, and no credential-shaped run survives into the artifacts.
 */

import { createServer } from 'node:http';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';

import {
  classifyClientAuth,
  clientAuthFromMethods,
  deriveCustody,
  fetchDiscovery,
  observeFirstRefresh,
  observeTokenResponse,
  probe,
  probeRedirectTolerance,
  serialize,
} from '../src/probe/index.ts';

/* ─────────────────────────────── a configurable mock provider ─────────────────────────────── */

interface MockOpts {
  metadata8414?: Record<string, unknown> | null;
  metadataOidc?: Record<string, unknown> | null;
  /** Token endpoint requires a secret ⇒ 401 invalid_client without one. */
  confidential?: boolean;
  /** Loopback host literals the authorize endpoint accepts. */
  acceptedHosts?: string[];
  /** When false, only `fixedPort` is accepted (loopback_fixed_port). */
  acceptAnyPort?: boolean;
  fixedPort?: number;
}

interface Mock {
  origin: string;
  close: () => Promise<void>;
}

function parseRedirect(uri: string): { host: string; port: number } {
  // Manual parse so `[::1]` survives — new URL() would rewrite it.
  const m = uri.match(/^http:\/\/(\[[^\]]+\]|[^:/]+):(\d+)\//);
  return { host: m?.[1] ?? '', port: Number(m?.[2] ?? 0) };
}

async function startMock(opts: MockOpts = {}): Promise<Mock> {
  const fixedPort = opts.fixedPort ?? 33418;
  const acceptedHosts = new Set(opts.acceptedHosts ?? []);
  const server: Server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', 'http://mock.invalid');
      const json = (status: number, body: unknown): void => {
        const text = JSON.stringify(body);
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(text);
      };

      if (url.pathname === '/.well-known/oauth-authorization-server') {
        if (opts.metadata8414 == null) { json(404, { error: 'not_found' }); return; }
        json(200, opts.metadata8414);
        return;
      }
      if (url.pathname === '/.well-known/openid-configuration') {
        if (opts.metadataOidc == null) { json(404, { error: 'not_found' }); return; }
        json(200, opts.metadataOidc);
        return;
      }
      if (url.pathname === '/oauth/token') {
        const chunks: Buffer[] = [];
        for await (const c of req) chunks.push(c as Buffer);
        const params = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
        const hasSecret = req.headers.authorization !== undefined || params.has('client_secret');
        if (opts.confidential && !hasSecret) {
          json(401, { error: 'invalid_client', error_description: 'client authentication required' });
          return;
        }
        // Public (or authenticated): the client is fine, only the throwaway code is bad.
        json(400, { error: 'invalid_grant', error_description: 'code is invalid' });
        return;
      }
      if (url.pathname === '/oauth/authorize') {
        const redirectUri = url.searchParams.get('redirect_uri') ?? '';
        const { host, port } = parseRedirect(redirectUri);
        const hostOk = acceptedHosts.has(host);
        const portOk = opts.acceptAnyPort === true || port === fixedPort;
        if (hostOk && portOk) {
          res.writeHead(302, { location: 'https://login.mock.invalid/consent?flow=1' });
          res.end();
          return;
        }
        json(400, { error: 'redirect_uri_mismatch', error_description: 'redirect_uri did not match a registered value' });
        return;
      }
      json(404, { error: 'not_found' });
    })().catch(() => { try { res.writeHead(500); res.end(); } catch { /* gone */ } });
  });

  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  return {
    origin: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((e) => (e ? reject(e) : resolve()));
      }),
  };
}

const openMocks: Mock[] = [];
async function mock(opts: MockOpts = {}): Promise<Mock> {
  const m = await startMock(opts);
  openMocks.push(m);
  return m;
}
afterEach(async () => {
  while (openMocks.length) await openMocks.pop()!.close();
});

/**
 * A mock that serves RFC 8414 metadata pointing at ITS OWN origin, so the orchestrator's
 * live token/authorize probes hit the same endpoints discovery advertised. The document is
 * built lazily inside the handler from the bound port — solving the chicken-and-egg where
 * metadata must reference an origin that does not exist until the server is listening.
 */
interface SelfMockOpts {
  confidential?: boolean;
  acceptedHosts?: string[];
  acceptAnyPort?: boolean;
  metaOver?: Record<string, unknown>;
}
async function selfServingMock(opts: SelfMockOpts = {}): Promise<Mock> {
  const fixedPort = 33418;
  const acceptedHosts = new Set(opts.acceptedHosts ?? []);
  const ref = { origin: '' };
  const server: Server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', 'http://mock.invalid');
      const json = (status: number, body: unknown): void => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(body));
      };
      if (url.pathname === '/.well-known/oauth-authorization-server') {
        json(200, metadata(ref.origin, opts.metaOver ?? {}));
        return;
      }
      if (url.pathname === '/oauth/token') {
        const chunks: Buffer[] = [];
        for await (const c of req) chunks.push(c as Buffer);
        const params = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
        const hasSecret = req.headers.authorization !== undefined || params.has('client_secret');
        if (opts.confidential && !hasSecret) { json(401, { error: 'invalid_client' }); return; }
        json(400, { error: 'invalid_grant' });
        return;
      }
      if (url.pathname === '/oauth/authorize') {
        const { host, port } = parseRedirect(url.searchParams.get('redirect_uri') ?? '');
        const ok = acceptedHosts.has(host) && (opts.acceptAnyPort === true || port === fixedPort);
        if (ok) { res.writeHead(302, { location: 'https://login.mock.invalid/consent' }); res.end(); return; }
        json(400, { error: 'redirect_uri_mismatch' });
        return;
      }
      json(404, { error: 'not_found' });
    })().catch(() => { try { res.writeHead(500); res.end(); } catch { /* gone */ } });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  ref.origin = `http://127.0.0.1:${port}`;
  const m: Mock = {
    origin: ref.origin,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((e) => (e ? reject(e) : resolve()));
      }),
  };
  openMocks.push(m);
  return m;
}

/** A representative RFC 8414 metadata document, parameterized by origin. */
function metadata(origin: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    issuer: origin,
    authorization_endpoint: `${origin}/oauth/authorize`,
    token_endpoint: `${origin}/oauth/token`,
    revocation_endpoint: `${origin}/oauth/revoke`,
    registration_endpoint: `${origin}/oauth/register`,
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    scopes_supported: ['read', 'write'],
    ...over,
  };
}

/* ───────────────────────────────── pure mapping units ───────────────────────────────── */

describe('clientAuthFromMethods', () => {
  it('reads each closed value from the advertised methods', () => {
    expect(clientAuthFromMethods(['none']).value).toBe('none');
    expect(clientAuthFromMethods(['client_secret_post']).value).toBe('secret_post');
    expect(clientAuthFromMethods(['client_secret_basic']).value).toBe('secret_basic');
    expect(clientAuthFromMethods(['private_key_jwt']).value).toBe('private_key_jwt');
    expect(clientAuthFromMethods(['tls_client_auth']).value).toBe('mtls');
  });
  it('is unknown when the metadata is silent (INV-CONFIG-5)', () => {
    expect(clientAuthFromMethods(undefined).value).toBe('unknown');
  });
});

describe('deriveCustody', () => {
  it('none + S256 ⇒ Class A', () => {
    expect(deriveCustody({ client_auth: 'none', pkce: 'S256' }).custody_class).toBe('A');
  });
  it('private_key_jwt ⇒ B2a with assertion signing', () => {
    const d = deriveCustody({ client_auth: 'private_key_jwt' });
    expect(d.custody_class).toBe('B2a');
    expect(d.relay_mode).toBe('assertion_signing');
  });
  it('secret_post ⇒ B1', () => {
    expect(deriveCustody({ client_auth: 'secret_post' }).custody_class).toBe('B1');
  });
  it('unknown auth but DCR available ⇒ Class C', () => {
    expect(deriveCustody({ client_auth: 'unknown', dcr: 'rfc7591' }).custody_class).toBe('C');
  });
  it('unknown auth, no DCR ⇒ unknown (conservative)', () => {
    expect(deriveCustody({ client_auth: 'unknown', dcr: 'none' }).custody_class).toBe('unknown');
  });
});

/* ──────────────────────────────────── discovery (C-18) ──────────────────────────────────── */

describe('fetchDiscovery', () => {
  it('populates capability fields from an RFC 8414 document', async () => {
    const m = await mock({});
    const enrichedDoc = metadata(m.origin, {
      pushed_authorization_request_endpoint: `${m.origin}/oauth/par`,
      dpop_signing_alg_values_supported: ['ES256'],
    });
    const srv = await mock({ metadata8414: enrichedDoc });
    const enriched = await fetchDiscovery(srv.origin);
    expect(enriched.discovery).toBe('rfc8414');
    expect(enriched.fields.authorize_url).toBe(`${m.origin}/oauth/authorize`);
    expect(enriched.fields.token_url).toBe(`${m.origin}/oauth/token`);
    expect(enriched.fields.pkce).toBe('S256');
    expect(enriched.fields.client_auth).toBe('none');
    expect(enriched.fields.dcr).toBe('rfc7591');
    expect(enriched.fields.revocation).toBe('rfc7009');
    expect(enriched.fields.par).toBe('rfc9126');
    expect(enriched.fields.sender_constraint).toBe('dpop');
  });

  it('falls back to openid-configuration when the oauth doc is absent', async () => {
    const srv = await mock({ metadata8414: null, metadataOidc: metadata('http://issuer.invalid') });
    const out = await fetchDiscovery(srv.origin);
    expect(out.discovery).toBe('oidc');
    expect(out.fields.token_url).toBe('http://issuer.invalid/oauth/token');
  });

  it('returns discovery:none with a receipt when nothing is served', async () => {
    const srv = await mock({});
    const out = await fetchDiscovery(srv.origin);
    expect(out.discovery).toBe('none');
    expect(out.fields.discovery).toBe('none');
    expect(out.receipts.some((r) => r.field === 'discovery')).toBe(true);
  });

  it('device_flow is rfc8628 when the device_code grant is advertised', async () => {
    const doc = metadata('http://issuer.invalid', {
      grant_types_supported: ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'],
    });
    const srv = await mock({ metadata8414: doc });
    const out = await fetchDiscovery(srv.origin);
    expect(out.fields.device_flow).toBe('rfc8628');
  });
});

/* ─────────────────────────── client-auth classification (C-1) ─────────────────────────── */

describe('classifyClientAuth', () => {
  it('classifies a public token endpoint as none (400/invalid_grant)', async () => {
    const m = await mock({ confidential: false });
    const c = await classifyClientAuth(`${m.origin}/oauth/token`, 'public-client-id');
    expect(c.value).toBe('none');
    expect(c.confidential).toBe(false);
    expect(c.receipt.field).toBe('client_auth');
    expect(c.receipt.response?.status).toBe(400);
  });

  it('classifies a confidential endpoint as needing a secret (401/invalid_client)', async () => {
    const m = await mock({ confidential: true });
    const c = await classifyClientAuth(`${m.origin}/oauth/token`, 'public-client-id', {}, 'secret_post');
    expect(c.confidential).toBe(true);
    expect(c.value).toBe('secret_post');
    expect(c.receipt.response?.status).toBe(401);
  });

  it('confidential with no discovered method ⇒ unknown (conservative), still flagged confidential', async () => {
    const m = await mock({ confidential: true });
    const c = await classifyClientAuth(`${m.origin}/oauth/token`, 'public-client-id');
    expect(c.confidential).toBe(true);
    expect(c.value).toBe('unknown');
  });

  it('invalid_client with NO client_id is ambiguous ⇒ unknown, not a guess', async () => {
    const m = await mock({ confidential: true });
    const c = await classifyClientAuth(`${m.origin}/oauth/token`, undefined);
    expect(c.value).toBe('unknown');
    expect(c.confidential).toBe(false);
    expect(c.receipt.note).toMatch(/ambiguous/i);
  });

  it('a transport failure is a receipt, never a throw', async () => {
    const c = await classifyClientAuth('http://127.0.0.1:1/oauth/token', 'id', { timeoutMs: 500 });
    expect(c.value).toBe('unknown');
    expect(c.receipt.note).toMatch(/transport failure/i);
  });
});

/* ─────────────────────────── redirect / host tolerance (C-1, §7) ─────────────────────────── */

describe('probeRedirectTolerance', () => {
  it('records which loopback host literals are tolerated', async () => {
    const m = await mock({ acceptedHosts: ['127.0.0.1'], acceptAnyPort: false, fixedPort: 33418 });
    const r = await probeRedirectTolerance(`${m.origin}/oauth/authorize`, 'client', {}, 33418);
    expect(r.tolerated_hosts).toContain('127.0.0.1');
    expect(r.tolerated_hosts).not.toContain('localhost');
    expect(r.redirect_host).toBe('127.0.0.1');
  });

  it('detects a fixed-port-only provider (rejects the random high port)', async () => {
    const m = await mock({ acceptedHosts: ['127.0.0.1'], acceptAnyPort: false, fixedPort: 33418 });
    const r = await probeRedirectTolerance(`${m.origin}/oauth/authorize`, 'client', {}, 33418);
    expect(r.redirect).toBe('loopback_fixed_port');
  });

  it('detects an any-port provider', async () => {
    const m = await mock({ acceptedHosts: ['127.0.0.1'], acceptAnyPort: true, fixedPort: 33418 });
    const r = await probeRedirectTolerance(`${m.origin}/oauth/authorize`, 'client', {}, 33418);
    expect(r.redirect).toBe('loopback_any_port');
  });

  it('an explicit redirect rejection is classified as rejected', async () => {
    const m = await mock({ acceptedHosts: [], acceptAnyPort: false });
    const r = await probeRedirectTolerance(`${m.origin}/oauth/authorize`, 'client', {}, 33418);
    expect(r.probes.every((p) => p.outcome === 'rejected')).toBe(true);
    expect(r.tolerated_hosts).toHaveLength(0);
  });
});

/* ─────────────────────────── connect observations (C-1, §2 b5) ─────────────────────────── */

const SLACK_EXCHANGE = {
  ok: true,
  app_id: 'A0MOCK',
  token_type: 'bot',
  access_token: 'mock-top-bot-token', // the C-SL-07 trap
  team: { id: 'T0MOCK', name: 'HQ' },
  authed_user: {
    id: 'U04',
    scope: 'channels:read channels:history',
    token_type: 'user',
    access_token: 'mock-nested-user-tok',
    refresh_token: 'mock-nested-refr-0',
    expires_in: 43200,
  },
};

describe('observeTokenResponse', () => {
  it('prefers the nested access_token and flags the ambiguity (C-SL-07)', () => {
    const o = observeTokenResponse(SLACK_EXCHANGE, ['channels:read', 'channels:history']);
    expect(o.fields.token_path).toBe('authed_user.access_token');
    expect(o.fields.refresh_token_path).toBe('authed_user.refresh_token');
    expect(o.fields.expires_in_path).toBe('authed_user.expires_in');
    const receipt = o.receipts.find((r) => r.field === 'token_path');
    expect(receipt?.note).toMatch(/ambiguous/i);
  });

  it('classifies an exact scope grant', () => {
    const o = observeTokenResponse(SLACK_EXCHANGE, ['channels:read', 'channels:history']);
    expect(o.fields.scope_grant).toBe('exact');
    expect(o.granted_scopes).toEqual(['channels:read', 'channels:history']);
  });

  it('classifies a downgraded scope grant', () => {
    const o = observeTokenResponse(SLACK_EXCHANGE, ['channels:read', 'channels:history', 'users:read']);
    expect(o.fields.scope_grant).toBe('downgradeable');
  });

  it('reads a top-level bearer token and expires_in', () => {
    const o = observeTokenResponse(
      { access_token: 'a', refresh_token: 'r', expires_in: 3600, scope: 'read' },
      ['read'],
    );
    expect(o.fields.token_path).toBe('access_token');
    expect(o.fields.expires_in_path).toBe('expires_in');
    expect(o.fields.scope_grant).toBe('exact');
  });

  it('emits token_path unknown when no access_token exists', () => {
    const o = observeTokenResponse({ ok: false });
    const r = o.receipts.find((x) => x.field === 'token_path');
    expect(r?.value).toBe('unknown');
  });

  it('reports expiry:none via receipt when absent', () => {
    const o = observeTokenResponse({ access_token: 'a' });
    expect(o.receipts.some((r) => r.field === 'expiry' && r.value === 'none')).toBe(true);
  });
});

describe('observeFirstRefresh', () => {
  it('detects rotation when the refresh token changes', () => {
    const o = observeFirstRefresh('mock-nested-refr-0', { access_token: 'a', refresh_token: 'mock-nested-refr-1' });
    expect(o.fields.refresh).toBe('rotation');
    expect(o.fields.rotation).toBe('forced');
  });
  it('detects long-lived when the refresh token is unchanged', () => {
    const o = observeFirstRefresh('same-refresh', { access_token: 'a', refresh_token: 'same-refresh' });
    expect(o.fields.refresh).toBe('long_lived');
  });
  it('detects long-lived when no new refresh token is returned', () => {
    const o = observeFirstRefresh('orig', { access_token: 'a' });
    expect(o.fields.refresh).toBe('long_lived');
  });
  it('refresh:none when there was never a refresh token', () => {
    const o = observeFirstRefresh(undefined, {});
    expect(o.fields.refresh).toBe('none');
  });
});

/* ──────────────────────────────── the orchestrator ──────────────────────────────── */

describe('probe (end to end)', () => {
  it('measures a public provider from discovery + live classification', async () => {
    const one = await selfServingMock({
      confidential: false,
      acceptedHosts: ['localhost', '127.0.0.1'],
      acceptAnyPort: true,
    });
    const result = await probe({ name: 'acme', target: one.origin, client_id: 'acme-public-id' });

    expect(result.profile.name).toBe('acme');
    expect(result.profile.discovery).toBe('rfc8414');
    expect(result.profile.client_auth).toBe('none');
    expect(result.profile.custody_class).toBe('A');
    expect(result.profile.pkce).toBe('S256');
    expect(result.profile.redirect_host).toBe('localhost');
    expect(result.evidence.receipts.length).toBeGreaterThan(5);
    expect(result.evidence.receipts.some((r) => r.field === 'client_auth')).toBe(true);
  });

  it('a confidential provider derives a B custody class', async () => {
    const one = await selfServingMock({
      confidential: true,
      metaOver: { token_endpoint_auth_methods_supported: ['client_secret_post'] },
    });
    const result = await probe({ name: 'conf', target: one.origin, client_id: 'x', probeRedirect: false });
    expect(result.profile.client_auth).toBe('secret_post');
    expect(result.profile.custody_class).toBe('B1');
  });

  it('with no discovery and no endpoints, every dimension is unknown (INV-CONFIG-5)', async () => {
    const m = await mock({}); // serves nothing useful
    const result = await probe({ name: 'blank', target: m.origin, probeRedirect: false });
    expect(result.profile.discovery).toBe('none');
    expect(result.profile.client_auth).toBe('unknown');
    expect(result.profile.dcr).toBe('unknown');
    expect(result.profile.par).toBe('unknown');
    expect(result.profile.sender_constraint).toBe('unknown');
    expect(result.profile.device_flow).toBe('unknown');
    expect(result.profile.custody_class).toBe('unknown');
    // Each unknown carries a receipt.
    for (const f of ['dcr', 'par', 'sender_constraint', 'device_flow']) {
      expect(result.evidence.receipts.some((r) => r.field === f)).toBe(true);
    }
  });

  it('folds captured connect observations into the profile', async () => {
    const m = await mock({ metadata8414: null, confidential: false });
    const m2 = await mock({ metadata8414: metadata(m.origin), confidential: false });
    const result = await probe({
      name: 'obs',
      target: m2.origin,
      client_id: 'id',
      scopes: ['channels:read', 'channels:history'],
      probeRedirect: false,
      tokenResponse: SLACK_EXCHANGE,
      originalRefreshToken: 'mock-nested-refr-0',
      firstRefreshResponse: { access_token: 'a', refresh_token: 'mock-nested-refr-1' },
    });
    expect(result.profile.token_path).toBe('authed_user.access_token');
    expect(result.profile.scope_grant).toBe('exact');
    expect(result.profile.refresh).toBe('rotation');
  });
});

/* ──────────────────────────────── emit / no-secret-leak ──────────────────────────────── */

describe('serialize', () => {
  it('produces both named files with trailing newlines', () => {
    const out = serialize({
      profile: { name: 'zed', display_name: 'Zed', client_auth: 'none' },
      evidence: { provider: 'zed', probed_at: 'now', target: 'http://x', receipts: [] },
    });
    expect(out.profile_filename).toBe('zed.json');
    expect(out.evidence_filename).toBe('zed.evidence.json');
    expect(out.profile_json.endsWith('}\n')).toBe(true);
    expect(JSON.parse(out.profile_json).name).toBe('zed');
  });

  it('scrubs credential-shaped runs from the artifacts', () => {
    const out = serialize({
      profile: { name: 'leak' },
      evidence: {
        provider: 'leak',
        probed_at: 'now',
        target: 'http://x',
        receipts: [
          {
            field: 'client_auth',
            value: 'none',
            method: 'x',
            response: { status: 400, body: 'oops access_token=SUPERSECRETVALUE12345 leaked' },
          },
        ],
      },
    });
    expect(out.evidence_json).not.toContain('SUPERSECRETVALUE12345');
    expect(out.evidence_json).toContain('[redacted]');
  });
});
