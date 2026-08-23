/**
 * P1-I11 — the mock authorization server. TEST-ONLY, never imported by production code.
 *
 * It exists because the two things most likely to break this engine at 12h+1 minute are
 * invisible to a happy-path integration test:
 *
 *   1. Slack's token endpoint has TWO response shapes — the exchange nests the user token
 *      under `authed_user.*`, the refresh returns it at the TOP LEVEL (D-2026-08-16-1,
 *      measured live). A mock that returns one shape for both would green-light an engine
 *      that dies exactly twelve hours after the demo.
 *   2. Slack ships failures as HTTP 200 + `{"ok": false}` [C-SL-20]. A mock that signals
 *      failure with a 4xx would green-light an engine that reports "connected" on a refusal.
 *
 * It is also an ASSERTING mock, not just a stub. Three invariants the engine must never
 * violate are checked server-side and recorded in `violations`, because a client-side
 * assertion can only check what the test remembered to look at:
 *
 *   - no `client_secret` is ever sent (this engine is architecturally secret-free)
 *   - `redirect_uri` on the exchange is BYTE-IDENTICAL to the one the authorize used (§A8/D6)
 *   - in `zoom` mode: `client_id` travels in the BODY and there is NO Authorization header
 *     (empirically verified against the live Zoom endpoint, 2026-08-16)
 *
 * Rotation is modelled for real: every grant issues a new pair and invalidates the old
 * refresh token, so "two processes raced and bricked the demo" is a test, not a worry.
 */

import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

import { LOOPBACK_IP_HOST } from '../src/config.ts';

export type MockMode = 'slack' | 'zoom' | 'generic';

export interface MockAsOptions {
  mode: MockMode;
  /** The only code the exchange accepts. Anything else is a refusal. */
  code?: string;
  /** When set, the exchange asserts `redirect_uri` matches this byte for byte (§A8). */
  expectedRedirectUri?: string;
  /** When true (default), the exchange refuses a request with no `code_verifier`. */
  requirePkce?: boolean;
  /** Seconds. Slack under rotation = 43200; Zoom = 3600. */
  expiresIn?: number;
  /** Milliseconds of artificial latency on the token endpoint (concurrency tests). */
  tokenDelayMs?: number;
}

export interface MockRequest {
  method: string;
  path: string;
  grant: string;
  params: Record<string, string>;
  authorization: string | undefined;
}

export interface MockAs {
  /** e.g. `http://<loopback-ip>:<ephemeral>` — built from config, never a literal. */
  origin: string;
  tokenUrl: string;
  authorizeUrl: string;
  identityUrl: string;
  /** Every request the server saw, in order. Token values are recorded; it is a test double. */
  requests: MockRequest[];
  counts: { exchange: number; refresh: number; identity: number };
  /** Server-side invariant failures. A test that does not assert this is empty is not a test. */
  violations: string[];
  /** The pair currently considered live. Rotation makes the previous refresh token dead. */
  current(): { access: string; refresh: string };
  /** Force the next grant of a kind to fail with this provider error code. */
  failNext(kind: 'exchange' | 'refresh', error: string): void;
  /**
   * Swap the identity the token exchange and probe answer with — the way a SECOND workspace or
   * a work-vs-personal account looks to the engine. C-13 multi-account tests flip this between
   * connects to prove two accounts of one provider coexist without clobbering each other.
   */
  setIdentity(identity: { handle: string; workspace?: string; accountId: string }): void;
  close(): Promise<void>;
}

const IDENTITY = { handle: 'Rithvik', workspace: 'VoiceOS HQ', accountId: 'U04F2K9' };

function json(res: ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(Buffer.byteLength(body)),
  });
  res.end(body);
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

export async function startMockAs(options: MockAsOptions): Promise<MockAs> {
  const mode = options.mode;
  const expectedCode = options.code ?? 'mock-auth-code';
  const requirePkce = options.requirePkce ?? true;
  const expiresIn = options.expiresIn ?? (mode === 'zoom' ? 3600 : 43_200);

  const requests: MockRequest[] = [];
  const violations: string[] = [];
  const counts = { exchange: 0, refresh: 0, identity: 0 };
  const pending: { exchange?: string | undefined; refresh?: string | undefined } = {};
  // Mutable so a C-13 test can flip to a SECOND account between connects (two workspaces, a
  // work-vs-personal Gmail). Defaults to the shared fixture the copy-deck tests assert against.
  let identity: { handle: string; workspace?: string; accountId: string } = { ...IDENTITY };

  let generation = 0;
  // No provider-shaped token prefixes anywhere in this file: a realistic-looking Slack
  // token literal in a committed test is exactly what tools/scan-secrets.mjs exists to
  // catch, and "it's only a mock" is what every leaked credential's commit message says.
  let live = { access: 'mock-access-0', refresh: 'mock-refresh-0' };
  function rotate(): { access: string; refresh: string } {
    generation += 1;
    live = { access: `mock-access-${generation}`, refresh: `mock-refresh-${generation}` };
    return live;
  }

  /** Both failure dialects. Slack: 200 + ok:false. Zoom/generic: 4xx + reason/error. */
  function refuse(res: ServerResponse, error: string, status = 400): void {
    if (mode === 'slack') {
      json(res, 200, { ok: false, error });
      return;
    }
    json(res, status, { reason: error.replace(/_/g, ' '), error });
  }

  function tokenSuccess(res: ServerResponse, grant: 'exchange' | 'refresh'): void {
    const pair = rotate();
    const scope =
      mode === 'slack'
        ? `channels:read,channels:history,users:read${grant === 'refresh' ? ',identify' : ''}`
        : 'user:read:user';

    if (mode === 'slack' && grant === 'exchange') {
      // NESTED — the user token lives under authed_user. The top-level access_token is the
      // BOT token [C-SL-07]; it is present here on purpose, so a parser that grabs the
      // top-level one on exchange gets a plausible-looking WRONG token and the test catches it.
      json(res, 200, {
        ok: true,
        app_id: 'A0MOCK',
        scope: '',
        token_type: 'bot',
        access_token: 'mock-bot-token-do-not-use',
        bot_user_id: 'B0MOCK',
        team: { id: 'T0MOCK', name: identity.workspace },
        authed_user: {
          id: identity.accountId,
          scope,
          token_type: 'user',
          access_token: pair.access,
          refresh_token: pair.refresh,
          expires_in: expiresIn,
        },
      });
      return;
    }

    if (mode === 'slack') {
      // TOP-LEVEL — D-2026-08-16-1, measured against the live endpoint.
      json(res, 200, {
        ok: true,
        token_type: 'user',
        access_token: pair.access,
        refresh_token: pair.refresh,
        expires_in: expiresIn,
        scope,
        team_id: 'T0MOCK',
        user_id: identity.accountId,
      });
      return;
    }

    json(res, 200, {
      access_token: pair.access,
      token_type: 'bearer',
      refresh_token: pair.refresh,
      expires_in: expiresIn,
      scope,
    });
  }

  const server: Server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', `http://${LOOPBACK_IP_HOST}`);
      const authorization = req.headers.authorization;

      if (url.pathname === '/oauth/token') {
        const raw = await readBody(req);
        const params = new URLSearchParams(raw);
        const grant = params.get('grant_type') ?? '';
        requests.push({
          method: req.method ?? 'POST',
          path: url.pathname,
          grant,
          params: Object.fromEntries(params.entries()),
          authorization,
        });

        // ── invariants, asserted server-side ──────────────────────────────────────────
        if (params.has('client_secret')) {
          violations.push('client_secret was sent to the token endpoint');
        }
        if (mode === 'zoom') {
          if (params.get('client_id') === null || params.get('client_id') === '') {
            violations.push('zoom: client_id must travel in the request body');
          }
          if (authorization !== undefined) {
            violations.push('zoom: a public PKCE client must send NO Authorization header');
          }
        }
        if (mode === 'slack' && authorization !== undefined) {
          violations.push('slack: the PKCE token request carries no Authorization header');
        }

        if (options.tokenDelayMs !== undefined && options.tokenDelayMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, options.tokenDelayMs));
        }

        if (grant === 'authorization_code') {
          counts.exchange += 1;
          const forced = pending.exchange;
          if (forced !== undefined) {
            pending.exchange = undefined;
            refuse(res, forced);
            return;
          }
          if (options.expectedRedirectUri !== undefined) {
            const sent = params.get('redirect_uri');
            if (sent !== options.expectedRedirectUri) {
              violations.push(
                `redirect_uri is not byte-identical to the bound one (§A8): sent ${String(sent)}`,
              );
              refuse(res, 'bad_redirect_uri');
              return;
            }
          }
          if (requirePkce && (params.get('code_verifier') ?? '') === '') {
            violations.push('code_verifier missing from a PKCE exchange');
            refuse(res, 'invalid_request');
            return;
          }
          if (params.get('code') !== expectedCode) {
            refuse(res, 'invalid_code');
            return;
          }
          tokenSuccess(res, 'exchange');
          return;
        }

        if (grant === 'refresh_token') {
          counts.refresh += 1;
          const forced = pending.refresh;
          if (forced !== undefined) {
            pending.refresh = undefined;
            refuse(res, forced);
            return;
          }
          // Single-use rotation: replaying yesterday's refresh token is a dead grant.
          if (params.get('refresh_token') !== live.refresh) {
            refuse(res, 'invalid_refresh_token');
            return;
          }
          tokenSuccess(res, 'refresh');
          return;
        }

        refuse(res, 'unsupported_grant_type');
        return;
      }

      if (url.pathname === '/api/identity') {
        counts.identity += 1;
        requests.push({
          method: req.method ?? 'GET',
          path: url.pathname,
          grant: '',
          params: Object.fromEntries(url.searchParams.entries()),
          authorization,
        });
        const presented = (authorization ?? '').replace(/^Bearer /i, '');
        if (presented !== live.access) {
          if (mode === 'slack') {
            json(res, 200, { ok: false, error: 'invalid_auth' });
            return;
          }
          json(res, 401, { message: 'Invalid access token' });
          return;
        }
        if (mode === 'slack') {
          json(res, 200, {
            ok: true,
            user: identity.handle,
            user_id: identity.accountId,
            team: identity.workspace,
          });
          return;
        }
        json(res, 200, { display_name: identity.handle, id: identity.accountId });
        return;
      }

      if (url.pathname === '/oauth/authorize') {
        // Never actually rendered in tests — the scripted "browser" calls the loopback
        // callback directly. Present so an authorize URL built by the engine is resolvable.
        json(res, 200, { ok: true, note: 'mock consent screen' });
        return;
      }

      json(res, 404, { error: 'not_found' });
    })().catch((error: unknown) => {
      violations.push(`mock AS threw: ${String(error)}`);
      try {
        json(res, 500, { error: 'mock_failure' });
      } catch {
        /* the socket is already gone; the violation is recorded */
      }
    });
  });

  await new Promise<void>((resolve) => server.listen(0, LOOPBACK_IP_HOST, resolve));
  const port = (server.address() as AddressInfo).port;
  const origin = `http://${LOOPBACK_IP_HOST}:${port}`;

  return {
    origin,
    tokenUrl: `${origin}/oauth/token`,
    authorizeUrl: `${origin}/oauth/authorize`,
    identityUrl: `${origin}/api/identity`,
    requests,
    counts,
    violations,
    current: () => ({ ...live }),
    failNext: (kind, error) => {
      pending[kind] = error;
    },
    setIdentity: (next) => {
      identity = { ...next };
    },
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

/** The identity the mock answers with, for assertions in the copy-deck tests. */
export const MOCK_IDENTITY = IDENTITY;
