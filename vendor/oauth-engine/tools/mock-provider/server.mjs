/**
 * A self-contained mock OAuth 2.0 authorization server — the thing that makes `make demo`
 * runnable with ZERO external registration. TOOLS-ONLY, never imported by engine/ or shipped.
 *
 * It is a *real* server, not a stub: it speaks the four things the engine actually exercises,
 * over real HTTP sockets, and it enforces the invariants the engine's whole custody story rests
 * on — so a green demo is proof the engine did the right thing, not proof the mock was lenient.
 *
 *   GET  /authorize   — the consent screen. Auto-APPROVES: it binds the PKCE challenge to a
 *                       freshly minted single-use code and 302-redirects to the loopback
 *                       redirect_uri (byte-identical to the one it was handed) with code+state.
 *                       This is the "user clicked Allow" beat, performed by the provider.
 *   POST /token       — code -> token AND refresh -> token. HONORS PKCE (S256): the exchange is
 *                       refused unless SHA-256(code_verifier) matches the bound code_challenge.
 *                       Refresh tokens ROTATE and are single-use, so a replayed refresh is dead.
 *   GET  /me          — the protected resource + identity probe. 200 with the identity when the
 *                       presented Bearer is the live access token; 401 once it has expired.
 *
 * Invariants asserted SERVER-SIDE (recorded in `violations`, empty === the engine behaved):
 *   - no `client_secret` ever reaches the token endpoint (this engine is architecturally
 *     secret-free — a public PKCE client);
 *   - the exchange's `redirect_uri` is BYTE-IDENTICAL to the authorize's (§A8/D6);
 *   - a PKCE exchange without a `code_verifier` is refused, never accepted;
 *   - an authorize request without a `code_challenge` is refused (no downgrade to no-PKCE).
 *
 * No provider-shaped token literals live in this file: `mock-access-N` / `mock-refresh-N` /
 * `mock-code-…` are deliberately un-credential-shaped so tools/scan-secrets.mjs stays quiet —
 * "it's only a mock" is what every leaked credential's commit message says.
 *
 * Zero runtime dependencies: node:http + node:crypto only.
 */

import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';

const DEFAULT_IDENTITY = {
  handle: 'Ada Lovelace',
  workspace: 'Handshake Demo Workspace',
  accountId: 'user_ada_1815',
};

/** RFC 7636 base64url (no padding). */
function base64url(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** The S256 code-challenge derivation the engine used at authorize time. */
function s256(verifier) {
  return base64url(createHash('sha256').update(verifier).digest());
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(Buffer.byteLength(body)),
    'cache-control': 'no-store',
  });
  res.end(body);
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * Start the mock provider. Resolves once it is listening. The returned handle exposes the URLs
 * the engine profile points at, the request counters + server-side `violations` for the demo's
 * closing assertions, and two demo controls (`expireAccessToken`, `close`).
 */
export async function startMockProvider(options = {}) {
  const identity = { ...DEFAULT_IDENTITY, ...(options.identity ?? {}) };
  const expiresIn = options.expiresIn ?? 3600; // seconds

  /** code -> { challenge, redirectUri, claimed } — one authorization code, used exactly once. */
  const codes = new Map();
  const counts = { authorize: 0, exchange: 0, refresh: 0, resource: 0, resource_401: 0 };
  const violations = [];

  let generation = 0;
  let live = null; // { access, refresh } — the currently valid pair
  let accessExpired = false; // demo control: server-side expiry of the access token only

  function rotate() {
    generation += 1;
    live = { access: `mock-access-${generation}`, refresh: `mock-refresh-${generation}` };
    accessExpired = false;
    return live;
  }

  const server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', `http://127.0.0.1`);

      // ── GET /authorize — auto-approve, bind PKCE, redirect to the loopback with a code ──
      if (url.pathname === '/authorize' && (req.method ?? 'GET') === 'GET') {
        counts.authorize += 1;
        const q = url.searchParams;
        const redirectUri = q.get('redirect_uri');
        const state = q.get('state');
        const challenge = q.get('code_challenge');
        const method = q.get('code_challenge_method');

        if (redirectUri === null || redirectUri === '') {
          sendJson(res, 400, { error: 'invalid_request', error_description: 'redirect_uri required' });
          return;
        }
        // No PKCE offered → refuse. A provider that let a public client skip PKCE would be the
        // downgrade this whole engine exists to make impossible.
        if (challenge === null || challenge === '') {
          violations.push('authorize request carried no code_challenge (PKCE downgrade)');
          const back = new URL(redirectUri);
          back.searchParams.set('error', 'invalid_request');
          if (state !== null) back.searchParams.set('state', state);
          res.writeHead(302, { location: back.toString() });
          res.end();
          return;
        }
        if (method !== 'S256') {
          violations.push(`authorize code_challenge_method was ${String(method)}, expected S256`);
        }

        const code = `mock-code-${base64url(randomBytes(18))}`;
        codes.set(code, { challenge, redirectUri, claimed: false });

        // The consent decision, made by the provider: Allow. In a real flow a human clicks the
        // button on the rendered page; here the mock approves and bounces straight back.
        const back = new URL(redirectUri);
        back.searchParams.set('code', code);
        if (state !== null) back.searchParams.set('state', state);
        res.writeHead(302, { location: back.toString() });
        res.end();
        return;
      }

      // ── POST /token — authorization_code exchange + refresh_token rotation ──
      if (url.pathname === '/token' && (req.method ?? 'POST') === 'POST') {
        const params = new URLSearchParams(await readBody(req));

        if (params.has('client_secret')) {
          violations.push('client_secret was sent to the token endpoint (engine must be secret-free)');
        }

        const grant = params.get('grant_type') ?? '';

        if (grant === 'authorization_code') {
          counts.exchange += 1;
          const code = params.get('code') ?? '';
          const record = codes.get(code);
          if (record === undefined) {
            sendJson(res, 400, { error: 'invalid_grant', error_description: 'unknown or reused code' });
            return;
          }
          if (record.claimed) {
            sendJson(res, 400, { error: 'invalid_grant', error_description: 'authorization code already used' });
            return;
          }
          const sentRedirect = params.get('redirect_uri');
          if (sentRedirect !== record.redirectUri) {
            violations.push(
              `exchange redirect_uri not byte-identical to authorize's (§A8): sent ${String(sentRedirect)}`,
            );
            sendJson(res, 400, { error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
            return;
          }
          const verifier = params.get('code_verifier') ?? '';
          if (verifier === '') {
            violations.push('token exchange carried no code_verifier (PKCE not honored)');
            sendJson(res, 400, { error: 'invalid_request', error_description: 'code_verifier required' });
            return;
          }
          if (s256(verifier) !== record.challenge) {
            sendJson(res, 400, { error: 'invalid_grant', error_description: 'PKCE verification failed' });
            return;
          }
          record.claimed = true;
          const pair = rotate();
          sendJson(res, 200, {
            access_token: pair.access,
            token_type: 'bearer',
            refresh_token: pair.refresh,
            expires_in: expiresIn,
            scope: (options.scopes ?? ['read']).join(' '),
          });
          return;
        }

        if (grant === 'refresh_token') {
          counts.refresh += 1;
          const presented = params.get('refresh_token');
          // Single-use rotation: only the newest refresh token is live; a replay is dead.
          if (live === null || presented !== live.refresh) {
            sendJson(res, 400, { error: 'invalid_grant', error_description: 'refresh token expired or reused' });
            return;
          }
          const pair = rotate();
          sendJson(res, 200, {
            access_token: pair.access,
            token_type: 'bearer',
            refresh_token: pair.refresh,
            expires_in: expiresIn,
            scope: (options.scopes ?? ['read']).join(' '),
          });
          return;
        }

        sendJson(res, 400, { error: 'unsupported_grant_type' });
        return;
      }

      // ── GET /me — protected resource + identity probe ──
      if (url.pathname === '/me' && (req.method ?? 'GET') === 'GET') {
        counts.resource += 1;
        const presented = (req.headers.authorization ?? '').replace(/^Bearer /i, '');
        if (live === null || presented !== live.access || accessExpired) {
          counts.resource_401 += 1;
          sendJson(res, 401, { error: 'invalid_token', error_description: 'the access token is expired or invalid' });
          return;
        }
        sendJson(res, 200, {
          ok: true,
          display_name: identity.handle,
          workspace: identity.workspace,
          account_id: identity.accountId,
        });
        return;
      }

      sendJson(res, 404, { error: 'not_found' });
    })().catch((error) => {
      violations.push(`mock provider threw: ${String(error)}`);
      try {
        sendJson(res, 500, { error: 'mock_failure' });
      } catch {
        /* socket already gone; the violation is recorded */
      }
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const origin = `http://127.0.0.1:${port}`;

  return {
    origin,
    authorizeUrl: `${origin}/authorize`,
    tokenUrl: `${origin}/token`,
    resourceUrl: `${origin}/me`,
    identity,
    counts,
    violations,
    /** The pair currently considered live (post-rotation). */
    current: () => (live === null ? null : { ...live }),
    /** How many times the token endpoint has rotated the pair (exchange + each refresh). */
    generation: () => generation,
    /**
     * Demo control: mark the current access token expired server-side, WITHOUT rotating — the
     * refresh token stays live. The next protected call presents a token the server now rejects
     * (401), which is exactly what the engine's silent-refresh-on-401 path exists to absorb.
     */
    expireAccessToken: () => {
      accessExpired = true;
    },
    close: () =>
      new Promise((resolve, reject) => {
        server.closeAllConnections();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

/**
 * Build the engine ProviderProfile that points at a running mock. Kept next to the server so the
 * endpoint paths live in exactly one place. This is a Custody Class A (public + PKCE) provider —
 * the class the engine proves fully on-device.
 */
export function mockProviderProfile(mock, name = 'handshake-demo') {
  return {
    name,
    display_name: 'Handshake Demo',
    client_id: 'mock.public.client',
    client_type: 'public',
    pkce: 'S256',
    redirect_strategy: 'loopback',
    redirect_host: 'localhost',
    redirect_ports: [33418, 33419, 33420],
    authorize_url: mock.authorizeUrl,
    token_url: mock.tokenUrl,
    api_base: mock.origin,
    scopes: ['read'],
    scope_param: 'scope',
    scope_delimiter: ' ',
    token_auth: 'none',
    refresh_auth: 'client_id_body',
    token_path: 'access_token',
    refresh_token_path: 'refresh_token',
    expires_in_path: 'expires_in',
    refresh: 'rotation',
    rotation: 'optional-enabled',
    access_token_ttl: 3600,
    identity_probe: {
      url: mock.resourceUrl,
      method: 'GET',
      auth: 'bearer',
      success_predicate: { path: 'ok', equals: true },
      handle_path: 'display_name',
      workspace_path: 'workspace',
      account_id_path: 'account_id',
    },
  };
}
