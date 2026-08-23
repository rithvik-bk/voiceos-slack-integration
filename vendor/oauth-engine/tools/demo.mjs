#!/usr/bin/env node
/**
 * `make demo` — the "it works end to end, run it yourself" proof.
 *
 * Clone the repo, run this, watch the whole OAuth dance happen against a REAL local
 * authorization server with ZERO external registration: no dev-app, no client secret, no
 * account anywhere. A self-contained mock provider (tools/mock-provider/) plays the other
 * side; this script drives the REAL engine against it through nothing but its PUBLIC API
 * (connect · auth.client · getToken · disconnect · setPlatformHooks) and narrates every beat.
 *
 * The run of show:
 *   1. start the mock provider (a real HTTP authorization server on a loopback port)
 *   2. connect() — opens the flow; the mock auto-approves by redirecting to the loopback with a
 *      code; the engine exchanges it (PKCE-verified), probes identity, and vaults the token
 *   3. auth.client("…").get("/me") — a call to the protected resource succeeds with the token
 *      the author never saw
 *   4. force the access token to expire server-side, then call /me again — the engine SILENTLY
 *      refreshes (rotating the pair) and retries, and the call succeeds again
 *
 * The token that authorizes those calls is never a variable in this file. That absence is the
 * product.
 *
 * The one seam we drive is `setPlatformHooks({ openUrl })`: in production it hands the URL to
 * the user's browser; here it hands it to `fetch`, which follows the mock's redirect. That is
 * the whole simulation — everything downstream is the shipping engine, unmodified.
 */

import {
  auth,
  connect,
  disconnect,
  getConnectStatus,
  getToken,
  setPlatformHooks,
  resetPlatformHooks,
} from '../engine/src/index.ts';
import { startMockProvider, mockProviderProfile } from './mock-provider/server.mjs';

const PROVIDER = 'handshake-demo';

/* ── a tiny narrated timeline ──────────────────────────────────────────────────────────── */

const t0 = Date.now();
const stamp = () => `+${String(Date.now() - t0).padStart(4, ' ')}ms`;
function step(n, title) {
  console.log(`\n\x1b[1m${n}\x1b[0m  \x1b[1m${title}\x1b[0m`);
}
function beat(text) {
  console.log(`   \x1b[2m${stamp()}\x1b[0m  ${text}`);
}
function ok(text) {
  console.log(`   \x1b[2m${stamp()}\x1b[0m  \x1b[32m✓\x1b[0m ${text}`);
}
function fail(text) {
  console.log(`   \x1b[2m${stamp()}\x1b[0m  \x1b[31m✗\x1b[0m ${text}`);
}

/** Poll the status board the way the integration's `auth_status` tool does. */
async function waitForPhase(connectId, phases, ms = 8000) {
  const deadline = Date.now() + ms;
  for (;;) {
    const status = await getConnectStatus(connectId);
    if (phases.includes(status.phase)) return status;
    if (Date.now() > deadline) throw new Error(`connect stuck in phase "${status.phase}"`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

async function main() {
  console.log('\x1b[1mHANDSHAKE — end-to-end demo\x1b[0m');
  console.log('\x1b[2mReal engine · real HTTP OAuth · built-in mock provider · zero external registration\x1b[0m');

  const mock = await startMockProvider();
  const profile = mockProviderProfile(mock, PROVIDER);

  // The only seam we drive: hand the authorize URL to `fetch` (which follows the mock's 302)
  // instead of a real browser. `activateApp` is a no-op here — there is no app to pull forward.
  setPlatformHooks({
    // Fire-and-forget, exactly like handing a URL to a real browser: `connect()` awaits
    // openUrl BEFORE it arms the loopback's callback waiter, and the loopback PARKS an early
    // callback without responding until that waiter exists — so awaiting the redirect here
    // would deadlock. We kick the navigation off and return, and the engine drains the parked
    // callback the moment it starts listening.
    openUrl: async (url) => {
      void fetch(url).catch(() => {}); // /authorize -> 302 -> loopback /callback?code=…&state=…
    },
    activateApp: async () => {},
  });

  // Start clean so a re-run is deterministic (the token is vaulted in the OS keychain).
  await disconnect(PROVIDER).catch(() => undefined);

  try {
    step('1', 'Start the mock authorization server');
    beat(`authorize : ${mock.authorizeUrl}`);
    beat(`token     : ${mock.tokenUrl}`);
    beat(`resource  : ${mock.resourceUrl}`);
    ok(`listening on ${mock.origin} — no registration, no secret, no account`);

    step('2', 'connect() — open the flow, auto-approve, exchange, vault');
    const seen = [];
    const first = await connect(profile, {
      onStatus: (s) => {
        seen.push(s.phase);
        if (s.spoken !== undefined) beat(`\x1b[36m${s.phase}\x1b[0m — "${s.spoken}"`);
        else beat(`\x1b[36m${s.phase}\x1b[0m`);
      },
    });
    beat(`connect() returned in phase "${first.phase}" while the flow completes out of band`);
    const connected = await waitForPhase(first.connect_id, ['connected']);
    ok(
      `connected as \x1b[1m${connected.identity.handle}\x1b[0m` +
        (connected.identity.workspace ? ` in \x1b[1m${connected.identity.workspace}\x1b[0m` : '') +
        ' — via the identity probe, never an HTTP 200',
    );
    if (mock.violations.length > 0) throw new Error(`provider recorded violations: ${mock.violations.join('; ')}`);
    ok('token vaulted in the OS keychain (PKCE-verified exchange, no secret on the wire)');

    step('3', 'auth.client() — call the protected resource with a token this code never sees');
    const api = auth.client(PROVIDER);
    const r1 = await api.get('/me');
    const body1 = await r1.json();
    const tokenBefore = await getToken(PROVIDER);
    beat(`GET /me -> ${r1.status}  ${JSON.stringify(body1)}`);
    beat(`live access token is now "${tokenBefore}" (exchanged, generation ${mock.generation()})`);
    ok(`protected call succeeded — ${mock.counts.refresh} refreshes so far`);

    step('4', 'Force a silent refresh — expire the access token, then call again');
    mock.expireAccessToken();
    beat('the mock now rejects the current access token (server-side expiry); refresh token stays live');
    const r2 = await api.get('/me');
    const body2 = await r2.json();
    const tokenAfter = await getToken(PROVIDER);
    beat(`GET /me -> ${r2.status}  ${JSON.stringify(body2)}`);
    beat(`live access token is now "${tokenAfter}" (rotated by the silent refresh)`);
    if (mock.counts.refresh !== 1) throw new Error(`expected exactly 1 silent refresh, saw ${mock.counts.refresh}`);
    if (tokenAfter === tokenBefore) throw new Error('the access token did not rotate on refresh');
    if (r2.status !== 200 || body2.ok !== true) throw new Error('the post-refresh call did not succeed');
    ok('401 -> silent refresh (rotated) -> retry -> 200, and the caller never knew');

    console.log('\n\x1b[1mSummary\x1b[0m');
    console.log(`   phases           : ${seen.join(' -> ')} -> connected`);
    console.log(`   token exchanges  : ${mock.counts.exchange}`);
    console.log(`   silent refreshes : ${mock.counts.refresh}`);
    console.log(`   protected calls  : ${mock.counts.resource} (${mock.counts.resource_401} first-try 401s absorbed by refresh)`);
    console.log(`   provider violations : ${mock.violations.length === 0 ? 'none' : mock.violations.join('; ')}`);
    console.log('\n\x1b[32m\x1b[1mDEMO PASSED\x1b[0m — connect -> vault -> call -> silent refresh -> call, end to end.\n');
  } catch (error) {
    fail(String(error instanceof Error ? error.message : error));
    console.log('\n\x1b[31m\x1b[1mDEMO FAILED\x1b[0m\n');
    process.exitCode = 1;
  } finally {
    await disconnect(PROVIDER).catch(() => undefined);
    resetPlatformHooks();
    await mock.close();
  }
}

await main();
