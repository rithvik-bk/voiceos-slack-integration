/**
 * P1-I7 — the engine's entire public API.
 *
 * This file is the contract an integration is allowed to depend on. It is deliberately
 * three verbs wide:
 *
 *     connect(profile)      start the dance   → returns in ≲1s, finishes out of band
 *     getToken(provider)    a fresh token     → refresh happens behind this call
 *     disconnect(provider)  forget everything → vault entry destroyed
 *
 * plus `getConnectStatus(connect_id)` for the poll the two-phase design requires: their
 * client enforces a 60s per-tool timeout and a 30s connect gate, so a tool call may never
 * block on a human clicking Allow.
 *
 * A tool built on top of this engine reads as if auth does not exist. That is the point:
 * the auth cost of the next integration is zero lines.
 *
 * THE ORDER OF OPERATIONS IN `connect` IS THE DESIGN, not an implementation detail:
 *   bind the loopback  →  build the authorize URL around the port we ACTUALLY bound
 *                      →  open the browser  →  RETURN (phase: launching-browser)
 *                      →  …out of band: callback → exchange → identity probe → vault
 * Binding first is what makes the ladder safe: a consent screen whose redirect lands on a
 * dead port fails with no error message anywhere (D6). Returning before the human acts is
 * what keeps the tool inside their timeout.
 */

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import {
  deriveAccountId,
  emptyIndex,
  resolveAccount,
  resolveAccountOrThrow,
  toAccountRef,
  upsertAccount,
} from './account.ts';
import { buildAuthorizeUrl } from './authorize.ts';
import { deleteClientCredentials } from './byos.ts';
import { createAuthClient, type AuthClient, type AuthClientOptions } from './client.ts';
import {
  CONNECT_TIMEOUT_MS,
  IP_REDIRECT_URIS,
  LOOPBACK_IP_HOST,
  REDIRECT_HOST,
  REDIRECT_URIS,
} from './config.ts';
import * as copy from './copy.ts';
import { applyRegisteredClient, deleteRegisteredClient, ensureRegisteredClient } from './dcr.ts';
import {
  pollForDeviceToken,
  requestDeviceAuthorization,
  selectGrantPath,
  type DeviceAuthorization,
} from './device.ts';
import { EngineError } from './errors.ts';
import { exchangeCode } from './exchange.ts';
import {
  createHealthMonitor,
  type HealthDeps,
  type HealthMonitor,
  type HealthMonitorOptions,
  type HealthTarget,
} from './health.ts';
import { probeIdentity } from './identity.ts';
import { openLoopback } from './loopback.ts';
import { bindFlow } from './mixup.ts';
import * as obs from './observability.ts';
import { generatePkce } from './pkce.ts';
import { getFreshToken } from './refresh.ts';
import { normalizeScopes, unionScopes } from './scope.ts';
import { DEFAULT_ACCOUNT, admit, begin, complete } from './singleflight.ts';
import { mintState } from './state.ts';
import {
  deleteAccountIndex,
  deleteToken,
  putToken,
  readAccountIndex,
  readToken,
  writeAccountIndex,
} from './vault.ts';
import type { ConnectErrorCode, ConnectStatus, ProviderProfile, TokenRecord } from './types.ts';

export type {
  ClientType,
  ConnectErrorCode,
  ConnectPhase,
  ConnectStatus,
  EngineErrorCode,
  IdentityProbe,
  PkceMode,
  ProviderProfile,
  RateLimit,
  RedirectStrategy,
  RefreshAuth,
  RefreshModel,
  RotationMode,
  ScopeParam,
  SuccessPredicate,
  TokenAuth,
  TokenRecord,
} from './types.ts';

export { renderPage, esc, clip } from './ui/pages.ts';
export type { PageOptions, PageState } from './ui/pages.ts';

/**
 * The only error type the engine throws across its public boundary. Defined in `errors.ts`
 * (a leaf module, so every layer can throw it without an import cycle) and re-exported here
 * because this file is the published surface. One class, one `instanceof`.
 */
export { EngineError } from './errors.ts';

/**
 * C-13 multi-account surface. `getToken(provider, account)` may throw `AccountAmbiguousError`
 * (an `EngineError` carrying `.candidates`) when several accounts exist and none was selected.
 */
export { AccountAmbiguousError } from './account.ts';
export type { AccountRef, AccountIndex, AccountResolution } from './account.ts';

/** An authenticated `fetch` with silent refresh — the lower-level primitive `auth.client()` sits on. */
export { authorizedFetch } from './refresh.ts';

/**
 * C-21 — `auth.client()`, the zero-auth-code wrapper (SPEC §18). `client.ts` takes its profile
 * resolver as an injected dependency (this file imports it, so it cannot import back), so the
 * public {@link client} below wires {@link createAuthClient} with the same `resolveProfile`
 * `getToken()` uses. Re-exported types let a tool `catch (e) { if (e instanceof TaxonomyError) … }`.
 */
export { TaxonomyError } from './client.ts';
export type { AuthClient, AuthClientOptions, ClientRequestInit, StepUpCard } from './client.ts';
export { probeIdentity } from './identity.ts';
export type { Identity } from './identity.ts';
export * as copy from './copy.ts';

/**
 * C-17 — the RFC 8628 device authorization grant, exposed for headless callers and for tests. The
 * grant is selected automatically inside {@link connect} via `options.headless`; these are the
 * lower-level pieces (the grant-path selector, the two device-flow phases) for anyone driving it
 * directly.
 */
export { selectGrantPath, requestDeviceAuthorization, pollForDeviceToken, runDeviceGrant } from './device.ts';
export type { GrantPath, DeviceAuthorization, DevicePollOptions } from './device.ts';

/**
 * C-14 error taxonomy. `ConnectErrorCode` (6) stays the product-surface render contract;
 * `TaxonomyCode` (9) is the closed set tool code branches on. Bridge at a throw site with
 * `normalizeEngineError(err)`, or `normalize({status, providerError, engineCode})` at an HTTP
 * boundary.
 */
export {
  normalize,
  normalizeEngineError,
  recommendedAction,
  fromEngineCode,
  fromOAuthError,
  fromHttpStatus,
  TAXONOMY_CODES,
} from './taxonomy.ts';
export type { TaxonomyCode, NormalizedError, NormalizeInput } from './taxonomy.ts';

/**
 * C-23 — observability (SPEC §16, §29). The credential-free auth-event log and the metrics
 * computed from it: connect success rate per provider, time-to-token p50/p95, silent-refresh
 * rate, and the ranked "needs attention" list. `connect()`/`disconnect()` (this file) and
 * `getFreshToken()` (refresh.ts) and the health probe (health.ts) all funnel writes through
 * `observability.record`, so INV-OBS-1 ("no credential in the log") is a property of one place.
 */
export {
  metrics,
  metricsFor,
  log as authEventLog,
  subscribe as subscribeAuthEvents,
  percentile,
} from './observability.ts';
export type {
  AuthEvent,
  AuthEventType,
  AuthOutcome,
  Metrics,
  ProviderMetrics,
} from './observability.ts';

/**
 * C-12 — background token-health probe (SPEC §10). {@link startHealthMonitor} wires the loop to
 * the engine's real vault + identity probe with a conservative default budget; the lower-level
 * pieces (the pure {@link shouldProbe} decision, {@link runProbe}, the {@link HealthMonitor}
 * class) are exposed for a host that wants to drive the discipline itself or test it with a fake
 * clock.
 */
export {
  createHealthMonitor,
  HealthMonitor,
  shouldProbe,
  runProbe,
  configFor as healthConfigFor,
} from './health.ts';
export type {
  HealthConfig,
  HealthGates,
  HealthState,
  HealthStatus,
  HealthTarget,
  HealthDeps,
  HealthMonitorOptions,
  ProbeDecision,
  ProbeReport,
} from './health.ts';

export interface ConnectOptions {
  /** Abort the dance early (tool cancelled, app quitting). */
  signal?: AbortSignal;
  /** Fires on every phase transition. Drives the spoken copy deck; never generates text. */
  onStatus?: (status: ConnectStatus) => void;
  /** Overrides CONNECT_TIMEOUT_MS from config.ts. Demo default: 120s. */
  timeoutMs?: number;
  /** Force a fresh consent even if a valid token is vaulted (the "switch account" path). */
  force?: boolean;
  /**
   * C-13/C-16 — which account this connect targets. Selects the single-flight slot (a second
   * connect for the same provider+account supersedes the first) and the already-connected
   * lookup. A brand-new account's stable id is discovered by the identity probe regardless of
   * this hint, so connecting a fresh workspace needs no selector.
   */
  account?: string;
  /**
   * C-11 — scope step-up. Scopes to request BEYOND the profile's base set. The authorize
   * request carries the UNION of base ∪ already-granted ∪ these (unless the provider is
   * `scope_grant: 'incremental'`, which may request the delta alone), so a re-connect that
   * adds a scope never drops the scopes already granted — the union rule from SPEC §9.
   */
  scopes?: string[];
  /**
   * C-17 — force the RFC 8628 device authorization grant instead of the loopback path, for a
   * headless / no-loopback context (no browser to open, no port to bind: CI, SSH, a kiosk, or a
   * provider that refuses loopback redirects). Requires `device_flow: 'rfc8628'` in the profile;
   * otherwise the connect fails with a config error rather than silently attempting a browser flow
   * that cannot complete. When false/absent, the preferred loopback path is used unchanged.
   */
  headless?: boolean;
}

/* ────────────────────────────── platform seams (testable) ────────────────────────────── */

/**
 * The two things this engine does to the machine rather than to the network. They are
 * injectable for exactly one reason: a test suite that launches a real browser and yanks
 * focus to a real app is a test suite nobody runs twice.
 */
export interface PlatformHooks {
  /** Hand a URL to the user's default browser. */
  openUrl(url: string): Promise<void>;
  /** Pull VoiceOS back in front after the callback lands (D5). Best-effort, never fatal. */
  activateApp(): Promise<void>;
}

/** D5, verified on this machine: `osascript -e 'id of app "VoiceOS"'` → com.voiceos.app. */
const VOICEOS_BUNDLE_ID = 'com.voiceos.app';

function runDetached(args: readonly string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn('/usr/bin/open', [...args], { stdio: 'ignore' });
    child.once('error', reject);
    child.once('close', (code) =>
      code === 0 ? resolve() : reject(new Error(`open exited ${String(code)}`)),
    );
  });
}

const DEFAULT_HOOKS: PlatformHooks = {
  openUrl: (url) => runDetached([url]),
  // Best-effort by contract: a machine without VoiceOS installed still completes a connect.
  activateApp: () => runDetached(['-b', VOICEOS_BUNDLE_ID]).catch(() => undefined),
};

let hooks: PlatformHooks = { ...DEFAULT_HOOKS };

/** Test seam. Production never calls this. */
export function setPlatformHooks(overrides: Partial<PlatformHooks>): void {
  hooks = { ...hooks, ...overrides };
}

/** Test seam. Restores the real browser/app behaviour. */
export function resetPlatformHooks(): void {
  hooks = { ...DEFAULT_HOOKS };
}

/* ─────────────────────────────── the provider registry ─────────────────────────────── */

const registry = new Map<string, ProviderProfile>();

/**
 * Teach the engine about a provider so `getToken(name)` works from a tool that only
 * knows a name. `connect()` registers automatically; an integration that starts up already
 * connected calls this once at boot with its own provider.json.
 */
export function registerProvider(profile: ProviderProfile): void {
  registry.set(profile.name, profile);
}

/**
 * Resolve a provider's profile exactly the way `getToken()` does in a fresh process —
 * registry first, then the on-disk candidate layouts. Exposed (additively — the frozen
 * P1-I7 surface is untouched) so the install test can prove profile resolution works from
 * inside the INSTALLED folder, whose real home (`~/Library/Application Support/…`) contains
 * a space that `.pathname` used to percent-encode into a nonexistent path. No vault, no
 * network: this reads at most three JSON files.
 */
export async function resolveProviderProfile(provider: string): Promise<ProviderProfile> {
  return resolveProfile(provider);
}

/**
 * Optional on-disk fallback for callers who do not register their profile in-process.
 * The preferred path is always `registerProvider(profile)`; these locations let a host
 * that vendors the engine next to its own config resolve a profile without that call.
 * Point the loader at wherever your own `provider.json` lives by placing it at one of
 * these relative locations, or skip the file entirely and register the parsed object.
 */
function profileCandidates(provider: string): string[] {
  const here = new URL('./', import.meta.url);
  // fileURLToPath, NEVER `.pathname`: an installed layout can live under a path with a
  // space (e.g. `~/Library/Application Support/…`), and `.pathname` keeps the space
  // percent-encoded (`Application%20Support`) — a path that does not exist on disk. That
  // single character made every fresh-process `getToken()` in such a folder throw
  // `config_invalid`, so resolution goes through fileURLToPath.
  return [
    fileURLToPath(new URL(`../${provider}/provider.json`, here)),
    fileURLToPath(new URL(`../provider.json`, here)),
    fileURLToPath(new URL(`../../provider.json`, here)),
  ];
}

async function resolveProfile(provider: string): Promise<ProviderProfile> {
  const known = registry.get(provider);
  if (known !== undefined) return known;

  for (const path of profileCandidates(provider)) {
    try {
      const parsed = JSON.parse(await readFile(path, 'utf8')) as ProviderProfile;
      if (parsed.name === provider) {
        registry.set(provider, parsed);
        return parsed;
      }
    } catch {
      // Not there, or not ours. Try the next layout.
    }
  }

  throw new EngineError('config_invalid', `no provider profile for '${provider}'`, {
    hint: `Call registerProvider() with the parsed provider.json, or point the loader at your own config path (see profileCandidates()).`,
  });
}

/* ───────────────────────────────── the status board ───────────────────────────────── */

/** Bounded on purpose: a long-lived MCP process must not accumulate connect records. */
const MAX_TRACKED = 50;
const statuses = new Map<string, ConnectStatus>();

function publish(status: ConnectStatus, onStatus?: (s: ConnectStatus) => void): ConnectStatus {
  statuses.set(status.connect_id, status);
  while (statuses.size > MAX_TRACKED) {
    const oldest = statuses.keys().next().value;
    if (oldest === undefined) break;
    statuses.delete(oldest);
  }
  // C-23: every terminal ERROR is recorded here, once, so no failure path has to remember to.
  // The success paths (`connected`/`already_connected`) are recorded at their own sites, which
  // is where a fresh mint can be told from a cache hit for the time-to-token metric.
  if (status.phase === 'error') {
    const code = status.error?.code;
    const outcome = code === 'denied_by_user' ? 'denied' : code === 'timeout' ? 'timeout' : 'error';
    obs.recordConnectResult(
      status.connect_id,
      status.provider,
      outcome,
      code === undefined ? {} : { errorCode: code },
    );
  }
  onStatus?.(status);
  return status;
}

function errorStatus(
  connectId: string,
  profile: ProviderProfile,
  code: ConnectErrorCode,
  providerMessage?: string,
): ConnectStatus {
  return {
    phase: 'error',
    connect_id: connectId,
    provider: profile.name,
    spoken: copy.errorLine(code, profile.display_name, providerMessage),
    error: {
      code,
      hint: copy.errorHint(code),
      ...(providerMessage === undefined ? {} : { provider_message: providerMessage }),
    },
  };
}

/** Every internal failure becomes one of the six codes the product surface can render. */
function toConnectErrorCode(error: unknown): ConnectErrorCode {
  if (!(error instanceof EngineError)) return 'provider_error';
  switch (error.code) {
    case 'denied_by_user':
    case 'port_blocked':
    case 'expired_or_revoked':
    case 'state_mismatch':
    case 'timeout':
    case 'provider_error':
      return error.code;
    default:
      // not_implemented / config_invalid / vault_unavailable / refresh_failed / not_connected
      // are engineering faults. They are still shown, with the provider's voice, never as a
      // silent success.
      return 'provider_error';
  }
}

/* ────────────────────────────────────── connect ────────────────────────────────────── */

/**
 * Start the OAuth dance for `profile`.
 *
 * Returns as soon as the browser has been handed the authorize URL — phase
 * `launching-browser`, carrying the `connect_id` the caller polls with. The exchange,
 * vault write and identity probe complete out of band; the terminal status is delivered
 * through `onStatus` and readable via {@link getConnectStatus}.
 *
 * Never resolves to `phase: 'connected'` on an HTTP 200 alone — only after the provider's
 * identity probe returns a handle.
 */
export async function connect(
  profile: ProviderProfile,
  options: ConnectOptions = {},
): Promise<ConnectStatus> {
  registerProvider(profile);
  const connectId = `c_${randomBytes(6).toString('hex')}`;
  // C-23: mark the start of this connect so its terminal outcome can be measured as a true
  // time-to-token. A cache hit below still records an `already_connected` result (a success),
  // but only a fresh mint contributes a time-to-token sample.
  obs.recordConnectAttempt(connectId, profile.name, options.account);

  // Already connected? Say so instead of making the user re-approve. `force` is the
  // "switch account" path and skips this.
  //
  // "Already connected" means a record that can still produce a token: either it has not
  // expired, or it holds a refresh token that getToken() can spend. A dead record with no
  // way back must fall through to a real consent — otherwise the user is told they are
  // connected and the very next tool call fails.
  // C-13: resolve the target account against the stored index. With no selector and a single
  // connected account this is that account; an ambiguous multi-account provider does NOT
  // short-circuit — it falls through to a real (account-selecting) consent rather than guessing.
  if (options.force !== true) {
    const index = await readAccountIndex(profile.name).catch(() => emptyIndex());
    const resolution = resolveAccount(index, options.account);
    // Where to read the already-connected record. The account index is the primary path; the
    // LEGACY BARE-SLOT FALLBACK (mirroring getToken) covers a pre-wave-2 record written under the
    // bare provider key before the index existed. Without it a live legacy credential is invisible
    // here, so the user is forced through a full re-consent for a connection they already hold.
    let vaulted: TokenRecord | null = null;
    let hitAccountId: string | undefined;
    if (resolution.ok) {
      vaulted = await readToken(profile.name, resolution.account.accountId).catch(() => null);
      hitAccountId = resolution.account.accountId;
    } else if (index.accounts.length === 0) {
      // No index at all → try the legacy bare slot (no account id to record).
      vaulted = await readToken(profile.name).catch(() => null);
    }
    const recoverable =
      vaulted !== null &&
      (vaulted.refresh_token !== undefined ||
        vaulted.expires_at === undefined ||
        vaulted.expires_at > Date.now());
    if (vaulted !== null && recoverable && vaulted.identity !== undefined) {
      obs.recordConnectResult(
        connectId,
        profile.name,
        'already_connected',
        hitAccountId === undefined ? {} : { accountId: hitAccountId },
      );
      return publish(
        {
          phase: 'connected',
          connect_id: connectId,
          provider: profile.name,
          spoken: copy.connected(vaulted.identity.handle, vaulted.identity.workspace),
          identity: vaulted.identity,
        },
        options.onStatus,
      );
    }
  }

  // Grant-path selection (SPEC §3): a headless / no-loopback context takes the RFC 8628 device
  // grant when the provider advertises it; everything else takes the preferred loopback path. The
  // selector keys off capability values, never a provider name (INV-CONFIG-1). A headless request
  // against a provider with no device grant throws config_invalid, surfaced here rather than thrown
  // across the public boundary.
  // C-16(c): the single-flight slot keys off the RESOLVED account id, not the raw selector, so
  // different spellings of the same account supersede each other rather than racing in two slots.
  // Resolved once here and shared by both grant paths (loopback below, device in connectDevice).
  const flowAccount = await resolveFlowAccountId(profile.name, options.account);

  let grantPath;
  try {
    grantPath = selectGrantPath(profile, { headless: options.headless === true });
  } catch (error) {
    return publish(
      errorStatus(connectId, profile, toConnectErrorCode(error), providerMessageOf(error)),
      options.onStatus,
    );
  }
  if (grantPath === 'device') {
    return connectDevice(connectId, profile, options, flowAccount);
  }

  // The host STRING is a profile axis (Zoom's form rejects the literal word `localhost`,
  // C-ZM-24); the socket is the same either way (§A3).
  const host = profile.redirect_host === LOOPBACK_IP_HOST ? LOOPBACK_IP_HOST : REDIRECT_HOST;

  let loopback;
  try {
    loopback = await openLoopback({
      provider: profile.display_name,
      host,
      // C-3: the stable profile name, for the mix-up binding lookup at callback time.
      providerName: profile.name,
      ...(profile.brand_icon === undefined ? {} : { providerIcon: profile.brand_icon }),
    });
  } catch (error) {
    return publish(
      errorStatus(connectId, profile, toConnectErrorCode(error)),
      options.onStatus,
    );
  }

  // C-8, Custody Class C: a dcr-capable provider ships with NO pre-registered client_id. Self-
  // register one per RFC 7591 (dcr.ts), store it on-device, and run the rest of the flow against
  // that client_id — exactly as if a client id had been pasted in. The full ladder of redirect
  // URIs is registered (not just the port we bound) so any bound rung matches this client (§7).
  // Registration happens only when there is no already-connected token to short-circuit on, so a
  // reconnect with a live credential never touches the endpoint. `authProfile` carries the minted
  // client_id (and, if the provider issued a secret, the confidential wire modes) into authorize
  // and exchange; every other selection below keys off the stable provider name and is unchanged.
  let authProfile = profile;
  if (profile.dcr === 'rfc7591') {
    const redirectUris =
      profile.redirect_host === LOOPBACK_IP_HOST ? [...IP_REDIRECT_URIS] : [...REDIRECT_URIS];
    try {
      const client = await ensureRegisteredClient(profile, { redirectUris });
      authProfile = applyRegisteredClient(profile, client);
    } catch (error) {
      await loopback.close();
      return publish(
        errorStatus(connectId, profile, toConnectErrorCode(error), providerMessageOf(error)),
        options.onStatus,
      );
    }
  }

  const pkce = generatePkce();
  const state = mintState();
  // C-3: bind this state to the provider (and issuer, when the profile publishes one) that
  // minted it, so a mix-up response from a different AS cannot satisfy this flow.
  bindFlow(state, profile.name, {
    ...(profile.issuer === undefined ? {} : { issuer: profile.issuer }),
    ...(profile.authorization_response_iss_parameter_supported ? { issRequired: true } : {}),
  });

  // C-16: register this flow in the single-flight slot for (provider, account). A second
  // connect() for the same slot supersedes this one — its state stops being admissible and its
  // teardown closes this listener — so two Connect clicks can never leave two listeners racing
  // for one callback. Admission is authoritative (checked again after the callback lands);
  // teardown is advisory.
  begin(profile.name, state, {
    account: flowAccount,
    teardown: () => {
      void loopback.close();
    },
  });

  // C-11: the scope set the authorize request carries. With no step-up the profile's scopes are
  // sent verbatim (order preserved — several providers echo the requested order). A step-up
  // (`options.scopes`) applies the union rule: request base ∪ already-granted ∪ requested unless
  // the provider is genuinely `incremental`, so re-consenting to add a scope never drops one.
  const authorizeProfile = await scopedProfile(authProfile, options);
  const authorizeUrl = buildAuthorizeUrl(authorizeProfile, {
    redirectUri: loopback.redirectUri,
    state,
    ...(profile.pkce === 'S256' ? { challenge: pkce.challenge } : {}),
  });

  try {
    await hooks.openUrl(authorizeUrl);
  } catch (error) {
    complete(state);
    await loopback.close();
    return publish(
      publishOpenFailure(connectId, profile, error),
      options.onStatus,
    );
  }

  const status = publish(
    {
      phase: 'launching-browser',
      connect_id: connectId,
      provider: profile.name,
      spoken: copy.openingBrowser(profile.display_name),
    },
    options.onStatus,
  );

  // Out of band, deliberately not awaited: the human is the slow part, and their client
  // gives a tool 60 seconds. Failures land on the status board, never as an unhandled
  // rejection — a crashed MCP server would take the whole integration down with it.
  void finishConnect(connectId, authProfile, loopback, pkce.verifier, state, options).catch(
    (error: unknown) => {
      publish(
        errorStatus(connectId, profile, toConnectErrorCode(error), providerMessageOf(error)),
        options.onStatus,
      );
    },
  );

  return status;
}

function providerMessageOf(error: unknown): string | undefined {
  return error instanceof EngineError ? error.providerMessage : undefined;
}

/**
 * C-16 — the account this connect's single-flight slot occupies, RESOLVED to the stable account
 * id rather than the raw selector STRING the caller passed. Two spellings of one connected account
 * (its opaque id, its handle, `handle@workspace`) must land on ONE slot so a second connect
 * supersedes the first instead of racing it in a separate slot. An unresolvable selector — a
 * not-yet-connected account, or an empty index — falls back to the raw selector (spelling-to-
 * spelling is the best available match) or the default slot when none was given, which is exactly
 * the prior behaviour.
 */
async function resolveFlowAccountId(providerName: string, selector?: string): Promise<string> {
  const index = await readAccountIndex(providerName).catch(() => emptyIndex());
  const resolution = resolveAccount(index, selector);
  return resolution.ok ? resolution.account.accountId : (selector ?? DEFAULT_ACCOUNT);
}

/**
 * C-11 — the profile whose `scopes` the authorize request will carry, applying the SPEC §9
 * step-up rules ONLY when the caller asks for extra scopes.
 *
 * No step-up → the profile is returned untouched, so its scopes reach the URL in their authored
 * order (asserted by connect-flow's `%20`-serialization test). With `options.scopes`:
 *   - a genuinely `incremental` provider may request the delta (the new scopes) alone;
 *   - every other provider (`exact`/`downgradeable`/`unknown`/absent) re-requests the UNION of
 *     the base scopes, whatever the target account was already granted, and the new scopes —
 *     because re-consenting with the delta alone silently drops the prior grant on many
 *     providers. The already-granted set is read from the resolved account's vaulted record.
 */
async function scopedProfile(
  profile: ProviderProfile,
  options: ConnectOptions,
): Promise<ProviderProfile> {
  const requested = normalizeScopes(options.scopes ?? []);
  if (requested.length === 0) return profile;

  let granted: string[] = [];
  const index = await readAccountIndex(profile.name).catch(() => emptyIndex());
  const resolution = resolveAccount(index, options.account);
  if (resolution.ok) {
    const record = await readToken(profile.name, resolution.account.accountId).catch(() => null);
    if (record !== null) granted = record.scopes;
  } else if (index.accounts.length === 0) {
    // LEGACY BARE-SLOT FALLBACK (mirrors getToken / the connect short-circuit): a pre-wave-2 record
    // under the bare provider key carries the already-granted scopes. Without this a step-up
    // re-consent unions against an empty set and silently DROPS the scopes the legacy token already
    // holds — the SPEC §9 union rule violated for exactly the account that most needs it preserved.
    const record = await readToken(profile.name).catch(() => null);
    if (record !== null) granted = record.scopes;
  }

  const scopes =
    profile.scope_grant === 'incremental'
      ? requested
      : unionScopes(profile.scopes, granted, requested);
  return { ...profile, scopes };
}

/**
 * We could not hand the authorize URL to a browser.
 *
 * FIXED 2026-08-16 (audit fix round 1, LOW finding). This used to be spoken through the
 * `provider_error` row — "Slack turned that down: <the OS error>. Nothing was connected." —
 * which is a false statement about Slack, said out loud, about a failure that happened
 * entirely on this machine. It now speaks its own ratified deck row, and the local error
 * text is NOT passed off as the provider's words: `provider_message` is the provider's
 * verbatim spelling or it is absent.
 *
 * The machine-facing `code` stays `provider_error` deliberately: `ConnectErrorCode` is
 * frozen at six values by the Phase-1 status contract, and correcting the sentence does not
 * need a seventh. The hint carries the real reason for whoever is debugging.
 */
function publishOpenFailure(
  connectId: string,
  profile: ProviderProfile,
  error: unknown,
): ConnectStatus {
  const reason = error instanceof Error ? error.message : 'the browser could not be opened';
  const status = errorStatus(connectId, profile, 'provider_error');
  status.spoken = copy.BROWSER_OPEN_FAILED;
  status.error = {
    code: 'provider_error',
    hint: `Could not hand the authorize URL to a browser: ${reason}`,
  };
  return status;
}

async function finishConnect(
  connectId: string,
  profile: ProviderProfile,
  loopback: Awaited<ReturnType<typeof openLoopback>>,
  verifier: string,
  state: string,
  options: ConnectOptions,
): Promise<void> {
  const timeoutMs = options.timeoutMs ?? CONNECT_TIMEOUT_MS;
  const onAbort = (): void => {
    void loopback.close();
  };
  options.signal?.addEventListener('abort', onAbort, { once: true });

  try {
    publish(
      {
        phase: 'awaiting-consent',
        connect_id: connectId,
        provider: profile.name,
        spoken: copy.AWAITING_CONSENT,
      },
      options.onStatus,
    );

    const { code } = await loopback.waitForCallback(state, timeoutMs);

    // C-16: admission is authoritative. If a newer connect() for this slot superseded us while
    // the human was deciding, this state is no longer admissible — refuse it rather than exchange
    // a code and vault a token for a flow the user abandoned. Teardown of our listener is only
    // best-effort, so this check, not the teardown, is what actually guarantees the invariant.
    if (!admit(state)) {
      publish(errorStatus(connectId, profile, 'timeout'), options.onStatus);
      return;
    }

    publish(
      {
        phase: 'exchanging',
        connect_id: connectId,
        provider: profile.name,
        spoken: copy.EXCHANGING,
      },
      options.onStatus,
    );

    const record = await exchangeCode(profile, {
      code,
      verifier,
      // The bound URI, byte for byte. Never re-derived (§A8, D6).
      redirectUri: loopback.redirectUri,
    });

    await finalizeConnected(connectId, profile, record, options.onStatus);
  } finally {
    // C-16: free the single-flight slot so the NEXT connect() is a clean start, not a
    // supersession of a flow that already reached its terminal outcome.
    complete(state);
    options.signal?.removeEventListener('abort', onAbort);
    await loopback.close();
    // Design decision: the success page owns the return trip. Its "Open VoiceOS"
    // button (voiceos:// deep link) focuses the app only when the user asks; yanking the
    // app to the front automatically fought the browser for focus mid-read. activateApp
    // stays in the hooks for tools that need it, but the connect flow never auto-focuses.
  }
}

/**
 * The tail every successful grant shares: prove who the token belongs to, vault it under
 * (provider + account), register the account, and publish `connected`.
 *
 * Extracted so the loopback path and the RFC 8628 device path (C-17) reach the connected state
 * through IDENTICAL steps — "connected" is produced by the identity probe and never by an HTTP 200,
 * the token is keyed by the probe's STABLE opaque account id so a second workspace never clobbers
 * the first (the wave-1 silent-overwrite MEDIUM), and the account is registered in the index that
 * routes getToken(provider, account?).
 */
async function finalizeConnected(
  connectId: string,
  profile: ProviderProfile,
  record: TokenRecord,
  onStatus?: (s: ConnectStatus) => void,
): Promise<void> {
  const identity = await probeIdentity(profile, record.access_token);

  const accountId = deriveAccountId(identity);
  await putToken(
    profile.name,
    {
      ...record,
      identity: {
        handle: identity.handle,
        ...(identity.workspace === undefined ? {} : { workspace: identity.workspace }),
      },
    },
    accountId,
  );
  const index = await readAccountIndex(profile.name).catch(() => emptyIndex());
  await writeAccountIndex(profile.name, upsertAccount(index, toAccountRef(profile.name, identity)));

  // C-23: a fresh mint reached a usable credential — the time-to-token sample (from the attempt
  // recorded in connect()) lands here, and only here, so a cache hit never pollutes the latency.
  obs.recordConnectResult(connectId, profile.name, 'connected', { accountId });

  publish(
    {
      phase: 'connected',
      connect_id: connectId,
      provider: profile.name,
      spoken: copy.connected(identity.handle, identity.workspace),
      identity: {
        handle: identity.handle,
        ...(identity.workspace === undefined ? {} : { workspace: identity.workspace }),
      },
    },
    onStatus,
  );
}

/* ─────────────────────────── grant path 3: device flow (RFC 8628, C-17) ─────────────────────────── */

/**
 * The device authorization grant, wired to the two-phase connect contract.
 *
 * Like the loopback path, this returns fast — as soon as the provider has handed back a user code
 * and verification URL — carrying them on `phase: 'awaiting-consent'` so the caller can show the
 * code. There is no browser to open and no port to bind (that is the whole point): the human enters
 * the code on another device while the engine POLLS out of band. The polling, the mandated backoff,
 * and the terminal outcomes complete through {@link finishDeviceConnect}, exactly as the loopback
 * exchange completes through {@link finishConnect}.
 *
 * The `device_code` is a secret and is NEVER placed on a ConnectStatus; only the human-facing
 * `user_code` and verification URL are surfaced.
 */
async function connectDevice(
  connectId: string,
  profile: ProviderProfile,
  options: ConnectOptions,
  flowAccount: string,
): Promise<ConnectStatus> {
  let auth: DeviceAuthorization;
  try {
    auth = await requestDeviceAuthorization(profile);
  } catch (error) {
    return publish(
      errorStatus(connectId, profile, toConnectErrorCode(error), providerMessageOf(error)),
      options.onStatus,
    );
  }

  // C-16 / SPEC §14 (grant path 3): register this device flow in the single-flight slot for
  // (provider, account) so two concurrent device connects can never both reach the vault write —
  // the second supersedes the first, and the superseded flow is refused at the admission check in
  // finishDeviceConnect before it can write. The device path binds no port and opens no browser,
  // so there is no listener to tear down; admission is authoritative, teardown would be a no-op.
  // The slot needs a key: device flows carry no `state` on the wire, so a fresh random token is
  // minted purely as this flow's private in-memory correlation id.
  const flowState = mintState();
  begin(profile.name, flowState, { account: flowAccount });

  const status = publish(
    {
      phase: 'awaiting-consent',
      connect_id: connectId,
      provider: profile.name,
      spoken: copy.deviceCode(profile.display_name, auth.userCode, auth.verificationUri),
      device: {
        user_code: auth.userCode,
        verification_uri: auth.verificationUri,
        ...(auth.verificationUriComplete === undefined
          ? {}
          : { verification_uri_complete: auth.verificationUriComplete }),
        expires_at: auth.expiresAt,
      },
    },
    options.onStatus,
  );

  // Out of band, deliberately not awaited: the human is the slow part, and their client gives a
  // tool 60 seconds. Failures land on the status board, never as an unhandled rejection.
  void finishDeviceConnect(connectId, profile, auth, flowState, options).catch((error: unknown) => {
    publish(
      errorStatus(connectId, profile, toConnectErrorCode(error), providerMessageOf(error)),
      options.onStatus,
    );
  });

  return status;
}

async function finishDeviceConnect(
  connectId: string,
  profile: ProviderProfile,
  auth: DeviceAuthorization,
  flowState: string,
  options: ConnectOptions,
): Promise<void> {
  try {
    const record = await pollForDeviceToken(profile, auth, {
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });

    // C-16: admission is authoritative. If a newer connect() for this slot superseded us while the
    // human was entering the code, this flow is no longer admissible — refuse it rather than race
    // the vault write with the live flow (SPEC §14, grant path 3).
    if (!admit(flowState)) {
      publish(errorStatus(connectId, profile, 'timeout'), options.onStatus);
      return;
    }

    // The identity probe is the "verifying" beat — the same step the loopback path narrates after
    // its exchange, so both paths speak the same deck.
    publish(
      {
        phase: 'exchanging',
        connect_id: connectId,
        provider: profile.name,
        spoken: copy.EXCHANGING,
      },
      options.onStatus,
    );

    await finalizeConnected(connectId, profile, record, options.onStatus);
  } finally {
    // C-16: free the single-flight slot so the NEXT connect() is a clean start, not a supersession
    // of a flow that already reached its terminal outcome.
    complete(flowState);
  }
}

/* ───────────────────────────────── the other three ───────────────────────────────── */

/**
 * A token that is valid *right now* for `provider` — the default/sole account, or the one named
 * by `account`.
 *
 * C-13: `getToken(provider)` stays back-compatible — it resolves the sole connected account, or
 * the caller-designated default when several exist, and SURFACES an {@link AccountAmbiguousError}
 * (carrying the candidates) rather than silently picking one when it cannot decide.
 * `getToken(provider, account)` selects an account by its stable id, handle, workspace, or a
 * `handle@workspace` compound.
 *
 * Refresh is this function's problem, not the caller's: it refreshes proactively inside
 * REFRESH_SKEW_MS of expiry and retries exactly once on an auth failure. Refreshes are
 * serialized across processes by an O_EXCL lock — five MCP processes sharing one single-use
 * rotating refresh token is how you permanently brick auth mid-demo.
 *
 * @throws EngineError `not_connected` when nothing is vaulted (the caller's cue to
 *         surface `needs_connect` and call {@link connect}).
 * @throws AccountAmbiguousError when several accounts exist and none was selected or defaulted.
 */
export async function getToken(provider: string, account?: string): Promise<string> {
  const profile = await resolveProfile(provider);
  const index = await readAccountIndex(provider).catch(() => emptyIndex());

  // Back-compat / pre-migration: no index yet (e.g. a legacy single-slot record written under
  // the bare provider key). Fall through to that slot — getFreshToken throws not_connected when
  // nothing is vaulted there either.
  if (index.accounts.length === 0) {
    return getFreshToken(profile);
  }

  const ref = resolveAccountOrThrow(provider, index, account);
  return getFreshToken(profile, { accountId: ref.accountId });
}

/**
 * Destroy every vaulted record for `provider` — all accounts, the account index, and the legacy
 * single-slot record — plus any bring-your-own client secret. Idempotent: disconnecting
 * something that was never connected succeeds silently rather than throwing at a user who just
 * wants it gone.
 *
 * When the profile names a `revoke_url`, each token is revoked upstream FIRST — best-effort,
 * because a provider that is unreachable must not be able to trap a user's credential on
 * their machine. Local destruction always happens.
 */
export async function disconnect(provider: string): Promise<void> {
  const profile = await resolveProfile(provider).catch(() => null);
  const revokeUrl = profile?.revoke_url;
  const index = await readAccountIndex(provider).catch(() => emptyIndex());

  // Collect every record this provider owns: one per indexed account, plus the legacy bare slot.
  const records: TokenRecord[] = [];
  for (const acct of index.accounts) {
    const record = await readToken(provider, acct.accountId).catch(() => null);
    if (record !== null) records.push(record);
  }
  const legacy = await readToken(provider).catch(() => null);
  if (legacy !== null) records.push(legacy);

  if (revokeUrl !== undefined) {
    for (const record of records) {
      await fetch(revokeUrl, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
          ...(profile?.static_headers ?? {}),
          authorization: `Bearer ${record.access_token}`,
        },
        body: new URLSearchParams({ token: record.access_token }).toString(),
      }).catch(() => undefined);
    }
  }

  for (const acct of index.accounts) await deleteToken(provider, acct.accountId);
  await deleteToken(provider); // the legacy bare-key slot
  await deleteAccountIndex(provider);
  // C-23: record the disconnect credential-free. `revoked` only where an upstream revocation was
  // attempted; otherwise `forgotten` (local removal is unconditional — §6, INV-CUST-6).
  if (records.length > 0) {
    obs.record({
      type: 'revocation',
      provider,
      outcome: revokeUrl === undefined ? 'forgotten' : 'revoked',
    });
  }
  // B1 custody: a disconnect also forgets the user's bring-your-own client secret, if any.
  // Idempotent and never throws on a missing item.
  await deleteClientCredentials(provider).catch(() => undefined);
  // Class C custody (C-8): forget the self-registered client too. When DCR issued a secret it was
  // mirrored into the B1 store, which the line above already cleared. Idempotent.
  await deleteRegisteredClient(provider).catch(() => undefined);
}

/* ─────────────────────────── the zero-auth-code surface (C-21, §18) ─────────────────────────── */

/**
 * A fetch-shaped client for `provider` (and, optionally, one `account`) that carries auth so an
 * integration's tools never do:
 *
 *     const api = auth.client("slack");
 *     const res = await api.post("/chat.postMessage", { channel, text });
 *
 * It injects the credential, refreshes silently, retries once on a 401 after a successful
 * refresh, applies the profile's sender-constraint scheme (DPoP / mTLS / bearer), raises the
 * scope step-up card before dispatch when an action needs an ungranted scope, and throws the
 * closed 9-code {@link TaxonomyError}. There is no token variable in the author's code because
 * there is no place for one — the falsifiable claim of §18: auth LOC in a new integration = 0.
 *
 * `auth.token(provider, account?)` (i.e. {@link getToken}) remains available for the cases the
 * client wrapper does not cover.
 */
export function client(provider: string, account?: string, options?: AuthClientOptions): AuthClient {
  return createAuthClient({ resolveProfile }, provider, account, options);
}

/**
 * The §18 surface as one object: `auth.client(...)` (zero-auth-code fetch) and `auth.token(...)`
 * (the lower-level fresh-token accessor). Exported both as this namespace and as the standalone
 * {@link client} / {@link getToken} so either import style works.
 */
export const auth = {
  client,
  token: getToken,
} as const;

/* ─────────────────────────── background token health (C-12, §10) ─────────────────────────── */

/**
 * Enumerate what is connected right now — every account in every registered provider's index,
 * plus a legacy bare-slot record where no index exists yet. Called each tick by the monitor, so
 * a provider connected after the monitor started joins the watch on the next pass and a
 * disconnected one drops off. No secrets: only the provider name and the opaque account id.
 */
async function defaultHealthTargets(): Promise<HealthTarget[]> {
  const targets: HealthTarget[] = [];
  for (const name of registry.keys()) {
    const index = await readAccountIndex(name).catch(() => emptyIndex());
    if (index.accounts.length === 0) {
      const legacy = await readToken(name).catch(() => null);
      if (legacy !== null) targets.push({ provider: name });
    } else {
      for (const acct of index.accounts) targets.push({ provider: name, accountId: acct.accountId });
    }
  }
  return targets;
}

/**
 * C-12 — start the background token-health probe (SPEC §10), wired to the engine's real vault and
 * identity probe with a conservative default budget. The host binds the four environmental gates
 * (active-turn, connectivity, power, awake) and an `onBroken` callback that turns a healthy→broken
 * transition into a quiet reconnect badge. A successful probe is silent by design; nothing is
 * probed during an active turn, on a metered link, on low power, or while the machine sleeps.
 *
 * The monitor is created but NOT started here — the caller decides when to `start()` it — so a
 * test (or a headless run) can drive `tick()` deterministically. Every result feeds
 * observability, so re-auth rate per provider becomes a measured number.
 */
export function startHealthMonitor(
  options: Partial<HealthMonitorOptions> & { autostart?: boolean } = {},
): HealthMonitor {
  const deps: HealthDeps = options.deps ?? {
    resolveProfile: resolveProviderProfile,
    readAccessToken: async (provider, accountId) =>
      (await readToken(provider, accountId).catch(() => null))?.access_token ?? null,
    probe: async (profile, accessToken) => {
      await probeIdentity(profile, accessToken);
    },
  };
  const monitor = createHealthMonitor({
    deps,
    listTargets: options.listTargets ?? defaultHealthTargets,
    ...(options.gates === undefined ? {} : { gates: options.gates }),
    ...(options.onBroken === undefined ? {} : { onBroken: options.onBroken }),
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.tickMs === undefined ? {} : { tickMs: options.tickMs }),
    ...(options.config === undefined ? {} : { config: options.config }),
  });
  if (options.autostart === true) monitor.start();
  return monitor;
}

/**
 * Current status of an in-flight or completed connect. The poll half of the two-phase
 * design (`auth_status(connect_id)` in the integration's tool surface).
 */
export async function getConnectStatus(connectId: string): Promise<ConnectStatus> {
  const status = statuses.get(connectId);
  if (status === undefined) {
    throw new EngineError('not_connected', `no connect in flight with id '${connectId}'`, {
      hint: 'connect_id values are minted by connect() and kept for the last 50 attempts of this process.',
    });
  }
  return status;
}
