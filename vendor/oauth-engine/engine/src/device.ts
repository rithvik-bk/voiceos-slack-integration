/**
 * Grant path 3 — the RFC 8628 device authorization grant. Closes C-17.
 *
 * The loopback path (grant paths 1 and 2) assumes two things a headless box does not have: a
 * browser to open, and a loopback port a redirect can land on. A CI runner, an SSH session, a
 * kiosk, a TV — and any provider that flatly refuses loopback redirects — leave the preferred
 * path with nowhere to go. RFC 8628 is the answer the SPEC reserves for exactly this (§3 path 3,
 * §1 `device_flow`): the device asks the provider for a short **user code** and a **verification
 * URL**, shows them to the human, and then POLLS the token endpoint until the human has entered
 * the code on some *other* device with a browser.
 *
 * Two secrets, one displayed and one not, and the distinction is the whole security story here:
 *   - the `user_code` is display material — spoken, rendered, safe on a projector;
 *   - the `device_code` is the credential the poll authenticates with. It never appears in a
 *     ConnectStatus, a log line, an error message, or argv. It is registered with redact() on
 *     every token-endpoint round trip, exactly as the authorization code is on the loopback path.
 *
 * This module owns the device-specific choreography — the authorization request, the mandated
 * polling backoff (§3.5: honor `interval`, and add five seconds on every `slow_down`) — and reuses
 * the ONE token-endpoint implementation in exchange.ts for the wire itself, so client-auth routing,
 * redaction, success-predicate evaluation and token-shape parsing stay in a single place and a
 * device-grant provider is a row of capability values, never a branch.
 */

import { EngineError } from './errors.ts';
import {
  applyTokenAuth,
  assertOk,
  baseHeaders,
  buildRecord,
  postForm,
  satisfiesPredicate,
  type HttpOptions,
} from './exchange.ts';
import { readFirstNumber, readFirstString } from './paths.ts';
import { redact, safeProviderMessage } from './redact.ts';
import {
  fetchClientAssertion,
  forwardSealedDeviceCode,
  resolveRelayBaseUrl,
} from './relay-client.ts';
import type { ProviderProfile, TokenRecord } from './types.ts';

/** The grant paths the engine selects among from the profile (SPEC §3). */
export type GrantPath = 'loopback' | 'device';

/** RFC 8628's default poll interval when the provider omits one (§3.5). */
const DEFAULT_INTERVAL_S = 5;
/** RFC 8628 §3.5: on `slow_down`, the client increases the interval by five seconds. */
const SLOW_DOWN_STEP_MS = 5_000;
/** A device-authorization endpoint that has not answered in this long is a hung flow. */
const DEVICE_AUTHZ_TIMEOUT_MS = 20_000;
/** Sane fallback when a provider omits `expires_in` from the authorization response. */
const DEFAULT_EXPIRES_IN_S = 600;

/**
 * Choose the grant path for a connect, from the profile and the caller's context (SPEC §3).
 *
 * The device grant is selected for a **headless / no-loopback** context — a machine with no
 * browser to open or no loopback port to bind — and only when the provider actually advertises it
 * (`device_flow: 'rfc8628'`). A headless request against a provider with no device grant is a hard
 * `config_invalid`, not a silent fall-back to a loopback flow that cannot possibly complete without
 * a browser. Every other connect takes the preferred loopback path unchanged.
 *
 * The selection keys off capability values (`device_flow`) and context, never a provider name, so
 * it satisfies INV-CONFIG-1 the same way the rest of the engine does.
 */
export function selectGrantPath(
  profile: ProviderProfile,
  context: { headless?: boolean },
): GrantPath {
  if (context.headless === true) {
    if (profile.device_flow === 'rfc8628') return 'device';
    throw new EngineError('config_invalid', `${profile.name} cannot connect headless`, {
      hint: `A headless connect needs device_flow: 'rfc8628' in the profile; ${profile.name} does not advertise it, and the loopback path needs a browser this context does not have.`,
    });
  }
  return 'loopback';
}

/**
 * What the RFC 8628 §3.2 device-authorization response hands back, normalized. `deviceCode` is a
 * secret and is deliberately kept OUT of every product-surface type; the rest is display material.
 */
export interface DeviceAuthorization {
  /** SECRET — the credential the token poll authenticates with. Never displayed or logged. */
  deviceCode: string;
  /** Shown to the human to type on the verification page. */
  userCode: string;
  /** Where the human goes to enter the code. */
  verificationUri: string;
  /** Prefilled URL (code embedded) when the provider offers one — a QR/one-tap convenience. */
  verificationUriComplete?: string;
  /** Epoch ms after which the user code stops working and the poll must give up. */
  expiresAt: number;
  /** Seconds between polls the provider asked for (RFC default 5). */
  interval: number;
}

/**
 * Step 1 — request a device + user code (RFC 8628 §3.1). One POST to the device-authorization
 * endpoint, authenticated the same way the token endpoint authenticates the client (public →
 * client_id in the body; confidential → the B1 secret via byos, same seam exchange.ts uses).
 *
 * @throws EngineError `config_invalid` when the profile is not device-flow capable or names no
 *         device-authorization endpoint.
 * @throws EngineError `provider_error` when the endpoint is unreachable, non-2xx, or returns a body
 *         that is not a usable authorization (no device_code / user_code / verification URL).
 */
export async function requestDeviceAuthorization(
  profile: ProviderProfile,
  http: HttpOptions = {},
): Promise<DeviceAuthorization> {
  if (profile.device_flow !== 'rfc8628') {
    throw new EngineError('config_invalid', `${profile.name} is not marked device_flow: 'rfc8628'`, {
      hint: 'Only a provider whose measured profile reports the RFC 8628 device grant uses this path.',
    });
  }
  const endpoint = profile.device_authorization_url;
  if (typeof endpoint !== 'string' || endpoint === '') {
    throw new EngineError('config_invalid', `${profile.name} has device_flow: 'rfc8628' but no device_authorization_url`, {
      hint: 'The profile must carry the RFC 8628 device_authorization_endpoint before the engine can start a device flow.',
    });
  }

  const headers: Record<string, string> = {
    'content-type': 'application/x-www-form-urlencoded',
    accept: 'application/json',
    ...(profile.static_headers ?? {}),
  };
  const body = new URLSearchParams();
  const scopeValue = profile.scopes.join(profile.scope_delimiter ?? ' ');
  if (scopeValue !== '') body.set('scope', scopeValue);
  // Custody routing (SPEC §5b). A B2a/B2b provider's client secret lives on the relay, not on this
  // device, so the device-authorization request — which returns NO token — is sent as a public
  // client (client_id only). The relay's client authentication is applied at the token poll, where
  // the credential and the token custody actually matter (see pollOnce). Public/B1 keep the
  // existing on-device client auth.
  const relayMode = profile.relay_mode;
  let secrets: Array<string | undefined> = [];
  if (relayMode === 'assertion_signing' || relayMode === 'exchange_forwarding') {
    body.set('client_id', profile.client_id);
  } else {
    const authSecret = await applyTokenAuth(profile, profile.token_auth, body, headers);
    if (authSecret !== undefined) secrets = [authSecret];
  }

  const doFetch = http.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), http.timeoutMs ?? DEVICE_AUTHZ_TIMEOUT_MS);

  let response: Response;
  try {
    response = await doFetch(endpoint, {
      method: 'POST',
      headers,
      body: body.toString(),
      signal: controller.signal,
      redirect: 'error',
    });
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : 'network failure';
    throw new EngineError('provider_error', 'could not reach the device authorization endpoint', {
      hint: `POST ${endpoint} failed: ${redact(detail, secrets)}`,
      cause,
    });
  } finally {
    clearTimeout(timer);
  }

  const text = await response.text();
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    // The body is NOT echoed: a non-JSON response is exactly where an error page could carry
    // credential material.
    throw new EngineError('provider_error', 'the device authorization endpoint returned a non-JSON body', {
      hint: `HTTP ${response.status} from ${endpoint}, ${text.length} bytes that are not JSON.`,
    });
  }

  const httpOk = response.status >= 200 && response.status < 300;
  if (!httpOk || !satisfiesPredicate(profile.success_predicate, payload)) {
    const providerMessage = safeProviderMessage(payload, secrets);
    throw new EngineError('provider_error', `${profile.name} refused the device authorization request`, {
      hint: `HTTP ${response.status} from ${endpoint}.`,
      ...(providerMessage === undefined ? {} : { providerMessage }),
    });
  }

  const deviceCode = readFirstString(payload, ['device_code']);
  const userCode = readFirstString(payload, ['user_code']);
  // Google spells it verification_url; RFC 8628 spells it verification_uri. A candidate list, not a branch.
  const verificationUri = readFirstString(payload, ['verification_uri', 'verification_url']);
  if (deviceCode === undefined || userCode === undefined || verificationUri === undefined) {
    throw new EngineError('provider_error', `${profile.name} returned an incomplete device authorization`, {
      hint: 'RFC 8628 §3.2 requires device_code, user_code and a verification URI in the response.',
    });
  }
  const verificationUriComplete = readFirstString(payload, [
    'verification_uri_complete',
    'verification_url_complete',
  ]);
  const expiresIn = readFirstNumber(payload, ['expires_in']) ?? DEFAULT_EXPIRES_IN_S;
  const interval = readFirstNumber(payload, ['interval']) ?? DEFAULT_INTERVAL_S;

  return {
    deviceCode,
    userCode,
    verificationUri,
    ...(verificationUriComplete === undefined ? {} : { verificationUriComplete }),
    expiresAt: Date.now() + expiresIn * 1000,
    interval,
  };
}

/** Options for the poll loop. `sleep`/`now` are injected in tests so backoff is asserted, not waited on. */
export interface DevicePollOptions {
  http?: HttpOptions;
  /** Abort the poll (tool cancelled, app quitting). */
  signal?: AbortSignal;
  /** Wait `ms` between polls. Default: real setTimeout. Injected in tests. */
  sleep?: (ms: number) => Promise<void>;
  /** Current epoch ms. Default: Date.now. Injected in tests to drive the expiry deadline. */
  now?: () => number;
}

type PollOutcome =
  | { kind: 'complete'; record: TokenRecord }
  | { kind: 'pending' }
  | { kind: 'slow_down' };

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** RFC 8628 §3.4 device-code grant type — one string, one place. */
const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

/**
 * POST one device-code grant to the token endpoint, routed by the profile's DERIVED custody mode
 * (SPEC §5b) exactly as exchange/refresh are — never a provider name. A relay-custody device-flow
 * provider authenticates its poll through the relay (its secret cannot live on this device):
 *
 *   B2a  the relay signs a client assertion; the DEVICE polls here with it (RFC 7523), so the relay
 *        never sees the device-code token. One assertion per poll — cheap, and the relay stays
 *        token-blind for the whole device flow.
 *   B2b  the relay holds the raw secret, so the poll FORWARDS through it and the token (or the
 *        `authorization_pending` body — the relay seals whatever the provider returns) comes back
 *        sealed to an ephemeral device key, opened here.
 *   A/B1 the poll runs on device with the profile's own client auth, unchanged.
 *
 * Returns the parsed payload and the upstream status so `pollOnce` classifies pending / slow_down /
 * complete / terminal identically for every custody class.
 */
async function pollTokenEndpoint(
  profile: ProviderProfile,
  deviceCode: string,
  http: HttpOptions,
  secrets: Array<string | undefined>,
): Promise<{ payload: unknown; status: number }> {
  const relayMode = profile.relay_mode;

  if (relayMode === 'exchange_forwarding') {
    const relayBaseUrl = resolveRelayBaseUrl(http);
    return forwardSealedDeviceCode(relayBaseUrl, profile.name, deviceCode, http);
  }

  const headers = baseHeaders(profile);
  const body = new URLSearchParams({ grant_type: DEVICE_CODE_GRANT, device_code: deviceCode });

  if (relayMode === 'assertion_signing') {
    const relayBaseUrl = resolveRelayBaseUrl(http);
    const assertion = await fetchClientAssertion(relayBaseUrl, profile.name, http);
    body.set('client_id', profile.client_id);
    body.set('client_assertion_type', assertion.client_assertion_type);
    body.set('client_assertion', assertion.client_assertion);
    return postForm(profile, body, headers, http, secrets);
  }

  const authSecret = await applyTokenAuth(profile, profile.token_auth, body, headers);
  if (authSecret !== undefined) secrets.push(authSecret);
  return postForm(profile, body, headers, http, secrets);
}

/**
 * ONE poll of the token endpoint with the device-code grant (RFC 8628 §3.4). Returns the terminal
 * `complete` (token in hand) or one of the two *keep-polling* signals; every genuinely terminal
 * failure throws through the shared token-endpoint classifier so the copy deck reads it correctly.
 */
async function pollOnce(
  profile: ProviderProfile,
  deviceCode: string,
  http: HttpOptions,
): Promise<PollOutcome> {
  const secrets: Array<string | undefined> = [deviceCode];
  const { payload, status } = await pollTokenEndpoint(profile, deviceCode, http, secrets);

  const httpOk = status >= 200 && status < 300;
  if (httpOk && satisfiesPredicate(profile.success_predicate, payload)) {
    return { kind: 'complete', record: buildRecord(profile, payload, 'device') };
  }

  // Not a success — read the RFC 8628 §3.5 error token to decide keep-polling vs terminal.
  const error = (readFirstString(payload, ['error']) ?? '').toLowerCase();
  if (error === 'authorization_pending') return { kind: 'pending' };
  if (error === 'slow_down') return { kind: 'slow_down' };
  if (error === 'access_denied') {
    const providerMessage = safeProviderMessage(payload, secrets);
    throw new EngineError('denied_by_user', `${profile.name} device authorization was declined`, {
      hint: 'The user declined the request on the verification page. Nothing was stored.',
      ...(providerMessage === undefined ? {} : { providerMessage }),
    });
  }
  // `expired_token` and anything else terminal go through the shared classifier, which maps
  // expired_token → expired_or_revoked (reconnect) and unknown refusals → provider_error.
  assertOk(profile, payload, status, 'device', secrets);
  // assertOk always throws on a non-success; this is unreachable and only satisfies the type.
  throw new EngineError('provider_error', `${profile.name} refused the device token poll`, {
    hint: 'The device token endpoint returned neither a token nor a recognized error.',
  });
}

/**
 * Step 2 — poll the token endpoint until the human approves, denies, or the code expires
 * (RFC 8628 §3.4/§3.5). Honors the provider's `interval` and adds five seconds on every
 * `slow_down`, and gives up at the authorization's own `expiresAt` rather than an arbitrary clock.
 *
 * @throws EngineError `denied_by_user` when the user declines.
 * @throws EngineError `expired_or_revoked` when the user code expires before approval.
 * @throws EngineError `timeout` when the caller aborts.
 * @throws EngineError `provider_error` on an unrecognized token-endpoint refusal.
 */
export async function pollForDeviceToken(
  profile: ProviderProfile,
  auth: DeviceAuthorization,
  options: DevicePollOptions = {},
): Promise<TokenRecord> {
  const sleep = options.sleep ?? defaultSleep;
  const now = options.now ?? Date.now;
  // A function, not a narrowed property read: `aborted` is a live getter that flips under us, and a
  // `signal.aborted === true` check would otherwise be narrowed to `false` for the rest of the loop.
  const aborted = (): boolean => options.signal?.aborted === true;
  const cancelled = (): EngineError =>
    new EngineError('timeout', 'the device authorization was cancelled', {
      hint: 'The connect was aborted before the user approved it.',
    });
  let intervalMs = Math.max(auth.interval, 0) * 1000;

  for (;;) {
    if (aborted()) throw cancelled();
    if (now() >= auth.expiresAt) {
      throw new EngineError('expired_or_revoked', `${profile.name} device code expired before approval`, {
        hint: 'The code was not entered in time. Start the connect again to get a fresh code.',
      });
    }

    // RFC 8628 §3.4: wait `interval` seconds between polls; the human is the slow part.
    await sleep(intervalMs);
    if (aborted()) throw cancelled();

    const outcome = await pollOnce(profile, auth.deviceCode, options.http ?? {});
    if (outcome.kind === 'complete') return outcome.record;
    if (outcome.kind === 'slow_down') intervalMs += SLOW_DOWN_STEP_MS;
    // 'pending' (and 'slow_down' after the bump) fall through and poll again.
  }
}

/** The whole grant, end to end, for a caller that does not need the two phases separately. */
export async function runDeviceGrant(
  profile: ProviderProfile,
  onCode: (auth: DeviceAuthorization) => void,
  options: DevicePollOptions = {},
): Promise<TokenRecord> {
  const auth = await requestDeviceAuthorization(profile, options.http);
  onCode(auth);
  return pollForDeviceToken(profile, auth, options);
}
