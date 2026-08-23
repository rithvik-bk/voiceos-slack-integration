/**
 * P1-I4 — the token endpoint. Code → tokens, and refresh token → tokens.
 *
 * This is the file where per-provider knowledge would normally metastasize into
 * `if (provider === 'slack')`. It does not, and the discipline is visible: every axis on
 * which Slack, Zoom and Reddit differ is read out of the `ProviderProfile` —
 *
 *   token_auth / refresh_auth   how the request authenticates (two axes, on purpose:
 *                               Slack's exchange and refresh do NOT authenticate alike)
 *   success_predicate           whether an HTTP 200 is actually a success (Slack ships
 *                               failures as 200 + {"ok": false} — [C-SL-20])
 *   token_path / refresh_token_path / expires_in_path
 *                               where the tokens live in the body
 *
 * The one genuinely surprising provider behaviour of Phase 0 is D-2026-08-16-1: Slack's
 * **exchange** nests the user tokens under `authed_user.*`, while its **refresh** returns
 * them at the TOP LEVEL. That is encoded here as DATA — a candidate path list, profile
 * path first and top-level second — not as a Slack branch. A second provider with two
 * shapes costs zero lines, and a provider that only ever uses one shape is unaffected
 * because the profile path hits first.
 *
 * Byte-identical redirect_uri (§A8, D6): the caller passes the URI the loopback actually
 * bound, and it is sent unmodified. We never re-derive it here — re-deriving is precisely
 * how a ladder walk to :33419 ends up exchanging against :33418 and hanging with no error.
 */

import { applyConfidentialAuth, isConfidentialAuth, type ConfidentialAuthMode } from './byos.ts';
import { EngineError } from './errors.ts';
import { readFirstNumber, readFirstString, readPath } from './paths.ts';
import { redact, safeProviderMessage } from './redact.ts';
import {
  fetchClientAssertion,
  forwardSealedExchange,
  forwardSealedRefresh,
  resolveRelayBaseUrl,
} from './relay-client.ts';
import type { ProviderProfile, SuccessPredicate, TokenRecord } from './types.ts';

export interface ExchangeInput {
  /** The `code` the provider handed the loopback. */
  code: string;
  /** The PKCE verifier minted for THIS authorize request. Ignored when `pkce: 'none'`. */
  verifier: string;
  /** Byte-identical to the value sent on the authorize request (§A8). */
  redirectUri: string;
}

/** Injected in tests; production always uses the platform `fetch`. */
export interface HttpOptions {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  /**
   * The confidential-custody relay base URL (B2a/B2b). Overrides the deployment default from
   * `HANDSHAKE_RELAY_URL`; a test points it at a loopback relay. Ignored for Class A / B1.
   */
  relayBaseUrl?: string;
}

/** A token endpoint that has not answered in this long is a hung demo, not a slow network. */
const TOKEN_TIMEOUT_MS = 20_000;

/* ─────────────────────────────── request construction ─────────────────────────────── */

/**
 * Client authentication for the two grants.
 *
 * `none` and `body` behave identically for a public client, and that is not sloppiness —
 * it is what both live-proven providers actually require. Slack's PKCE token request and
 * Zoom's (empirically, 2026-08-16) both carry `client_id` in the form body with NO
 * Authorization header. `none` therefore means "no HTTP auth header"; the public client id
 * is not a credential and always travels in the body. `basic` is rejected loudly: it needs
 * a client secret, and this engine is architecturally incapable of holding one.
 */
function applyClientAuth(
  mode: ProviderProfile['token_auth'] | ProviderProfile['refresh_auth'],
  profile: ProviderProfile,
  body: URLSearchParams,
  headers: Record<string, string>,
): void {
  switch (mode) {
    case 'none':
    case 'body':
    case 'client_id_body':
      body.set('client_id', profile.client_id);
      return;
    case 'basic_empty_password':
      headers.authorization = `Basic ${Buffer.from(`${profile.client_id}:`, 'utf8').toString('base64')}`;
      return;
    case 'basic':
    case 'secret_basic':
    case 'secret_post':
      // Confidential (B1) modes are handled by byos.applyConfidentialAuth and are peeled
      // off by the router in exchangeCode/refreshGrant before this switch runs. Kept only
      // as a defensive exhaustiveness arm; never a live path.
      throw new EngineError('config_invalid', `confidential auth '${mode}' must route through byos`, {
        hint: `${profile.name}: '${mode}' is a bring-your-own (B1) client-secret method; call applyConfidentialAuth, not applyClientAuth.`,
      });
    case 'unknown':
      // The honest default for a PUBLIC client, and the one both live probes confirmed:
      // client_id in the body, no Authorization header. Recorded as a decision rather
      // than hidden as a fallthrough, because the day it is wrong we want to find this
      // comment, not guess.
      body.set('client_id', profile.client_id);
      return;
    default: {
      const exhaustive: never = mode;
      throw new EngineError('config_invalid', 'unknown client-auth mode', {
        hint: `Unsupported auth axis value: ${String(exhaustive)}`,
      });
    }
  }
}

/**
 * Apply client authentication for ONE token-endpoint request, whichever custody class the
 * profile lands in, and return the secret that was used so the caller can redact it.
 *
 * This is the single seam every grant that talks to the token endpoint shares — exchange,
 * refresh, and the RFC 8628 device-code poll (device.ts) — so client-auth routing lives in
 * exactly one place and stays a capability decision, never a per-grant re-implementation:
 *   - a confidential (B1) mode routes through byos.applyConfidentialAuth and yields the
 *     user's client_secret, which the caller pushes onto its `secrets` list;
 *   - every public mode sets `client_id` in the body via {@link applyClientAuth} and yields
 *     `undefined` (a public client id is not a credential).
 */
export async function applyTokenAuth(
  profile: ProviderProfile,
  mode: ProviderProfile['token_auth'] | ProviderProfile['refresh_auth'],
  body: URLSearchParams,
  headers: Record<string, string>,
): Promise<string | undefined> {
  if (isConfidentialAuth(mode)) {
    return applyConfidentialAuth(profile.name, mode as ConfidentialAuthMode | 'basic', body, headers);
  }
  applyClientAuth(mode, profile, body, headers);
  return undefined;
}

export function baseHeaders(profile: ProviderProfile): Record<string, string> {
  return {
    'content-type': 'application/x-www-form-urlencoded',
    accept: 'application/json',
    ...(profile.static_headers ?? {}),
    ...(profile.token_endpoint_extra_headers ?? {}),
  };
}

/* ──────────────────────────────── response evaluation ──────────────────────────────── */

/**
 * "Did this 200 actually succeed?" — the one encoding, exported because the API layer needs
 * the same answer the token layer needs (Slack's `{"ok": false}` is not special to auth).
 */
export function satisfiesPredicate(predicate: SuccessPredicate | undefined, payload: unknown): boolean {
  if (predicate === undefined || predicate === null) return true;
  return readPath(payload, predicate.path) === predicate.equals;
}

/**
 * Errors a provider raises when the grant itself is dead, as opposed to a transient or
 * configuration failure. These are the ones the product surface must turn into "reconnect",
 * not "try again" — the copy deck's `expired_or_revoked` row.
 */
const DEAD_GRANT = new Set([
  'invalid_grant',
  'invalid_code',
  'code_already_used',
  'invalid_refresh_token',
  'token_expired',
  'expired_token',
  'token_revoked',
  'invalid_auth',
  'account_inactive',
  'unauthorized_client',
]);

function classify(payload: unknown, status: number): 'expired_or_revoked' | 'provider_error' {
  const error = readFirstString(payload, ['error', 'error_description', 'reason']);
  if (error !== undefined) {
    const normalized = error.toLowerCase();
    for (const dead of DEAD_GRANT) if (normalized.includes(dead)) return 'expired_or_revoked';
  }
  return status === 401 || status === 403 ? 'expired_or_revoked' : 'provider_error';
}

export async function postForm(
  profile: ProviderProfile,
  body: URLSearchParams,
  headers: Record<string, string>,
  options: HttpOptions,
  secrets: ReadonlyArray<string | undefined>,
): Promise<{ payload: unknown; status: number }> {
  const doFetch = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? TOKEN_TIMEOUT_MS);

  let response: Response;
  try {
    response = await doFetch(profile.token_url, {
      method: 'POST',
      headers,
      body: body.toString(),
      signal: controller.signal,
      redirect: 'error',
    });
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : 'network failure';
    throw new EngineError('provider_error', 'could not reach the token endpoint', {
      hint: `POST ${profile.token_url} failed: ${redact(detail, secrets)}`,
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
    // The body is NOT echoed: a non-JSON token response is exactly the case where an HTML
    // error page (or worse, a proxy dump) could be carrying credentials.
    throw new EngineError('provider_error', 'token endpoint returned a non-JSON body', {
      hint: `HTTP ${response.status} from ${profile.token_url}, ${text.length} bytes that are not JSON.`,
    });
  }
  return { payload, status: response.status };
}

export function assertOk(
  profile: ProviderProfile,
  payload: unknown,
  status: number,
  grant: 'exchange' | 'refresh' | 'device',
  secrets: ReadonlyArray<string | undefined>,
): void {
  const httpOk = status >= 200 && status < 300;
  if (httpOk && satisfiesPredicate(profile.success_predicate, payload)) return;

  const providerMessage = safeProviderMessage(payload, secrets);
  const code = classify(payload, status);
  throw new EngineError(code, `${profile.name} refused the ${grant}`, {
    hint:
      code === 'expired_or_revoked'
        ? `Reconnect ${profile.display_name}: the grant is no longer valid.`
        : `HTTP ${status} from ${profile.token_url}${profile.success_predicate ? ' (body-level success predicate not satisfied)' : ''}.`,
    ...(providerMessage === undefined ? {} : { providerMessage }),
  });
}

/* ────────────────────────────────── record building ────────────────────────────────── */

/** Scope lists arrive space- or comma-separated; both are legal and both appear live. */
function parseScopes(payload: unknown, profile: ProviderProfile, nestedScopePath: string | undefined): string[] {
  const raw = readFirstString(payload, [nestedScopePath, 'scope', 'scopes']);
  if (raw === undefined) return [...profile.scopes];
  return raw.split(/[,\s]+/).filter((s) => s.length > 0);
}

export function buildRecord(
  profile: ProviderProfile,
  payload: unknown,
  grant: 'exchange' | 'refresh' | 'device',
): TokenRecord {
  // The candidate lists ARE the D-2026-08-16-1 fix. Profile path first (Slack's nested
  // exchange), canonical top-level second (Slack's refresh, Zoom's everything).
  //
  // The asymmetry is deliberate and load-bearing: the EXCHANGE gets no top-level fallback,
  // because Slack's exchange response has a top-level `access_token` and it is the BOT
  // token [C-SL-07]. Falling back there would vault a real, working, WRONG token — the
  // worst possible failure, since it fails at read time with a scope error, not here.
  // A `device` grant (RFC 8628) returns a plain, top-level token response with none of the
  // authorization_code nesting hazard, so it takes the same fallback list as refresh.
  const accessPaths =
    grant === 'exchange' ? [profile.token_path] : [profile.token_path, 'access_token'];
  const refreshPaths = [profile.refresh_token_path, 'refresh_token'];
  const expiryPaths = [profile.expires_in_path, 'expires_in'];

  const accessToken = readFirstString(payload, accessPaths);
  if (accessToken === undefined) {
    throw new EngineError('provider_error', `${profile.name} returned no access token`, {
      hint: `Looked at ${accessPaths.filter(Boolean).join(', ')}. The response parsed as JSON and passed the success check, so this is a profile path that no longer matches the provider's shape.`,
    });
  }

  const refreshToken = readFirstString(payload, refreshPaths);
  const expiresIn = readFirstNumber(payload, expiryPaths) ?? profile.access_token_ttl;
  const now = Date.now();

  // Scope may be nested exactly where the token is (Slack: authed_user.scope).
  const nestedScopePath = profile.token_path.includes('.')
    ? `${profile.token_path.slice(0, profile.token_path.lastIndexOf('.'))}.scope`
    : undefined;

  return {
    provider: profile.name,
    access_token: accessToken,
    ...(refreshToken === undefined ? {} : { refresh_token: refreshToken }),
    ...(expiresIn === undefined ? {} : { expires_at: now + expiresIn * 1000 }),
    scopes: parseScopes(payload, profile, grant === 'exchange' ? nestedScopePath : undefined),
    obtained_at: now,
  };
}

/* ─────────────────────────────────── the two grants ─────────────────────────────────── */

/**
 * Authorization code → {@link TokenRecord}.
 *
 * `redirectUri` is sent exactly as given. Slack, verbatim: the value "must be the same for
 * both steps — otherwise, you will encounter a `bad_redirect_uri` error" (D6).
 */
export async function exchangeCode(
  profile: ProviderProfile,
  input: ExchangeInput,
  options: HttpOptions = {},
): Promise<TokenRecord> {
  const headers = baseHeaders(profile);
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: input.code,
    redirect_uri: input.redirectUri,
  });
  if (profile.pkce === 'S256') body.set('code_verifier', input.verifier);

  const secrets: Array<string | undefined> = [input.code, input.verifier];

  // Custody routing (C-6/C-7) — a capability decision on the DERIVED relay_mode, never a
  // provider name. A / B1 fall through to the on-device exchange below; the two relay classes
  // take the confidential path. relay_mode is derived alongside custody_class (B2a ⇒
  // assertion_signing, B2b ⇒ exchange_forwarding), so either field selects the same path.
  const relayMode = profile.relay_mode;

  if (relayMode === 'assertion_signing') {
    // B2a: the relay SIGNS a client assertion; the DEVICE performs the exchange here, so the
    // relay never sees the code, the verifier, or the resulting token. The public client_id
    // still travels in the body; the assertion is the client authentication.
    const relayBaseUrl = resolveRelayBaseUrl(options);
    const assertion = await fetchClientAssertion(relayBaseUrl, profile.name, options);
    body.set('client_id', profile.client_id);
    body.set('client_assertion_type', assertion.client_assertion_type);
    body.set('client_assertion', assertion.client_assertion);
    const { payload, status } = await postForm(profile, body, headers, options, secrets);
    assertOk(profile, payload, status, 'exchange', secrets);
    return buildRecord(profile, payload, 'exchange');
  }

  if (relayMode === 'exchange_forwarding') {
    // B2b: the relay performs the one exchange (it holds a raw secret we must never see) and
    // returns the provider token SEALED to an ephemeral device key we open on-device. The
    // engine stores nothing of the relay's; from assertOk onward this is identical to a direct
    // exchange, so the relay is invisible past this seam.
    const relayBaseUrl = resolveRelayBaseUrl(options);
    const { payload, status } = await forwardSealedExchange(relayBaseUrl, profile.name, input, options);
    assertOk(profile, payload, status, 'exchange', secrets);
    return buildRecord(profile, payload, 'exchange');
  }

  // A / B1: a confidential mode yields the user's client_secret (registered with redact() so it
  // can never surface in an error string); a public mode sets client_id in the body and yields
  // nothing. The exchange runs entirely on device.
  const authSecret = await applyTokenAuth(profile, profile.token_auth, body, headers);
  if (authSecret !== undefined) secrets.push(authSecret);

  const { payload, status } = await postForm(profile, body, headers, options, secrets);
  assertOk(profile, payload, status, 'exchange', secrets);
  return buildRecord(profile, payload, 'exchange');
}

/**
 * Refresh token → a NEW {@link TokenRecord}.
 *
 * Under rotation the returned refresh token replaces the one passed in, single-use — which
 * is why `refresh.ts` persists the result before it releases its lock. This function is
 * deliberately dumb about that: it performs one HTTP round trip and returns what came back.
 */
export async function refreshGrant(
  profile: ProviderProfile,
  refreshToken: string,
  options: HttpOptions = {},
): Promise<TokenRecord> {
  if (profile.refresh === 'none') {
    throw new EngineError('config_invalid', `${profile.name} does not issue refresh tokens`, {
      hint: `provider.json says refresh: 'none' — getFreshToken() must reconnect instead.`,
    });
  }
  const headers = baseHeaders(profile);
  const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken });

  const secrets: Array<string | undefined> = [refreshToken];

  // Custody routing (C-6/C-7), the same DERIVED relay_mode decision exchangeCode makes — never a
  // provider name (INV-CONFIG-1). Without this a confidential (B2a/B2b) provider had no silent
  // refresh at all: `refresh_auth: 'basic'` is hard-refused on device, so every expiry became a
  // forced human re-consent (contradicts SPEC §5b). A / B1 fall through to the on-device refresh.
  const relayMode = profile.relay_mode;

  if (relayMode === 'assertion_signing') {
    // B2a: the relay SIGNS a client assertion; the DEVICE performs the refresh here, so the relay
    // never sees the refresh token or the token that comes back — its custody property holds across
    // the whole lifecycle, not just the initial exchange. Public client_id in the body, assertion
    // as the client authentication (RFC 7523), exactly as the B2a exchange does.
    const relayBaseUrl = resolveRelayBaseUrl(options);
    const assertion = await fetchClientAssertion(relayBaseUrl, profile.name, options);
    body.set('client_id', profile.client_id);
    body.set('client_assertion_type', assertion.client_assertion_type);
    body.set('client_assertion', assertion.client_assertion);
    const { payload, status } = await postForm(profile, body, headers, options, secrets);
    assertOk(profile, payload, status, 'refresh', secrets);
    return buildRecord(profile, payload, 'refresh');
  }

  if (relayMode === 'exchange_forwarding') {
    // B2b: the relay holds a raw secret this device must never see, and a refresh needs it — so the
    // refresh forwards through the relay, which performs it and returns the new token SEALED to an
    // ephemeral device key. From assertOk onward this is identical to a direct refresh.
    const relayBaseUrl = resolveRelayBaseUrl(options);
    const { payload, status } = await forwardSealedRefresh(relayBaseUrl, profile.name, refreshToken, options);
    assertOk(profile, payload, status, 'refresh', secrets);
    return buildRecord(profile, payload, 'refresh');
  }

  // A / B1: a confidential mode yields the user's client_secret (registered with redact()); a
  // public mode sets client_id and yields nothing. The refresh runs entirely on device.
  const authSecret = await applyTokenAuth(profile, profile.refresh_auth, body, headers);
  if (authSecret !== undefined) secrets.push(authSecret);

  const { payload, status } = await postForm(profile, body, headers, options, secrets);
  assertOk(profile, payload, status, 'refresh', secrets);
  return buildRecord(profile, payload, 'refresh');
}
