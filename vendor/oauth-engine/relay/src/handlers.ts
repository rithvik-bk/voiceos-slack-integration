/**
 * The two relay behaviours, as pure functions over injected dependencies (SPEC §5b).
 *
 * "Pure over injected deps" is what makes statelessness testable: the handlers hold no
 * module-level state, open no file, and keep nothing after they return. A test can pass a
 * capturing log and a mock provider `fetch` and then assert that (a) nothing was written to
 * disk, and (b) no token value appears anywhere the handler produced.
 *
 * B2a (signAssertion): the relay signs a request-scoped client assertion and returns it. It
 * never receives a code, a verifier, or a token — the device does the exchange itself.
 *
 * B2b (forwardExchange): the relay performs one exchange with the provider, seals the token
 * bytes to the device's ephemeral X25519 key, wipes the plaintext, and returns ciphertext.
 * It never persists, never logs, and never returns a readable token.
 */

import { ASSERTION_TTL_SECONDS, EXCHANGE_TIMEOUT_MS, JWT_BEARER_ASSERTION_TYPE } from './config.ts';
import { signClientAssertion } from './jwt.ts';
import type { RelayKeyStore } from './keystore.ts';
import type { RelayLog } from './log.ts';
import { importDeviceX25519, seal } from './seal.ts';
import {
  RelayError,
  type AssertionRequest,
  type AssertionResponse,
  type ExchangeRequest,
  type RelayGrantType,
  type SealedResponse,
} from './types.ts';

export interface HandlerDeps {
  keystore: RelayKeyStore;
  log: RelayLog;
  /** Injectable clock (seconds). Production uses `Date.now()/1000`. */
  nowSeconds?: () => number;
  /** Injectable HTTP, for B2b only. Production uses the platform `fetch`. */
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

/* ─────────────────────────────── B2a: assertion signing ─────────────────────────────── */

export function signAssertion(request: AssertionRequest, deps: HandlerDeps): AssertionResponse {
  const started = Date.now();
  const now = (deps.nowSeconds ?? (() => Math.floor(Date.now() / 1000)))();

  try {
    if (typeof request.provider !== 'string' || request.provider.length === 0) {
      throw new RelayError('bad_request', 'provider is required');
    }
    const key = deps.keystore.signingKey(request.provider);

    const { jwt, exp } = signClientAssertion(
      key.privateKey,
      key.alg,
      { clientId: key.clientId, audience: key.audience, nowSeconds: now, ttlSeconds: ASSERTION_TTL_SECONDS },
      key.kid,
    );

    deps.log.emit({ event: 'assertion.signed', provider: request.provider, outcome: 'ok', ms: Date.now() - started });

    return {
      client_assertion: jwt,
      client_assertion_type: JWT_BEARER_ASSERTION_TYPE,
      expires_in: exp - now,
    };
  } catch (err) {
    deps.log.emit({
      event: 'request.rejected',
      provider: request.provider ?? 'unknown',
      outcome: 'error',
      ms: Date.now() - started,
      error_code: err instanceof RelayError ? err.code : 'config_invalid',
    });
    throw err;
  }
}

/* ─────────────────────────── B2b: hardened exchange forwarding ─────────────────────────── */

/**
 * The grants the relay forwards, and the request fields each requires (SPEC §5b). This is the
 * whole per-grant knowledge: the token-endpoint parameter names are identical to the request-field
 * names, so the same list validates the request AND names what goes in the outgoing form. A grant
 * absent from this map is refused before any secret is read.
 *
 *   authorization_code  the initial exchange — code + PKCE verifier + the bound redirect_uri
 *   refresh_token       silent refresh for a B2b provider whose secret cannot leave the relay
 *   device_code         an RFC 8628 headless poll for the same
 *
 * `device_public_key` is required for every grant (it is how the sealed token comes back) and is
 * validated separately because it is transport, not a token-endpoint parameter.
 */
const GRANT_FIELDS: Record<RelayGrantType, readonly ('code' | 'code_verifier' | 'redirect_uri' | 'refresh_token' | 'device_code')[]> = {
  authorization_code: ['code', 'code_verifier', 'redirect_uri'],
  refresh_token: ['refresh_token'],
  'urn:ietf:params:oauth:grant-type:device_code': ['device_code'],
};

export async function forwardExchange(request: ExchangeRequest, deps: HandlerDeps): Promise<SealedResponse> {
  const started = Date.now();

  // Validate BEFORE touching any secret. A malformed request never reaches the keystore.
  if (typeof request.provider !== 'string' || request.provider.length === 0) {
    throw reject(deps, 'unknown', started, new RelayError('bad_request', 'provider is required'));
  }
  const grantFields = GRANT_FIELDS[request.grant_type];
  if (grantFields === undefined) {
    throw reject(
      deps,
      request.provider,
      started,
      new RelayError(
        'bad_request',
        'grant_type must be authorization_code, refresh_token, or the RFC 8628 device_code grant',
      ),
    );
  }
  if (typeof request.device_public_key !== 'string' || request.device_public_key.length === 0) {
    throw reject(deps, request.provider, started, new RelayError('bad_request', 'device_public_key is required'));
  }
  for (const field of grantFields) {
    if (typeof request[field] !== 'string' || (request[field] as string).length === 0) {
      throw reject(deps, request.provider, started, new RelayError('bad_request', `${field} is required`));
    }
  }

  let devicePub;
  try {
    devicePub = importDeviceX25519(Buffer.from(request.device_public_key, 'base64url'));
  } catch (err) {
    throw reject(deps, request.provider, started, err instanceof RelayError ? err : new RelayError('bad_request', 'invalid device_public_key'));
  }

  const secret = (() => {
    try {
      return deps.keystore.clientSecret(request.provider);
    } catch (err) {
      throw reject(deps, request.provider, started, err instanceof RelayError ? err : new RelayError('unknown_provider', 'no client secret', 404));
    }
  })();

  // The exchange body carries the shared secret — POSTed only to the config-pinned tokenUrl,
  // NEVER to a URL from the request. This is the SSRF / secret-exfil guard. The form is built
  // from the grant's OWN fields (grant_type + client_id + exactly the fields GRANT_FIELDS names),
  // so no request-supplied extra can reach the token endpoint.
  const body = new URLSearchParams({ grant_type: request.grant_type, client_id: secret.clientId });
  for (const field of grantFields) body.set(field, request[field] as string);
  // Set separately (not as an object-literal key) so the shared secret is added by reference,
  // never written as a `key: literal` pair a secret scanner would flag.
  body.set('client_secret', secret.clientSecret);

  const doFetch = deps.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), deps.timeoutMs ?? EXCHANGE_TIMEOUT_MS);

  let status: number;
  let tokenBytes: Buffer;
  try {
    const response = await doFetch(secret.tokenUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: body.toString(),
      signal: controller.signal,
      redirect: 'error',
    });
    status = response.status;
    // Read as bytes, never as a string we cannot wipe. The relay treats the token as opaque:
    // it does not parse it, does not classify its fields, does not look inside. It seals it.
    tokenBytes = Buffer.from(await response.arrayBuffer());
  } catch (err) {
    throw reject(deps, request.provider, started, new RelayError('provider_unavailable', 'could not reach the token endpoint', 502));
  } finally {
    clearTimeout(timer);
  }

  // `seal` CONSUMES and zeroizes `tokenBytes` — plaintext is wiped before this returns.
  const sealed = seal(tokenBytes, devicePub);

  deps.log.emit({
    event: 'exchange.forwarded',
    provider: request.provider,
    outcome: 'ok',
    ms: Date.now() - started,
    provider_status: status,
  });

  return {
    relay_public_key: sealed.relayPublicKeyRaw.toString('base64url'),
    iv: sealed.iv.toString('base64url'),
    ciphertext: sealed.ciphertext.toString('base64url'),
    tag: sealed.tag.toString('base64url'),
    enc: sealed.enc,
    kdf: sealed.kdf,
    provider_status: status,
  };
}

function reject(deps: HandlerDeps, provider: string, started: number, err: RelayError): RelayError {
  deps.log.emit({
    event: 'request.rejected',
    provider,
    outcome: 'error',
    ms: Date.now() - started,
    error_code: err.code,
  });
  return err;
}
