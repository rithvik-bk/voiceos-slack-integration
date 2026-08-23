/**
 * The engine-side relay client — the DEVICE leg of confidential custody (SPEC §5b). Closes
 * C-6 / C-7 end to end: wave 1 built the stateless relay SERVER (the `relay/` package); this
 * is the on-device half that talks to it, so B2a and B2b custody now work end to end.
 *
 * Two behaviours, selected in exchange.ts from the profile's DERIVED `relay_mode` — a
 * capability value, never a provider name (INV-CONFIG-1):
 *
 *   B2a (assertion_signing). The provider supports `private_key_jwt` (RFC 7523). The relay
 *     holds a private key and returns only a short-lived, request-scoped client-assertion JWT.
 *     The DEVICE then performs the token exchange itself, over its own TLS to the provider,
 *     attaching that assertion. The relay sees an assertion request and returns a signature —
 *     it never sees the authorization code, the PKCE verifier, or any token. This is the
 *     preferred B2 path.
 *
 *   B2b (exchange_forwarding). The provider requires a raw shared secret and offers no
 *     assertion path, so the relay must perform the one exchange. The device generates a
 *     single-use X25519 keypair and sends the public key; the relay seals the provider's token
 *     bytes to it (ECDH → HKDF-SHA256 → AES-256-GCM) and returns ciphertext. Only THIS device,
 *     holding a private key that never left it, can open it — the token is unreadable on every
 *     surface downstream of the relay process. The device opens the seal here.
 *
 * The custody invariants this module upholds, each a line in the SPEC audit sentence:
 *   - The relay's SECRET never reaches the engine. B2a returns a signature; B2b returns a
 *     sealed blob. Neither is the app secret, and the engine stores nothing of the relay's.
 *   - The seal suite is PINNED to the relay's (`A256GCM` / `HKDF-SHA256` / the fixed HKDF
 *     info). A response advertising any other suite is refused as a downgrade — an attacker
 *     must not be able to negotiate the seal down to something weaker via a crafted response.
 *   - The opened plaintext is zeroized the instant JSON.parse has consumed it.
 *
 * Zero shared runtime code with the relay package (SPEC Part 2 §5): the device and the relay
 * agree on the wire shapes and the crypto suite and NOTHING else. This file re-derives the
 * `open()` half of the seal from `node:crypto` rather than importing `relay/src`, so the engine
 * keeps its single-package, zero-dependency boundary. The engine's interop with the real relay
 * is proven end to end by `engine/test/relay-client.test.ts`, which drives the actual
 * `relay/` server.
 */

import {
  createDecipheriv,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  type KeyObject,
} from 'node:crypto';

import { configuredRelayBaseUrl } from './config.ts';
import { EngineError } from './errors.ts';
import { redact, safeProviderMessage } from './redact.ts';

/* ─────────────────────────────── pinned wire + crypto constants ─────────────────────────────── */

/** The 12-byte ASN.1 SPKI prefix for an X25519 public key (RFC 8410 id-X25519). Mirrors the relay. */
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const X25519_RAW_LEN = 32;

/** HKDF domain separation — byte-identical to the relay's `SEAL_HKDF_INFO`, or the key won't derive. */
const SEAL_HKDF_INFO = 'handshake-relay/b2b/response-encryption/v1';

/** The one seal suite this engine accepts. Anything else in a response is a downgrade attempt. */
const SEAL_ENC = 'A256GCM';
const SEAL_KDF = 'HKDF-SHA256';

/** RFC 7523 §2.2 — the client_assertion_type sent to the provider when the relay omits it. */
const JWT_BEARER_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/** A relay that has not answered in this long is a hung flow, not a slow network. */
const RELAY_TIMEOUT_MS = 20_000;

/* ─────────────────────────────────────── options ─────────────────────────────────────── */

/**
 * Injected in tests; production reads the relay URL from the environment and uses the platform
 * `fetch`. `relayBaseUrl` overrides the configured default (a test points it at a loopback relay).
 */
export interface RelayClientOptions {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  relayBaseUrl?: string;
}

/** The device leg's view of one exchange — the same three inputs `exchangeCode` already holds. */
export interface RelayExchangeInput {
  code: string;
  verifier: string;
  redirectUri: string;
}

/* ────────────────────────────────── base URL resolution ────────────────────────────────── */

/**
 * The relay base URL for a confidential-custody exchange: an explicit override (tests, an
 * embedder) first, else the deployment's configured relay. A B2a/B2b provider with no relay
 * configured is a config error the operator can act on, never a silent hang mid-connect.
 */
export function resolveRelayBaseUrl(options: RelayClientOptions): string {
  const url = options.relayBaseUrl ?? configuredRelayBaseUrl();
  if (url === undefined || url.length === 0) {
    throw new EngineError('config_invalid', 'this provider needs a relay, but none is configured', {
      hint: `B2a/B2b custody routes the token exchange through the stateless HANDSHAKE relay. Set ${'HANDSHAKE_RELAY_URL'} (or pass relayBaseUrl) to the relay's base URL, e.g. https://relay.example.com.`,
    });
  }
  return url.replace(/\/+$/, '');
}

/* ────────────────────────────────────── HTTP to relay ────────────────────────────────────── */

/** Map the relay's typed error code to the engine's error surface. A bad_request is OUR bug. */
function relayCodeToEngine(code: string): 'config_invalid' | 'provider_error' {
  // provider_unavailable = the relay could not reach the upstream token endpoint → transient.
  // unknown_provider / config_invalid / bad_request = misconfiguration on our or the relay's side.
  return code === 'provider_unavailable' ? 'provider_error' : 'config_invalid';
}

/**
 * POST one JSON request to the relay and return its parsed JSON body. A non-2xx response is a
 * typed `{ error, message }` from the relay; it is mapped to an `EngineError` and never echoed
 * wholesale (the message is written by the relay codebase, but we still route it through the
 * credential allowlist for defence in depth).
 */
async function relayPost(
  baseUrl: string,
  path: string,
  payload: Record<string, string>,
  options: RelayClientOptions,
  secrets: ReadonlyArray<string | undefined>,
): Promise<unknown> {
  const doFetch = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? RELAY_TIMEOUT_MS);
  const url = `${baseUrl}${path}`;

  let response: Response;
  try {
    response = await doFetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
      redirect: 'error',
    });
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : 'network failure';
    throw new EngineError('provider_error', 'could not reach the relay', {
      hint: `POST ${url} failed: ${redact(detail, secrets)}`,
      cause,
    });
  } finally {
    clearTimeout(timer);
  }

  const text = await response.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    // Never echo the body: a non-JSON relay response is exactly where a proxy/error page could
    // be carrying credential-shaped bytes.
    throw new EngineError('provider_error', 'the relay returned a non-JSON body', {
      hint: `HTTP ${response.status} from ${url}, ${text.length} bytes that are not JSON.`,
    });
  }

  if (response.status < 200 || response.status >= 300) {
    const errorCode =
      parsed !== null && typeof parsed === 'object' && typeof (parsed as { error?: unknown }).error === 'string'
        ? (parsed as { error: string }).error
        : 'config_invalid';
    const providerMessage = safeProviderMessage(parsed, secrets);
    throw new EngineError(relayCodeToEngine(errorCode), 'the relay refused the request', {
      hint: `HTTP ${response.status} from ${url} (relay error: ${errorCode}).`,
      ...(providerMessage === undefined ? {} : { providerMessage }),
    });
  }

  return parsed;
}

/* ─────────────────────────────── B2a: fetch a client assertion ─────────────────────────────── */

/** What the device needs back from the relay to authenticate its own on-device exchange. */
export interface ClientAssertion {
  client_assertion: string;
  client_assertion_type: string;
}

/**
 * B2a — ask the relay to sign a client assertion for `provider`. The device does the exchange
 * itself afterwards (in exchange.ts), so the relay never sees the code, verifier, or token.
 * Only the provider name travels: the relay reads iss/sub/aud from its own pinned config, so a
 * device cannot make it sign an assertion scoped to an attacker's endpoint.
 */
export async function fetchClientAssertion(
  baseUrl: string,
  provider: string,
  options: RelayClientOptions,
): Promise<ClientAssertion> {
  const parsed = (await relayPost(baseUrl, '/v1/assertion', { provider }, options, [])) as {
    client_assertion?: unknown;
    client_assertion_type?: unknown;
  };

  if (typeof parsed.client_assertion !== 'string' || parsed.client_assertion.length === 0) {
    throw new EngineError('provider_error', 'the relay returned no client assertion', {
      hint: `POST ${baseUrl}/v1/assertion returned a body with no usable client_assertion.`,
    });
  }
  const type =
    typeof parsed.client_assertion_type === 'string' && parsed.client_assertion_type.length > 0
      ? parsed.client_assertion_type
      : JWT_BEARER_ASSERTION_TYPE;

  return { client_assertion: parsed.client_assertion, client_assertion_type: type };
}

/* ─────────────────────────── B2b: forward one grant, open the seal ─────────────────────────── */

/** RFC 8628 §3.4 grant type — a headless device-code poll forwarded through the B2b relay. */
const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

/** The grant-specific fields the relay needs to rebuild the outgoing form itself (SSRF guard). */
interface RelayGrantFields {
  grant_type: 'authorization_code' | 'refresh_token' | typeof DEVICE_CODE_GRANT;
  code?: string;
  code_verifier?: string;
  redirect_uri?: string;
  refresh_token?: string;
  device_code?: string;
}

/**
 * The B2b engine of every forwarded grant: generate a single-use X25519 keypair, send the public
 * key with the grant's typed fields, and OPEN the sealed token on this device. Returns the
 * provider's token response payload (parsed JSON) and the upstream HTTP status, so the caller runs
 * the exact same `assertOk` / `buildRecord` it runs for a direct request — the relay is invisible
 * past this seam.
 *
 * All three B2b grants (exchange, refresh, device-code poll) share this one crypto path; they
 * differ only in which typed fields they carry, so the seal open, the downgrade guard, and the
 * plaintext zeroization live in exactly one place. The plaintext token buffer is wiped the instant
 * `JSON.parse` has consumed it, so it does not sit in a heap image taken after the flow (the
 * device-side mirror of the relay's `zeroize`).
 */
async function forwardSealedGrant(
  baseUrl: string,
  provider: string,
  grant: RelayGrantFields,
  options: RelayClientOptions,
  secrets: ReadonlyArray<string | undefined>,
): Promise<{ payload: unknown; status: number }> {
  const device = generateKeyPairSync('x25519');
  const devicePublicKeyRaw = exportRawX25519(device.publicKey);

  const request: Record<string, string> = {
    provider,
    grant_type: grant.grant_type,
    device_public_key: devicePublicKeyRaw.toString('base64url'),
  };
  // Only the fields THIS grant carries travel; the relay builds its own token-endpoint form.
  if (grant.code !== undefined) request.code = grant.code;
  if (grant.code_verifier !== undefined) request.code_verifier = grant.code_verifier;
  if (grant.redirect_uri !== undefined) request.redirect_uri = grant.redirect_uri;
  if (grant.refresh_token !== undefined) request.refresh_token = grant.refresh_token;
  if (grant.device_code !== undefined) request.device_code = grant.device_code;

  const sealed = (await relayPost(baseUrl, '/v1/exchange', request, options, secrets)) as Record<string, unknown>;

  // Downgrade guard: refuse anything but the pinned suite BEFORE touching the ciphertext.
  if (sealed.enc !== SEAL_ENC || sealed.kdf !== SEAL_KDF) {
    throw new EngineError('provider_error', 'the relay advertised an unexpected seal suite', {
      hint: `Expected enc=${SEAL_ENC} kdf=${SEAL_KDF}; a device must reject a silent downgrade of the return-leg encryption.`,
    });
  }

  const plaintext = openSealed(sealed, device.privateKey);
  const status = typeof sealed.provider_status === 'number' ? sealed.provider_status : 0;
  try {
    return { payload: JSON.parse(plaintext.toString('utf8')), status };
  } catch {
    throw new EngineError('provider_error', 'the sealed token response is not valid JSON', {
      hint: `The relay's ${status} response opened but did not parse as JSON.`,
    });
  } finally {
    zeroize(plaintext);
  }
}

/**
 * B2b — forward one authorization-code exchange through the relay and open the sealed token here.
 */
export function forwardSealedExchange(
  baseUrl: string,
  provider: string,
  input: RelayExchangeInput,
  options: RelayClientOptions,
): Promise<{ payload: unknown; status: number }> {
  return forwardSealedGrant(
    baseUrl,
    provider,
    { grant_type: 'authorization_code', code: input.code, code_verifier: input.verifier, redirect_uri: input.redirectUri },
    options,
    [input.code, input.verifier],
  );
}

/**
 * B2b — forward one refresh through the relay (SPEC §5b). A B2b provider authenticates its refresh
 * with the raw client secret the relay holds and the device must never see, so silent refresh
 * forwards through the relay exactly as the initial exchange does; without this, every B2b token
 * expiry would force a human re-consent. The relay sees this one refreshed token for the instant
 * of the exchange, seals it onward, and stores nothing.
 */
export function forwardSealedRefresh(
  baseUrl: string,
  provider: string,
  refreshToken: string,
  options: RelayClientOptions,
): Promise<{ payload: unknown; status: number }> {
  return forwardSealedGrant(
    baseUrl,
    provider,
    { grant_type: 'refresh_token', refresh_token: refreshToken },
    options,
    [refreshToken],
  );
}

/**
 * B2b — forward one RFC 8628 device-code poll through the relay (SPEC §5b, §3 path 3). A headless
 * B2b provider authenticates its device-code poll with the relay's client secret, so the poll
 * forwards through the relay and the token comes back sealed, the same as the exchange and refresh.
 */
export function forwardSealedDeviceCode(
  baseUrl: string,
  provider: string,
  deviceCode: string,
  options: RelayClientOptions,
): Promise<{ payload: unknown; status: number }> {
  return forwardSealedGrant(
    baseUrl,
    provider,
    { grant_type: DEVICE_CODE_GRANT, device_code: deviceCode },
    options,
    [deviceCode],
  );
}

/* ──────────────────────────────────── seal open (device side) ──────────────────────────────────── */

/** Wrap a raw 32-byte X25519 public key into a node KeyObject (the device's mirror of the relay). */
function importRawX25519(raw: Buffer): KeyObject {
  if (raw.length !== X25519_RAW_LEN) {
    throw new EngineError('provider_error', 'the relay public key is not a valid X25519 point', {
      hint: `Expected ${X25519_RAW_LEN} raw bytes, got ${raw.length}.`,
    });
  }
  const spki = Buffer.concat([X25519_SPKI_PREFIX, raw]);
  try {
    return createPublicKey({ key: spki, format: 'der', type: 'spki' });
  } catch (cause) {
    throw new EngineError('provider_error', 'the relay public key is not a valid X25519 point', {
      hint: 'The sealed response carried a relay_public_key that is not on the curve.',
      cause,
    });
  }
}

/** Export a node X25519 public KeyObject to the raw 32 bytes for the wire. */
function exportRawX25519(publicKey: KeyObject): Buffer {
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return spki.subarray(spki.length - X25519_RAW_LEN);
}

/** Best-effort wipe of the one plaintext copy we hold. Mirrors the relay's `zeroize`. */
function zeroize(...buffers: Array<Buffer | undefined>): void {
  for (const b of buffers) if (b !== undefined) b.fill(0);
}

function requireField(sealed: Record<string, unknown>, field: string): Buffer {
  const value = sealed[field];
  if (typeof value !== 'string' || value.length === 0) {
    throw new EngineError('provider_error', 'the sealed response is missing a required field', {
      hint: `Field '${field}' is absent or not a base64url string.`,
    });
  }
  return Buffer.from(value, 'base64url');
}

/**
 * Open a {@link forwardSealedExchange} response: ECDH the device private key with the relay's
 * ephemeral public key, stretch it through HKDF-SHA256 into the AES-256-GCM key, and decrypt.
 * The derivation is byte-identical to the relay's `seal`, or the AEAD tag will not verify.
 */
function openSealed(sealed: Record<string, unknown>, devicePrivateKey: KeyObject): Buffer {
  const relayPublicKeyRaw = requireField(sealed, 'relay_public_key');
  const iv = requireField(sealed, 'iv');
  const tag = requireField(sealed, 'tag');
  const ciphertext = requireField(sealed, 'ciphertext');

  const relayPublicKey = importRawX25519(relayPublicKeyRaw);
  const sharedSecret = diffieHellman({ privateKey: devicePrivateKey, publicKey: relayPublicKey });

  let derivedKey: Buffer | undefined;
  try {
    derivedKey = Buffer.from(
      hkdfSync('sha256', sharedSecret, Buffer.alloc(0), Buffer.from(SEAL_HKDF_INFO, 'utf8'), 32),
    );
    const decipher = createDecipheriv('aes-256-gcm', derivedKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (cause) {
    throw new EngineError('provider_error', 'could not open the sealed token response', {
      hint: 'The AEAD authentication tag did not verify — a tampered, truncated, or wrong-key seal.',
      cause,
    });
  } finally {
    zeroize(sharedSecret, derivedKey);
  }
}
