/**
 * The relay's wire and internal types. Self-contained — the relay shares no type with the
 * engine at runtime; the device and the relay agree on these shapes and nothing else.
 */

/* ─────────────────────────────── B2a: assertion signing ─────────────────────────────── */

/**
 * What the device asks the relay to sign. Note what is ABSENT and stays absent: no code, no
 * PKCE verifier, no access or refresh token. In B2a the relay signs a request-scoped
 * assertion and the device performs the exchange itself, so the relay is structurally
 * incapable of seeing a token (SPEC §5b, Mode B2a).
 *
 * The device sends ONLY the provider. The `client_id` (iss/sub) and `audience` (aud) are
 * read from the relay's own config, never from the request: a device that could name the
 * audience could make the relay sign an assertion scoped to an attacker's endpoint. The one
 * thing the device chooses is which provider it wants an assertion for.
 */
export interface AssertionRequest {
  /** Provider identifier — selects the signing key + its pinned client_id and audience. */
  provider: string;
}

export interface AssertionResponse {
  /** The signed, short-lived client-assertion JWT. This is the ONLY thing B2a returns. */
  client_assertion: string;
  /** RFC 7523 §2.2 fixed urn. */
  client_assertion_type: string;
  /** Seconds until the assertion's `exp`. Informational; the JWT is authoritative. */
  expires_in: number;
}

/* ─────────────────────────── B2b: hardened exchange forwarding ─────────────────────────── */

/**
 * The token-endpoint grants the relay will forward on a device's behalf (SPEC §5b, Mode B2b).
 *
 * `refresh_token` and the RFC 8628 `device_code` grant are here for one reason: a B2b provider
 * authenticates EVERY token request with the raw client secret the relay holds, refresh and
 * device-code polls included. Where B2a's relay only ever signs an assertion (so refresh runs on
 * device with a fresh assertion and never touches the relay), B2b's secret physically cannot leave
 * the relay — so silent refresh, and a headless device-code poll, forward through the relay exactly
 * as the initial exchange does, or they cannot happen at all and every expiry becomes a human
 * re-consent. The relay stays touches-each-request-once, never custodial: it holds the secret, sees
 * each token for the instant of one exchange, and seals it onward. It still stores nothing.
 */
export type RelayGrantType =
  | 'authorization_code'
  | 'refresh_token'
  | 'urn:ietf:params:oauth:grant-type:device_code';

/**
 * What the device sends when the provider offers no assertion path and a raw secret must be
 * used (SPEC §5b, Mode B2b). Only the fields this grant needs are populated; each lives in relay
 * memory for the duration of one exchange, and the token that comes back is sealed to
 * `device_public_key` before it leaves the process — the relay itself never returns a readable
 * token. The relay builds the outgoing form ITSELF from these typed fields (never echoing an
 * arbitrary body), so a request can never smuggle an extra parameter to the token endpoint.
 */
export interface ExchangeRequest {
  provider: string;
  /** Which grant to forward — `authorization_code` (initial), `refresh_token`, or device-code. */
  grant_type: RelayGrantType;
  /** The authorization code (authorization_code grant). Held in flight only; never logged. */
  code?: string;
  /** The PKCE verifier for this exchange (authorization_code grant). Held in flight only. */
  code_verifier?: string;
  /** Byte-identical to the value the device sent on its authorize request (authorization_code). */
  redirect_uri?: string;
  /** The refresh token to redeem (refresh_token grant). Held in flight only; never persisted. */
  refresh_token?: string;
  /** The RFC 8628 device code to redeem (device_code grant). Held in flight only. */
  device_code?: string;
  /** The device's single-use X25519 public key, base64url raw 32 bytes. */
  device_public_key: string;
}

/**
 * The sealed provider token response. Only the device — holding the X25519 private key that
 * never left it — can open this. Every field is public-safe: nothing here decrypts without
 * the device key, so this whole object may transit logs, caches, and error reporters
 * without leaking the token (SPEC §5b, ephemeral response encryption).
 */
export interface SealedResponse {
  /** The relay's single-use X25519 public key, base64url raw 32 bytes. Discarded after seal. */
  relay_public_key: string;
  /** AEAD nonce, base64url 12 bytes. */
  iv: string;
  /** The provider's token response body, sealed. base64url. */
  ciphertext: string;
  /** AEAD authentication tag, base64url 16 bytes. */
  tag: string;
  /** Pinned suite identifiers, so the device rejects a silent downgrade. */
  enc: 'A256GCM';
  kdf: 'HKDF-SHA256';
  /** Upstream HTTP status, so the device can classify a provider-side failure. */
  provider_status: number;
}

/* ─────────────────────────────────── errors ─────────────────────────────────── */

export type RelayErrorCode =
  | 'bad_request' // the device sent a malformed or incomplete request
  | 'unknown_provider' // no key material configured for this provider
  | 'provider_unavailable' // the upstream token endpoint could not be reached
  | 'config_invalid'; // the relay's own key material is unusable

export class RelayError extends Error {
  readonly code: RelayErrorCode;
  readonly httpStatus: number;
  constructor(code: RelayErrorCode, message: string, httpStatus = 400) {
    super(message);
    this.name = 'RelayError';
    this.code = code;
    this.httpStatus = httpStatus;
  }
}
