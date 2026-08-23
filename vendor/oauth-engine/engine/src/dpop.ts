/**
 * RFC 9449 — DPoP (Demonstrating Proof-of-Possession), the client half of the `dpop`
 * sender-constraint (SPEC §1, §18).
 *
 * A bearer token is a bearer instrument: whoever holds the string can spend it. A
 * sender-constrained token is bound to a key the client holds, so a token stolen from a log,
 * a proxy, or a crash dump is inert without the private key that never left the process. The
 * profile's `sender_constraint` axis decides which scheme every subsequent API call is signed
 * with; where it is `dpop`, {@link authClient} attaches a fresh DPoP proof to each request
 * instead of a plain `Authorization: Bearer`. This module is that proof, and nothing else —
 * it holds a keypair and signs, it does no network and no policy.
 *
 * The proof is a compact JWS (RFC 9449 §4.2):
 *   - header  `{ typ: "dpop+jwt", alg: "ES256", jwk: <public EC P-256 key> }`
 *   - payload `{ jti, htm, htu, iat, [nonce], [ath] }`
 *   - signature  ES256 (ECDSA P-256 / SHA-256) over `b64url(header).b64url(payload)`, in the
 *     JOSE raw R‖S encoding the JWS spec requires (NOT the DER encoding OpenSSL emits by
 *     default — `dsaEncoding: 'ieee-p1363'` asks node:crypto for the raw form directly, so
 *     there is no hand-rolled DER→JOSE conversion to get wrong).
 *
 * `htu` is the request URL with query and fragment stripped (RFC 9449 §4.2, `htu`), `htm` the
 * uppercase method, `ath` the base64url SHA-256 of the access token when one is presented, and
 * `jti` a fresh 128-bit random per proof so a captured proof cannot be replayed. `nonce` is
 * filled from a server's `DPoP-Nonce` challenge (RFC 9449 §8) — {@link authClient} adopts the
 * nonce and re-signs, which is why `proof()` takes it per-call rather than baking it in.
 *
 * Zero runtime dependencies: node:crypto only. The keypair is generated once per signer and
 * lives only in memory for the signer's lifetime.
 */

import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';

/** The claims that vary per request; everything else is fixed by the signer's key. */
export interface DpopProofInput {
  /** HTTP method. Serialized uppercase into `htm`. */
  method: string;
  /** Full request URL. Query and fragment are stripped for `htu`. */
  url: string;
  /**
   * The access token this proof accompanies. When present, its base64url SHA-256 is bound into
   * the proof as `ath` (RFC 9449 §4.2), so the proof cannot be lifted onto a different token.
   * Absent for a token-request proof (not used by the wrapper today, but the shape is correct).
   */
  accessToken?: string;
  /** A server-supplied `DPoP-Nonce` (RFC 9449 §8), echoed into the proof on a re-sign. */
  nonce?: string;
  /** Injected in tests for determinism. Production uses the real clock. */
  now?: number;
}

/** A per-connection DPoP signer: one EC P-256 keypair, one `proof()` per request. */
export interface DpopSigner {
  /** The public JWK bound into every proof header — the key the token is proven against. */
  readonly publicJwk: Readonly<Record<string, string>>;
  /** Build a compact-JWS DPoP proof for one request. */
  proof(input: DpopProofInput): string;
}

/** base64url of a UTF-8 string. */
function b64urlString(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64url');
}

/**
 * `htu`: the request URI without query or fragment (RFC 9449 §4.2). Built from origin + path
 * so a `?` or `#` a caller left on the URL never leaks into the signed claim, and so two calls
 * to the same endpoint with different query strings produce the same `htu` — which is what the
 * resource server checks against.
 */
export function htuOf(url: string): string {
  const u = new URL(url);
  return `${u.origin}${u.pathname}`;
}

/** `ath`: base64url( SHA-256( access_token ) ), the access-token hash claim (RFC 9449 §4.2). */
export function athOf(accessToken: string): string {
  return createHash('sha256').update(accessToken, 'utf8').digest('base64url');
}

/**
 * Create a DPoP signer backed by a freshly generated EC P-256 keypair.
 *
 * The keypair is the whole point of proof-of-possession: it never leaves this object, is never
 * serialized, and dies with the signer. `keyPair` is injectable ONLY so a test can assert a
 * stable thumbprint; production always generates.
 */
export function createDpopSigner(keyPair?: { publicKey: KeyObject; privateKey: KeyObject }): DpopSigner {
  const { publicKey, privateKey } =
    keyPair ?? generateKeyPairSync('ec', { namedCurve: 'P-256' });

  const rawJwk = publicKey.export({ format: 'jwk' }) as Record<string, string>;
  // RFC 9449 requires the REQUIRED members of the JWK, in the canonical order used for a
  // thumbprint: crv, kty, x, y. Extra members (e.g. a stray `d` — which an EC public key never
  // carries, but be defensive) are dropped so a private component can never ride into a header.
  const publicJwk: Record<string, string> = {
    crv: rawJwk.crv!,
    kty: rawJwk.kty!,
    x: rawJwk.x!,
    y: rawJwk.y!,
  };

  const header = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: publicJwk,
  };
  const encodedHeader = b64urlString(JSON.stringify(header));

  return {
    publicJwk: Object.freeze({ ...publicJwk }),
    proof(input: DpopProofInput): string {
      const payload: Record<string, string | number> = {
        jti: randomBytes(16).toString('base64url'),
        htm: input.method.toUpperCase(),
        htu: htuOf(input.url),
        iat: Math.floor((input.now ?? Date.now()) / 1000),
      };
      if (input.nonce !== undefined && input.nonce !== '') payload.nonce = input.nonce;
      if (input.accessToken !== undefined && input.accessToken !== '') {
        payload.ath = athOf(input.accessToken);
      }

      const signingInput = `${encodedHeader}.${b64urlString(JSON.stringify(payload))}`;
      // `ieee-p1363` = the raw R‖S encoding JWS/JOSE mandates. Without it node emits DER, which a
      // resource server rejects as a malformed ES256 signature.
      const signature = sign('sha256', Buffer.from(signingInput, 'ascii'), {
        key: privateKey,
        dsaEncoding: 'ieee-p1363',
      }).toString('base64url');

      return `${signingInput}.${signature}`;
    },
  };
}

/**
 * Does this response carry a DPoP nonce challenge (RFC 9449 §8)? A resource server that wants a
 * server-chosen nonce answers `401` with `WWW-Authenticate: DPoP … error="use_dpop_nonce"` and a
 * `DPoP-Nonce` header. That is NOT an expired token — it is "re-sign with this nonce" — so the
 * wrapper must retry with the nonce BEFORE it ever spends a refresh token.
 */
export function dpopNonceChallenge(response: {
  status: number;
  headers: { get(name: string): string | null };
}): string | undefined {
  if (response.status !== 401) return undefined;
  const nonce = response.headers.get('DPoP-Nonce');
  if (nonce === null || nonce === '') return undefined;
  const wwwAuth = response.headers.get('WWW-Authenticate') ?? '';
  // A nonce header with a use_dpop_nonce error is the unambiguous challenge; a nonce header
  // alone (some servers pre-seed one on an otherwise-normal 401) is still worth adopting.
  if (/use_dpop_nonce/i.test(wwwAuth) || /\bDPoP\b/i.test(wwwAuth) || wwwAuth === '') {
    return nonce;
  }
  return nonce;
}
