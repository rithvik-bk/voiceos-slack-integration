/**
 * Minimal RFC 7519 / RFC 7515 compact-JWS signer, for exactly one purpose: the RFC 7523
 * `private_key_jwt` client assertion the B2a relay hands back (SPEC §5b, Mode B2a).
 *
 * Two algorithms, because those are the two a real authorization server accepts for
 * `private_key_jwt`: ES256 (ECDSA P-256, the modern default) and RS256 (RSA, the ubiquitous
 * one). Both are signature-only asymmetric schemes — the relay holds the private key, the
 * provider verifies with the registered public key, and the assertion proves possession
 * without the secret ever leaving the relay.
 *
 * The one non-obvious wire detail: ES256's JWS signature is the raw R||S concatenation
 * (64 bytes), NOT the ASN.1/DER encoding node emits by default. `dsaEncoding: 'ieee-p1363'`
 * asks node for exactly R||S; forgetting it produces a signature that verifies in a local
 * round-trip and is rejected by every real provider — the same class of stage-only failure
 * the PKCE challenge comment warns about in the engine.
 */

import { createHash, randomBytes, sign as cryptoSign, type KeyObject } from 'node:crypto';

export type JwtAlg = 'ES256' | 'RS256';

/** base64url of a Buffer, no padding — the only encoding JWS speaks. */
function b64url(buf: Buffer): string {
  return buf.toString('base64url');
}

function segment(obj: Record<string, unknown>): string {
  return b64url(Buffer.from(JSON.stringify(obj), 'utf8'));
}

export interface AssertionClaims {
  /** iss AND sub are the client id per RFC 7523 §3 (1) and (2). */
  clientId: string;
  /** aud — the token endpoint the assertion is scoped to. */
  audience: string;
  /** exp/iat/nbf are derived from `nowSeconds` and `ttlSeconds`. */
  nowSeconds: number;
  ttlSeconds: number;
}

/**
 * Build and sign one client-assertion JWT. Returns the compact JWS string and its `jti` and
 * `exp` so the caller can report `expires_in` and (in a future rung) enforce jti uniqueness
 * upstream. A fresh `jti` is drawn per call: the assertion is single-use by intent, and a
 * repeated jti is exactly the replay a strict provider rejects.
 */
export function signClientAssertion(
  privateKey: KeyObject,
  alg: JwtAlg,
  claims: AssertionClaims,
  kid?: string,
): { jwt: string; jti: string; exp: number } {
  const jti = randomBytes(16).toString('base64url');
  const exp = claims.nowSeconds + claims.ttlSeconds;

  const header: Record<string, unknown> = { alg, typ: 'JWT' };
  if (kid !== undefined) header.kid = kid;

  const payload: Record<string, unknown> = {
    iss: claims.clientId,
    sub: claims.clientId,
    aud: claims.audience,
    jti,
    iat: claims.nowSeconds,
    nbf: claims.nowSeconds,
    exp,
  };

  const signingInput = `${segment(header)}.${segment(payload)}`;

  // ES256 → R||S (ieee-p1363); RS256 → PKCS#1 v1.5. Both hash SHA-256 over the signing input.
  const signature =
    alg === 'ES256'
      ? cryptoSign('sha256', Buffer.from(signingInput, 'ascii'), {
          key: privateKey,
          dsaEncoding: 'ieee-p1363',
        })
      : cryptoSign('sha256', Buffer.from(signingInput, 'ascii'), privateKey);

  return { jwt: `${signingInput}.${b64url(signature)}`, jti, exp };
}

/**
 * A stable, non-secret fingerprint of a public key, usable as a `kid`. SHA-256 over the DER
 * SPKI, first 8 bytes, base64url. Deriving the kid from the key means the device and provider
 * can agree on it without the relay inventing an out-of-band identifier.
 */
export function keyThumbprint(publicKey: KeyObject): string {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('base64url').slice(0, 11);
}
