/**
 * RFC 9449 — the DPoP signer produces a REAL, verifiable proof, not a plausible-looking string.
 *
 * The proof is only worth anything if the signature actually verifies against the public key in
 * its own header, with the exact ES256 (raw R‖S) encoding JWS requires. So this reconstructs the
 * signing input, imports the embedded JWK, and verifies the signature with node:crypto — the same
 * check a resource server does. A shaped-but-unsigned proof fails here.
 */

import { describe, expect, it } from 'vitest';
import { createHash, createPublicKey, verify, type JsonWebKey } from 'node:crypto';

import { athOf, createDpopSigner, dpopNonceChallenge, htuOf } from '../src/dpop.ts';

function part(proof: string, index: number): Record<string, unknown> {
  return JSON.parse(Buffer.from(proof.split('.')[index]!, 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
}

describe('DPoP proof (RFC 9449)', () => {
  it('emits a verifiable ES256 JWS with the required claims', () => {
    const signer = createDpopSigner();
    const proof = signer.proof({
      method: 'post',
      url: 'https://api.example.test/v1/things?q=1#frag',
      accessToken: 'the-access-token',
    });

    const [h, p, sig] = proof.split('.');
    const header = part(proof, 0);
    const payload = part(proof, 1);

    expect(header.typ).toBe('dpop+jwt');
    expect(header.alg).toBe('ES256');
    expect(payload.htm).toBe('POST'); // uppercased
    expect(payload.htu).toBe('https://api.example.test/v1/things'); // query + fragment stripped
    expect(payload.ath).toBe(athOf('the-access-token'));
    expect(typeof payload.jti).toBe('string');
    expect(typeof payload.iat).toBe('number');

    // The signature verifies against the JWK embedded in the header — proof it is real ES256.
    const key = createPublicKey({ key: header.jwk as JsonWebKey, format: 'jwk' });
    const ok = verify(
      'sha256',
      Buffer.from(`${h}.${p}`, 'ascii'),
      { key, dsaEncoding: 'ieee-p1363' },
      Buffer.from(sig!, 'base64url'),
    );
    expect(ok).toBe(true);
  });

  it('never embeds a private key component in the header JWK', () => {
    const proof = createDpopSigner().proof({ method: 'GET', url: 'https://x.test/a' });
    const jwk = part(proof, 0).jwk as Record<string, unknown>;
    expect(jwk.d).toBeUndefined(); // `d` is the private scalar — must never ride in a proof
    expect(Object.keys(jwk).sort()).toEqual(['crv', 'kty', 'x', 'y']);
  });

  it('gives every proof a fresh jti (anti-replay)', () => {
    const signer = createDpopSigner();
    const a = part(signer.proof({ method: 'GET', url: 'https://x.test/a' }), 1).jti;
    const b = part(signer.proof({ method: 'GET', url: 'https://x.test/a' }), 1).jti;
    expect(a).not.toBe(b);
  });

  it('carries a server nonce when one is supplied', () => {
    const proof = createDpopSigner().proof({ method: 'GET', url: 'https://x.test/a', nonce: 'N1' });
    expect(part(proof, 1).nonce).toBe('N1');
  });

  it('htuOf and athOf are the RFC forms', () => {
    expect(htuOf('https://h.test:8443/p/q?a=b#c')).toBe('https://h.test:8443/p/q');
    expect(athOf('tok')).toBe(createHash('sha256').update('tok').digest('base64url'));
  });

  it('detects a DPoP-Nonce challenge and ignores a plain 200', () => {
    const challenge = {
      status: 401,
      headers: { get: (n: string) => (n === 'DPoP-Nonce' ? 'abc' : 'DPoP error="use_dpop_nonce"') },
    };
    expect(dpopNonceChallenge(challenge)).toBe('abc');
    const ok = { status: 200, headers: { get: () => null } };
    expect(dpopNonceChallenge(ok)).toBeUndefined();
  });
});
