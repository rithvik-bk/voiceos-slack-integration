/**
 * B2a signing primitive: the client assertion must be a REAL, verifiable JWS — the kind a
 * live authorization server accepts, not one that only round-trips locally. So every test
 * here verifies the signature with node's own `verify` against the public key, exercises the
 * ES256 R||S wire detail explicitly, and pins the RFC 7523 claim set.
 */

import { generateKeyPairSync, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { keyThumbprint, signClientAssertion, type JwtAlg } from '../src/jwt.ts';

function decodeSegment(seg: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(seg, 'base64url').toString('utf8'));
}

function verifyJws(jwt: string, publicKey: KeyObject, alg: JwtAlg): boolean {
  const [h, p, s] = jwt.split('.');
  const signingInput = Buffer.from(`${h}.${p}`, 'ascii');
  const signature = Buffer.from(s ?? '', 'base64url');
  return alg === 'ES256'
    ? cryptoVerify('sha256', signingInput, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature)
    : cryptoVerify('sha256', signingInput, publicKey, signature);
}

const CLAIMS = { clientId: 'app-client-123', audience: 'https://provider.example/oauth/token', nowSeconds: 1_700_000_000, ttlSeconds: 60 };

describe('signClientAssertion (ES256)', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

  it('produces a three-segment compact JWS that verifies against the public key', () => {
    const { jwt } = signClientAssertion(privateKey, 'ES256', CLAIMS);
    expect(jwt.split('.')).toHaveLength(3);
    expect(verifyJws(jwt, publicKey, 'ES256')).toBe(true);
  });

  it('emits an ES256 signature in raw R||S form (64 bytes), not DER', () => {
    const { jwt } = signClientAssertion(privateKey, 'ES256', CLAIMS);
    const sig = Buffer.from(jwt.split('.')[2] ?? '', 'base64url');
    expect(sig.length).toBe(64); // IEEE-P1363; a DER signature would be ~70 and variable
  });

  it('carries the RFC 7523 claim set: iss=sub=client_id, aud, exp=iat+ttl, jti, nbf', () => {
    const { jwt, jti, exp } = signClientAssertion(privateKey, 'ES256', CLAIMS);
    const header = decodeSegment(jwt.split('.')[0] ?? '');
    const payload = decodeSegment(jwt.split('.')[1] ?? '');

    expect(header).toMatchObject({ alg: 'ES256', typ: 'JWT' });
    expect(payload.iss).toBe(CLAIMS.clientId);
    expect(payload.sub).toBe(CLAIMS.clientId);
    expect(payload.aud).toBe(CLAIMS.audience);
    expect(payload.iat).toBe(CLAIMS.nowSeconds);
    expect(payload.nbf).toBe(CLAIMS.nowSeconds);
    expect(payload.exp).toBe(CLAIMS.nowSeconds + CLAIMS.ttlSeconds);
    expect(payload.exp).toBe(exp);
    expect(payload.jti).toBe(jti);
  });

  it('draws a fresh jti per call (single-use by intent → replay-detectable)', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i += 1) seen.add(signClientAssertion(privateKey, 'ES256', CLAIMS).jti);
    expect(seen.size).toBe(200);
  });

  it('includes a kid header only when one is given', () => {
    const withKid = signClientAssertion(privateKey, 'ES256', CLAIMS, 'key-1');
    expect(decodeSegment(withKid.jwt.split('.')[0] ?? '').kid).toBe('key-1');
    const without = signClientAssertion(privateKey, 'ES256', CLAIMS);
    expect('kid' in decodeSegment(without.jwt.split('.')[0] ?? '')).toBe(false);
  });

  it('is rejected under a different key (the signature is real, not decorative)', () => {
    const { jwt } = signClientAssertion(privateKey, 'ES256', CLAIMS);
    const other = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey;
    expect(verifyJws(jwt, other, 'ES256')).toBe(false);
  });
});

describe('signClientAssertion (RS256)', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

  it('produces a JWS that verifies against the RSA public key', () => {
    const { jwt } = signClientAssertion(privateKey, 'RS256', CLAIMS);
    expect(decodeSegment(jwt.split('.')[0] ?? '').alg).toBe('RS256');
    expect(verifyJws(jwt, publicKey, 'RS256')).toBe(true);
  });

  it('tamper in the payload breaks verification', () => {
    const { jwt } = signClientAssertion(privateKey, 'RS256', CLAIMS);
    const [h, , s] = jwt.split('.');
    const forgedPayload = Buffer.from(JSON.stringify({ ...CLAIMS, aud: 'https://evil.example' }), 'utf8').toString('base64url');
    expect(verifyJws(`${h}.${forgedPayload}.${s}`, publicKey, 'RS256')).toBe(false);
  });
});

describe('keyThumbprint', () => {
  it('is stable for a key and differs across keys', () => {
    const a = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey;
    const b = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey;
    expect(keyThumbprint(a)).toBe(keyThumbprint(a));
    expect(keyThumbprint(a)).not.toBe(keyThumbprint(b));
    expect(keyThumbprint(a)).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});
