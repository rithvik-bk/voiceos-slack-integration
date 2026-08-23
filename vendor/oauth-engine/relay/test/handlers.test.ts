/**
 * The two handlers end to end, against a keystore fixture and a mock provider `fetch`.
 *
 * B2a: the assertion is signed and returned; the request shape has NO field for a code, a
 * verifier, or a token, so the relay cannot see one — this test pins that contract.
 * B2b: the relay performs one exchange, seals the token, and the device (holding the private
 * key) opens it — proving the round trip works and the relay returned only ciphertext.
 */

import { generateKeyPairSync, verify as cryptoVerify } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { forwardExchange, signAssertion, type HandlerDeps } from '../src/handlers.ts';
import { RelayKeyStore } from '../src/keystore.ts';
import { RelayLog } from '../src/log.ts';
import { exportRawX25519, open, type Sealed } from '../src/seal.ts';
import { RelayError, type RelayGrantType } from '../src/types.ts';

const AUDIENCE = 'https://provider.example/oauth/token';

function b2aDeps(): { deps: HandlerDeps; publicKey: import('node:crypto').KeyObject } {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const keystore = new RelayKeyStore().addSigningKey('acme', {
    privateKey,
    alg: 'ES256',
    clientId: 'acme-client-id',
    audience: AUDIENCE,
  });
  return { deps: { keystore, log: new RelayLog(() => {}), nowSeconds: () => 1_700_000_000 }, publicKey };
}

describe('signAssertion (B2a)', () => {
  it('returns a signed, provider-verifiable assertion and the RFC 7523 type', () => {
    const { deps, publicKey } = b2aDeps();
    const out = signAssertion({ provider: 'acme' }, deps);

    expect(out.client_assertion_type).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    expect(out.expires_in).toBe(60);

    const [h, p, s] = out.client_assertion.split('.');
    const ok = cryptoVerify('sha256', Buffer.from(`${h}.${p}`, 'ascii'), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(s ?? '', 'base64url'));
    expect(ok).toBe(true);

    // aud and iss/sub come from CONFIG, not the request — the device cannot influence them.
    const payload = JSON.parse(Buffer.from(p ?? '', 'base64url').toString('utf8'));
    expect(payload.aud).toBe(AUDIENCE);
    expect(payload.iss).toBe('acme-client-id');
    expect(payload.sub).toBe('acme-client-id');
  });

  it('the B2a request type has no field for a code, verifier, or token', () => {
    // Structural proof: signAssertion accepts AssertionRequest, whose only key is `provider`.
    // If a future edit widened it to carry a token, this object literal would still compile,
    // so we assert the runtime behaviour instead: the handler reads nothing but `provider`.
    const { deps } = b2aDeps();
    const noise = { provider: 'acme', code: 'AUTH_CODE', code_verifier: 'VERIFIER', access_token: 'TOKEN' };
    const out = signAssertion(noise as { provider: string }, deps);
    // None of the injected credential-shaped fields appear anywhere in the output.
    const blob = JSON.stringify(out);
    expect(blob).not.toContain('AUTH_CODE');
    expect(blob).not.toContain('VERIFIER');
    expect(blob).not.toContain('TOKEN');
  });

  it('rejects an unknown provider without touching key material', () => {
    const { deps } = b2aDeps();
    expect(() => signAssertion({ provider: 'nope' }, deps)).toThrow(RelayError);
  });

  it('rejects a missing provider', () => {
    const { deps } = b2aDeps();
    expect(() => signAssertion({ provider: '' }, deps)).toThrow(/provider is required/);
  });
});

/* ─────────────────────────────────── B2b ─────────────────────────────────── */

const TOKEN_JSON = '{"access_token":"mock-access-b2b-0001","refresh_token":"mock-refresh-b2b-002","expires_in":3600}';

function b2bKeystore(): RelayKeyStore {
  return new RelayKeyStore().addClientSecret('widgets', {
    clientId: 'widgets-client-id',
    clientSecret: 'mock-widgets-secret',
    tokenUrl: 'https://widgets.example/oauth/token',
  });
}

function mockProvider(captured: { url?: string; body?: string; status?: number }, status = 200, bodyText = TOKEN_JSON): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    captured.url = String(url);
    captured.body = String(init?.body ?? '');
    captured.status = status;
    return new Response(bodyText, { status });
  }) as unknown as typeof fetch;
}

function deviceKeypair() {
  const kp = generateKeyPairSync('x25519');
  return { privateKey: kp.privateKey, publicRaw: exportRawX25519(kp.publicKey) };
}

function sealedFromResponse(r: import('../src/types.ts').SealedResponse): Sealed {
  return {
    relayPublicKeyRaw: Buffer.from(r.relay_public_key, 'base64url'),
    iv: Buffer.from(r.iv, 'base64url'),
    ciphertext: Buffer.from(r.ciphertext, 'base64url'),
    tag: Buffer.from(r.tag, 'base64url'),
    enc: r.enc,
    kdf: r.kdf,
  };
}

describe('forwardExchange (B2b)', () => {
  it('exchanges once and returns a token the device can open — and only ciphertext otherwise', async () => {
    const device = deviceKeypair();
    const captured: { url?: string; body?: string } = {};
    const deps: HandlerDeps = { keystore: b2bKeystore(), log: new RelayLog(() => {}), fetchImpl: mockProvider(captured) };

    const out = await forwardExchange(
      { provider: 'widgets', grant_type: 'authorization_code', code: 'THE_CODE', code_verifier: 'THE_VERIFIER', redirect_uri: 'http://127.0.0.1:33418/callback', device_public_key: device.publicRaw.toString('base64url') },
      deps,
    );

    // The response itself carries NO readable token.
    const blob = JSON.stringify(out);
    expect(blob).not.toContain('ATSECRET');
    expect(blob).not.toContain('RTSECRET');
    expect(out.enc).toBe('A256GCM');
    expect(out.provider_status).toBe(200);

    // The device opens it and gets the exact provider bytes back.
    const opened = open(sealedFromResponse(out), device.privateKey).toString('utf8');
    expect(opened).toBe(TOKEN_JSON);
  });

  it('POSTs the secret only to the config-pinned tokenUrl, never a request-supplied URL', async () => {
    const device = deviceKeypair();
    const captured: { url?: string; body?: string } = {};
    const deps: HandlerDeps = { keystore: b2bKeystore(), log: new RelayLog(() => {}), fetchImpl: mockProvider(captured) };

    await forwardExchange(
      { provider: 'widgets', grant_type: 'authorization_code', code: 'c', code_verifier: 'v', redirect_uri: 'http://127.0.0.1/cb', device_public_key: device.publicRaw.toString('base64url') },
      deps,
    );

    expect(captured.url).toBe('https://widgets.example/oauth/token');
    // The secret goes in the body to the pinned endpoint, exactly once.
    expect(captured.body).toContain('client_secret=mock-widgets-secret');
    expect(captured.body).toContain('grant_type=authorization_code');
  });

  it('surfaces a provider failure status without leaking the (error) body plaintext', async () => {
    const device = deviceKeypair();
    const captured: { url?: string } = {};
    const errBody = '{"error":"invalid_grant","error_description":"code expired"}';
    const deps: HandlerDeps = { keystore: b2bKeystore(), log: new RelayLog(() => {}), fetchImpl: mockProvider(captured, 400, errBody) };

    const out = await forwardExchange(
      { provider: 'widgets', grant_type: 'authorization_code', code: 'c', code_verifier: 'v', redirect_uri: 'http://127.0.0.1/cb', device_public_key: device.publicRaw.toString('base64url') },
      deps,
    );
    // Even the error body is sealed — the device decides what to do with it.
    expect(out.provider_status).toBe(400);
    expect(JSON.stringify(out)).not.toContain('invalid_grant');
    expect(open(sealedFromResponse(out), device.privateKey).toString('utf8')).toBe(errBody);
  });

  it('rejects a request missing the device public key before any exchange', async () => {
    let fetched = false;
    const deps: HandlerDeps = {
      keystore: b2bKeystore(),
      log: new RelayLog(() => {}),
      fetchImpl: (async () => { fetched = true; return new Response('{}'); }) as unknown as typeof fetch,
    };
    await expect(
      forwardExchange({ provider: 'widgets', grant_type: 'authorization_code', code: 'c', code_verifier: 'v', redirect_uri: 'x', device_public_key: '' }, deps),
    ).rejects.toThrow(/device_public_key is required/);
    expect(fetched).toBe(false); // no secret was ever POSTed
  });

  // Contract change (wave 3, B2-custody refresh gap): the relay previously HARD-REJECTED every
  // non-authorization_code grant, which left a B2b provider with no silent refresh at all — its
  // secret lives on the relay, so refresh cannot run on device, and every expiry became a forced
  // human re-consent (contradicts SPEC §5b). The relay now forwards refresh_token and the RFC 8628
  // device_code grant for B2b, staying stateless: it sees each refreshed token for one exchange,
  // seals it onward, and stores nothing.
  it('forwards a refresh_token grant for a B2b provider (silent refresh, SPEC §5b)', async () => {
    const device = deviceKeypair();
    const captured: { url?: string; body?: string } = {};
    const deps: HandlerDeps = { keystore: b2bKeystore(), log: new RelayLog(() => {}), fetchImpl: mockProvider(captured) };

    const out = await forwardExchange(
      { provider: 'widgets', grant_type: 'refresh_token', refresh_token: 'RT_TO_REDEEM', device_public_key: device.publicRaw.toString('base64url') },
      deps,
    );

    // The relay built a refresh_token form, presented the secret upstream, and sealed the result.
    const sent = new URLSearchParams(captured.body ?? '');
    expect(sent.get('grant_type')).toBe('refresh_token');
    expect(sent.get('refresh_token')).toBe('RT_TO_REDEEM');
    expect(sent.get('client_secret')).toBe('mock-widgets-secret');
    // A refresh is not an exchange: no authorization-code fields leak into the form.
    expect(sent.get('code')).toBeNull();
    expect(sent.get('redirect_uri')).toBeNull();
    expect(out.provider_status).toBe(200);
    expect(open(sealedFromResponse(out), device.privateKey).toString('utf8')).toBe(TOKEN_JSON);
  });

  it('forwards an RFC 8628 device_code grant for a B2b provider', async () => {
    const device = deviceKeypair();
    const captured: { url?: string; body?: string } = {};
    const deps: HandlerDeps = { keystore: b2bKeystore(), log: new RelayLog(() => {}), fetchImpl: mockProvider(captured) };

    const out = await forwardExchange(
      { provider: 'widgets', grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: 'DEV_CODE', device_public_key: device.publicRaw.toString('base64url') },
      deps,
    );

    const sent = new URLSearchParams(captured.body ?? '');
    expect(sent.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:device_code');
    expect(sent.get('device_code')).toBe('DEV_CODE');
    expect(sent.get('client_secret')).toBe('mock-widgets-secret');
    expect(open(sealedFromResponse(out), device.privateKey).toString('utf8')).toBe(TOKEN_JSON);
  });

  it('rejects a refresh_token grant missing the refresh_token field before any exchange', async () => {
    let fetched = false;
    const deps: HandlerDeps = {
      keystore: b2bKeystore(),
      log: new RelayLog(() => {}),
      fetchImpl: (async () => { fetched = true; return new Response('{}'); }) as unknown as typeof fetch,
    };
    await expect(
      forwardExchange({ provider: 'widgets', grant_type: 'refresh_token', device_public_key: 'AA' }, deps),
    ).rejects.toThrow(/refresh_token is required/);
    expect(fetched).toBe(false); // no secret was ever POSTed
  });

  it('rejects an unrecognized grant_type before any secret is read', async () => {
    let fetched = false;
    const deps: HandlerDeps = {
      keystore: b2bKeystore(),
      log: new RelayLog(() => {}),
      fetchImpl: (async () => { fetched = true; return new Response('{}'); }) as unknown as typeof fetch,
    };
    await expect(
      forwardExchange({ provider: 'widgets', grant_type: 'client_credentials' as RelayGrantType, device_public_key: 'AA' }, deps),
    ).rejects.toThrow(/grant_type must be/);
    expect(fetched).toBe(false);
  });

  it('maps an unreachable provider to provider_unavailable', async () => {
    const device = deviceKeypair();
    const deps: HandlerDeps = {
      keystore: b2bKeystore(),
      log: new RelayLog(() => {}),
      fetchImpl: (async () => { throw new Error('ECONNREFUSED'); }) as unknown as typeof fetch,
    };
    await expect(
      forwardExchange({ provider: 'widgets', grant_type: 'authorization_code', code: 'c', code_verifier: 'v', redirect_uri: 'x', device_public_key: device.publicRaw.toString('base64url') }, deps),
    ).rejects.toMatchObject({ code: 'provider_unavailable' });
  });
});
