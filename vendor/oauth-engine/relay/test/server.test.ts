/**
 * The HTTP surface (`createRelay`) over a real loopback listener. Proves the wiring: the two
 * routes reach the two handlers, /healthz reveals provider NAMES only (never secrets), and
 * errors map to the typed status without echoing provider text.
 */

import { generateKeyPairSync } from 'node:crypto';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createRelay } from '../src/server.ts';
import { RelayKeyStore } from '../src/keystore.ts';
import { RelayLog } from '../src/log.ts';
import { exportRawX25519, open } from '../src/seal.ts';

const TOKEN_JSON = '{"access_token":"mock-server-at-scrt","expires_in":3600}';

function keystore(): RelayKeyStore {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return new RelayKeyStore()
    .addSigningKey('acme', { privateKey, alg: 'ES256', clientId: 'acme-client', audience: 'https://acme.example/token' })
    .addClientSecret('widgets', { clientId: 'widgets-client', clientSecret: 'WIDGETS-SECRET', tokenUrl: 'https://widgets.example/token' });
}

let server: Server;
let base: string;

beforeEach(async () => {
  const mockFetch = (async () => new Response(TOKEN_JSON, { status: 200 })) as unknown as typeof fetch;
  server = createRelay({ keystore: keystore(), log: new RelayLog(() => {}), fetchImpl: mockFetch });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address() as AddressInfo;
  base = `http://127.0.0.1:${addr.port}`;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe('createRelay HTTP surface', () => {
  it('GET /healthz returns provider names only, no secrets', async () => {
    const res = await fetch(`${base}/healthz`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, any>;
    expect(body.ok).toBe(true);
    expect(body.providers).toEqual({ signing: ['acme'], forwarding: ['widgets'] });
    expect(JSON.stringify(body)).not.toContain('WIDGETS-SECRET');
  });

  it('POST /v1/assertion signs and returns an assertion', async () => {
    const res = await fetch(`${base}/v1/assertion`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ provider: 'acme' }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, any>;
    expect(body.client_assertion.split('.')).toHaveLength(3);
    expect(body.client_assertion_type).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
  });

  it('POST /v1/exchange returns a sealed token the device can open', async () => {
    const kp = generateKeyPairSync('x25519');
    const res = await fetch(`${base}/v1/exchange`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        provider: 'widgets',
        grant_type: 'authorization_code',
        code: 'c',
        code_verifier: 'v',
        redirect_uri: 'http://127.0.0.1/cb',
        device_public_key: exportRawX25519(kp.publicKey).toString('base64url'),
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, any>;
    expect(JSON.stringify(body)).not.toContain('mock-server-at-scrt'); // only ciphertext on the wire
    const opened = open(
      {
        relayPublicKeyRaw: Buffer.from(body.relay_public_key, 'base64url'),
        iv: Buffer.from(body.iv, 'base64url'),
        ciphertext: Buffer.from(body.ciphertext, 'base64url'),
        tag: Buffer.from(body.tag, 'base64url'),
        enc: body.enc,
        kdf: body.kdf,
      },
      kp.privateKey,
    );
    expect(opened.toString('utf8')).toBe(TOKEN_JSON);
  });

  it('maps an unknown provider to 404 with a typed code', async () => {
    const res = await fetch(`${base}/v1/assertion`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ provider: 'nope' }),
    });
    expect(res.status).toBe(404);
    expect(((await res.json()) as Record<string, any>).error).toBe('unknown_provider');
  });

  it('rejects a non-POST on a POST route and an unknown route', async () => {
    expect((await fetch(`${base}/v1/assertion`)).status).toBe(405);
    expect((await fetch(`${base}/nope`, { method: 'POST', body: '{}' })).status).toBe(404);
  });

  it('rejects malformed JSON as a 400', async () => {
    const res = await fetch(`${base}/v1/exchange`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: 'not json' });
    expect(res.status).toBe(400);
    expect(((await res.json()) as Record<string, any>).error).toBe('bad_request');
  });
});
