/**
 * Confidential custody, END TO END, against the REAL relay (SPEC §5b — C-6 / C-7).
 *
 * Wave 1 built and tested the relay SERVER (the `relay/` package). This proves the engine's
 * DEVICE leg (`engine/src/relay-client.ts`, wired into `exchange.ts`) interoperates with that
 * exact server — a real `createRelay` listener, real ES256 assertion signing, real X25519
 * seal/open — not a hand-rolled stand-in that could agree with a bug on both sides.
 *
 * Two flows, each a rung of the custody ladder:
 *   B2a — the relay signs a client assertion and the DEVICE does the exchange. Proven end to
 *         end: the relay here is given NO client secret for the provider, so it is structurally
 *         incapable of performing an exchange, and the connect still succeeds. That is the
 *         custody property itself — "the relay never sees a token" — made mechanical.
 *   B2b — the relay performs the one exchange and returns the token SEALED to an ephemeral
 *         device key. Proven end to end: the engine opens a seal the real relay produced, the
 *         relay's own log never carried the token, and the upstream provider confirms the relay
 *         (not the device) presented the client secret.
 *
 * Every token-shaped literal is assembled from fragments at runtime so this file plants no
 * finding for the secret scanner (same rule as the other test files).
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { generateKeyPairSync, verify as cryptoVerify } from 'node:crypto';

import { afterEach, describe, expect, it } from 'vitest';

import { createRelay, RelayKeyStore } from '../../relay/src/index.ts';
import { pollForDeviceToken } from '../src/device.ts';
import { exchangeCode, refreshGrant } from '../src/exchange.ts';
import { EngineError } from '../src/index.ts';
import type { ProviderProfile } from '../src/index.ts';

/** A token value with a real credential's shape, assembled so the scanner sees no literal. */
const ACCESS_TOKEN = `xox${'p'}-${'A1b2C3d4E5f6G7h8i9J0kLmNoPqRsTuV'}`;
const REFRESH_TOKEN = `xox${'e'}-1-${'Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0'}`;
const CLIENT_SECRET = `${'sh'}${'hh-b2b-provider-secret-Kx7cQf3n2m'}`;

const REDIRECT = 'http://localhost:33418/callback';

/** A minimal provider token endpoint. Records the last form body it saw for assertions. */
interface MockProvider {
  url: string;
  bodies: URLSearchParams[];
  close: () => Promise<void>;
}

async function startProvider(): Promise<MockProvider> {
  const bodies: URLSearchParams[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      bodies.push(new URLSearchParams(Buffer.concat(chunks).toString('utf8')));
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({ access_token: ACCESS_TOKEN, refresh_token: REFRESH_TOKEN, expires_in: 3600 }),
      );
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/token`,
    bodies,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${port}`;
}

function profile(overrides: Partial<ProviderProfile>): ProviderProfile {
  return {
    name: 'acme',
    display_name: 'Acme',
    authorize_url: 'https://acme.example/authorize',
    token_url: 'https://acme.example/token',
    client_id: 'acme-public-client',
    client_type: 'confidential',
    pkce: 'S256',
    redirect_strategy: 'loopback',
    redirect_host: 'localhost',
    redirect_ports: [33418],
    scopes: ['read'],
    scope_param: 'scope',
    token_auth: 'none',
    refresh_auth: 'none',
    token_path: 'access_token',
    success_predicate: null,
    refresh: 'rotation',
    rotation: 'forced',
    identity_probe: { url: 'https://acme.example/me', handle_path: 'user' },
    ...overrides,
  };
}

const servers: Array<{ close: () => Promise<void> }> = [];
function track<T extends { close: () => Promise<void> }>(s: T): T {
  servers.push(s);
  return s;
}
async function closeHttp(s: Server): Promise<void> {
  await new Promise<void>((resolve) => s.close(() => resolve()));
}

afterEach(async () => {
  await Promise.all(servers.map((s) => s.close()));
  servers.length = 0;
});

describe('B2a — assertion signing (relay signs, never sees a token)', () => {
  it('signs on the relay and exchanges on the device, end to end', async () => {
    const provider = track(await startProvider());

    // The relay holds ONLY a signing key for this provider — no client secret. It is therefore
    // structurally unable to perform an exchange; a passing test is the custody proof.
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const relay = createRelay({
      keystore: new RelayKeyStore().addSigningKey('acme', {
        privateKey,
        alg: 'ES256',
        clientId: 'acme-confidential-client',
        audience: provider.url,
      }),
    });
    const relayBase = await listen(relay);
    track({ close: () => closeHttp(relay) });

    const record = await exchangeCode(
      profile({ token_url: provider.url, relay_mode: 'assertion_signing', custody_class: 'B2a' }),
      { code: 'auth-code-b2a', verifier: 'pkce-verifier-b2a', redirectUri: REDIRECT },
      { relayBaseUrl: relayBase },
    );

    expect(record.access_token).toBe(ACCESS_TOKEN);
    expect(record.refresh_token).toBe(REFRESH_TOKEN);

    // The device did the exchange: the provider saw a real, signature-verifiable assertion.
    const body = provider.bodies.at(-1)!;
    expect(body.get('client_assertion_type')).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    );
    expect(body.get('code')).toBe('auth-code-b2a');
    expect(body.get('code_verifier')).toBe('pkce-verifier-b2a');

    const jwt = body.get('client_assertion')!;
    const [h, p, s] = jwt.split('.');
    expect([h, p, s].every((seg) => seg && seg.length > 0)).toBe(true);
    const claims = JSON.parse(Buffer.from(p!, 'base64url').toString('utf8')) as Record<string, unknown>;
    expect(claims.iss).toBe('acme-confidential-client');
    expect(claims.sub).toBe('acme-confidential-client');
    expect(claims.aud).toBe(provider.url);
    // The signature verifies against the relay's public key — the whole B2a chain, cryptographically.
    const ok = cryptoVerify(
      'sha256',
      Buffer.from(`${h}.${p}`, 'ascii'),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(s!, 'base64url'),
    );
    expect(ok).toBe(true);
  });
});

describe('B2b — exchange forwarding (relay exchanges once, sealed onward)', () => {
  it('forwards through the relay and opens the seal on the device, end to end', async () => {
    const provider = track(await startProvider());

    // Capture the relay's own log: it must never carry a token value.
    const logLines: string[] = [];
    const relay = createRelay({
      keystore: new RelayKeyStore().addClientSecret('acme', {
        clientId: 'acme-confidential-client',
        clientSecret: CLIENT_SECRET,
        tokenUrl: provider.url,
      }),
      log: new (await import('../../relay/src/index.ts')).RelayLog((line: string) => logLines.push(line)),
    });
    const relayBase = await listen(relay);
    track({ close: () => closeHttp(relay) });

    const record = await exchangeCode(
      profile({ relay_mode: 'exchange_forwarding', custody_class: 'B2b' }),
      { code: 'auth-code-b2b', verifier: 'pkce-verifier-b2b', redirectUri: REDIRECT },
      { relayBaseUrl: relayBase },
    );

    // The engine opened a seal the REAL relay produced, and recovered the exact token.
    expect(record.access_token).toBe(ACCESS_TOKEN);
    expect(record.refresh_token).toBe(REFRESH_TOKEN);

    // The relay — not the device — presented the client secret upstream.
    const body = provider.bodies.at(-1)!;
    expect(body.get('client_secret')).toBe(CLIENT_SECRET);
    expect(body.get('code')).toBe('auth-code-b2b');

    // The relay's log carried metadata only: never the token, never the secret.
    const log = logLines.join('\n');
    expect(log).toContain('exchange.forwarded');
    expect(log).not.toContain(ACCESS_TOKEN);
    expect(log).not.toContain(REFRESH_TOKEN);
    expect(log).not.toContain(CLIENT_SECRET);
  });

  it('rejects a seal advertising a downgraded suite (no negotiated weakening)', async () => {
    // A hostile "relay" that returns a well-formed envelope with a downgraded suite marker.
    const bad = createServer((req, res) => {
      req.resume();
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            relay_public_key: 'AA',
            iv: 'AA',
            ciphertext: 'AA',
            tag: 'AA',
            enc: 'A128GCM',
            kdf: 'HKDF-SHA256',
            provider_status: 200,
          }),
        );
      });
    });
    const badBase = await listen(bad);
    track({ close: () => closeHttp(bad) });

    await expect(
      exchangeCode(
        profile({ relay_mode: 'exchange_forwarding', custody_class: 'B2b' }),
        { code: 'c', verifier: 'v', redirectUri: REDIRECT },
        { relayBaseUrl: badBase },
      ),
    ).rejects.toMatchObject({ code: 'provider_error' });
  });
});

describe('B2a — refresh (relay signs, device refreshes, relay stays token-blind)', () => {
  it('refreshes ON DEVICE with a relay-signed assertion, end to end', async () => {
    const provider = track(await startProvider());

    // Relay holds ONLY a signing key — no client secret. It is structurally unable to perform the
    // refresh; a passing refresh is the custody proof, exactly as for the B2a exchange.
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const relay = createRelay({
      keystore: new RelayKeyStore().addSigningKey('acme', {
        privateKey,
        alg: 'ES256',
        clientId: 'acme-confidential-client',
        audience: provider.url,
      }),
    });
    const relayBase = await listen(relay);
    track({ close: () => closeHttp(relay) });

    const record = await refreshGrant(
      profile({ token_url: provider.url, relay_mode: 'assertion_signing', custody_class: 'B2a' }),
      'refresh-token-in-hand-b2a',
      { relayBaseUrl: relayBase },
    );

    expect(record.access_token).toBe(ACCESS_TOKEN);

    // The device performed a real refresh grant, authenticated by the relay's assertion.
    const body = provider.bodies.at(-1)!;
    expect(body.get('grant_type')).toBe('refresh_token');
    expect(body.get('refresh_token')).toBe('refresh-token-in-hand-b2a');
    expect(body.get('client_assertion_type')).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    );
    const jwt = body.get('client_assertion')!;
    const [h, p, s] = jwt.split('.');
    const ok = cryptoVerify(
      'sha256',
      Buffer.from(`${h}.${p}`, 'ascii'),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(s!, 'base64url'),
    );
    expect(ok).toBe(true);
  });
});

describe('B2b — refresh (relay forwards one refresh, sealed onward)', () => {
  it('forwards the refresh through the relay and opens the seal on the device', async () => {
    const provider = track(await startProvider());

    const logLines: string[] = [];
    const relay = createRelay({
      keystore: new RelayKeyStore().addClientSecret('acme', {
        clientId: 'acme-confidential-client',
        clientSecret: CLIENT_SECRET,
        tokenUrl: provider.url,
      }),
      log: new (await import('../../relay/src/index.ts')).RelayLog((line: string) => logLines.push(line)),
    });
    const relayBase = await listen(relay);
    track({ close: () => closeHttp(relay) });

    const record = await refreshGrant(
      profile({ relay_mode: 'exchange_forwarding', custody_class: 'B2b' }),
      REFRESH_TOKEN,
      { relayBaseUrl: relayBase },
    );

    // The engine opened a seal the REAL relay produced and recovered the refreshed token.
    expect(record.access_token).toBe(ACCESS_TOKEN);

    // The relay — not the device — presented the client secret, on a refresh grant.
    const body = provider.bodies.at(-1)!;
    expect(body.get('grant_type')).toBe('refresh_token');
    expect(body.get('refresh_token')).toBe(REFRESH_TOKEN);
    expect(body.get('client_secret')).toBe(CLIENT_SECRET);

    // The relay's log carried metadata only: never the refreshed token, never the secret.
    const log = logLines.join('\n');
    expect(log).toContain('exchange.forwarded');
    expect(log).not.toContain(ACCESS_TOKEN);
    expect(log).not.toContain(CLIENT_SECRET);
  });
});

describe('device flow — relay-custody poll (SPEC §5b + §3 path 3)', () => {
  it('B2b: forwards the device-code poll through the relay and completes, sealed', async () => {
    const provider = track(await startProvider());
    const relay = createRelay({
      keystore: new RelayKeyStore().addClientSecret('acme', {
        clientId: 'acme-confidential-client',
        clientSecret: CLIENT_SECRET,
        tokenUrl: provider.url,
      }),
    });
    const relayBase = await listen(relay);
    track({ close: () => closeHttp(relay) });

    const auth = {
      deviceCode: 'device-code-b2b',
      userCode: 'WXYZ-1234',
      verificationUri: 'https://acme.example/device',
      expiresAt: Date.now() + 60_000,
      interval: 0,
    };
    const record = await pollForDeviceToken(
      profile({ relay_mode: 'exchange_forwarding', custody_class: 'B2b', device_flow: 'rfc8628' }),
      auth,
      { http: { relayBaseUrl: relayBase }, sleep: async () => {}, now: () => Date.now() },
    );

    expect(record.access_token).toBe(ACCESS_TOKEN);
    const body = provider.bodies.at(-1)!;
    expect(body.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:device_code');
    expect(body.get('device_code')).toBe('device-code-b2b');
    expect(body.get('client_secret')).toBe(CLIENT_SECRET);
  });

  it('B2a: polls on the device with a relay-signed assertion (relay stays token-blind)', async () => {
    const provider = track(await startProvider());
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const relay = createRelay({
      keystore: new RelayKeyStore().addSigningKey('acme', {
        privateKey,
        alg: 'ES256',
        clientId: 'acme-confidential-client',
        audience: provider.url,
      }),
    });
    const relayBase = await listen(relay);
    track({ close: () => closeHttp(relay) });

    const auth = {
      deviceCode: 'device-code-b2a',
      userCode: 'ABCD-1234',
      verificationUri: 'https://acme.example/device',
      expiresAt: Date.now() + 60_000,
      interval: 0,
    };
    const record = await pollForDeviceToken(
      profile({ token_url: provider.url, relay_mode: 'assertion_signing', custody_class: 'B2a' }),
      auth,
      { http: { relayBaseUrl: relayBase }, sleep: async () => {}, now: () => Date.now() },
    );

    expect(record.access_token).toBe(ACCESS_TOKEN);
    const body = provider.bodies.at(-1)!;
    expect(body.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:device_code');
    expect(body.get('device_code')).toBe('device-code-b2a');
    expect(body.get('client_assertion_type')).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    );
  });
});

describe('relay custody misconfiguration', () => {
  it('fails loudly when a relay provider is connected with no relay configured', async () => {
    const prior = process.env.HANDSHAKE_RELAY_URL;
    delete process.env.HANDSHAKE_RELAY_URL;
    try {
      await expect(
        exchangeCode(
          profile({ relay_mode: 'assertion_signing', custody_class: 'B2a' }),
          { code: 'c', verifier: 'v', redirectUri: REDIRECT },
          {},
        ),
      ).rejects.toBeInstanceOf(EngineError);
    } finally {
      if (prior !== undefined) process.env.HANDSHAKE_RELAY_URL = prior;
    }
  });

  it('maps an unknown-provider relay refusal to a config error', async () => {
    // A real relay with NO material for this provider returns 404 unknown_provider.
    const relay = createRelay({ keystore: new RelayKeyStore() });
    const relayBase = await listen(relay);
    track({ close: () => closeHttp(relay) });

    await expect(
      exchangeCode(
        profile({ relay_mode: 'assertion_signing', custody_class: 'B2a' }),
        { code: 'c', verifier: 'v', redirectUri: REDIRECT },
        { relayBaseUrl: relayBase },
      ),
    ).rejects.toMatchObject({ code: 'config_invalid' });
  });
});
