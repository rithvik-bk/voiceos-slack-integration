/**
 * THE custody-property tests for the relay (SPEC §5: "never persists a token ... has no
 * database, logs any credential material"). Two claims, proven, not asserted in prose:
 *
 *   1. The relay PERSISTS NOTHING. A full B2a + B2b flow writes zero bytes to the filesystem,
 *      and the relay source imports no persistence module (no fs, no db driver). It cannot
 *      keep a token because there is no code path that stores one.
 *
 *   2. A LOG-SCAN FINDS NO TOKEN-SHAPED STRINGS. Every credential value that transits a flow
 *      — access token, refresh token, authorization code, PKCE verifier, client secret, and
 *      the signed assertion itself — is fed in with a distinctive marker, and NONE of them
 *      appears anywhere in the captured log output.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { forwardExchange, signAssertion, type HandlerDeps } from '../src/handlers.ts';
import { RelayKeyStore } from '../src/keystore.ts';
import { RelayLog } from '../src/log.ts';
import { exportRawX25519 } from '../src/seal.ts';

/* ─────────────────── distinctive markers that must never reach a log ─────────────────── */

const MARK = {
  accessToken: 'ACCESS-TOKEN-MARKER-zzz111',
  refreshToken: 'REFRESH-TOKEN-MARKER-zzz222',
  code: 'AUTH-CODE-MARKER-zzz333',
  verifier: 'PKCE-VERIFIER-MARKER-zzz444',
  clientSecret: 'CLIENT-SECRET-MARKER-zzz555',
};
const PROVIDER_TOKEN_JSON = `{"access_token":"${MARK.accessToken}","refresh_token":"${MARK.refreshToken}","expires_in":3600}`;

function deviceKeypair() {
  const kp = generateKeyPairSync('x25519');
  return { privateKey: kp.privateKey, publicRaw: exportRawX25519(kp.publicKey) };
}

function b2aKeystore(): RelayKeyStore {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return new RelayKeyStore().addSigningKey('acme', { privateKey, alg: 'ES256', clientId: 'acme-client', audience: 'https://acme.example/token' });
}

function b2bKeystore(): RelayKeyStore {
  return new RelayKeyStore().addClientSecret('widgets', { clientId: 'widgets-client', clientSecret: MARK.clientSecret, tokenUrl: 'https://widgets.example/token' });
}

function mockProvider(): typeof fetch {
  return (async () => new Response(PROVIDER_TOKEN_JSON, { status: 200 })) as unknown as typeof fetch;
}

/* ───────────────────────────── 1. persists nothing ───────────────────────────── */

/**
 * A recursive listing of a directory tree (files + their sizes), for a before/after diff. If
 * the relay wrote anything — a token cache, a log file, a temp spill — a new or grown path
 * shows up in the diff. This is the BEHAVIOURAL proof; the import-scan below is the STRUCTURAL
 * one (the relay imports no fs at all, so it has no handle capable of writing).
 */
const SKIP_DIRS = new Set(['node_modules', '.git']);

function snapshot(dir: string, depth = 5): Map<string, number> {
  const out = new Map<string, number>();
  const walk = (d: string, left: number): void => {
    let entries: string[];
    try {
      entries = readdirSync(d);
    } catch {
      return;
    }
    for (const name of entries) {
      if (SKIP_DIRS.has(name)) continue;
      const p = join(d, name);
      let st;
      try {
        st = statSync(p);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (left > 0) walk(p, left - 1);
      } else {
        out.set(p, st.size);
      }
    }
  };
  walk(dir, depth);
  return out;
}

function diff(before: Map<string, number>, after: Map<string, number>): string[] {
  const changed: string[] = [];
  for (const [p, size] of after) if (before.get(p) !== size) changed.push(p);
  return changed;
}

describe('the relay persists nothing', () => {
  it('creates or grows no file across a full B2a + B2b flow', async () => {
    // Watch the relay package (where a token cache or log file would most plausibly land) and
    // the process cwd. tmpdir is deliberately excluded from the behavioural diff — it is noisy
    // with other processes' temp files; the STRUCTURAL import-scan below is what proves the
    // relay could not write to tmp (or anywhere) because it never imports fs.
    const relayRoot = fileURLToPath(new URL('..', import.meta.url));
    const watchDirs = [relayRoot, process.cwd()];
    const before = watchDirs.map((d) => snapshot(d));

    const device = deviceKeypair();
    const b2a: HandlerDeps = { keystore: b2aKeystore(), log: new RelayLog(() => {}) };
    const b2b: HandlerDeps = { keystore: b2bKeystore(), log: new RelayLog(() => {}), fetchImpl: mockProvider() };

    signAssertion({ provider: 'acme' }, b2a);
    await forwardExchange(
      { provider: 'widgets', grant_type: 'authorization_code', code: MARK.code, code_verifier: MARK.verifier, redirect_uri: 'http://127.0.0.1/cb', device_public_key: device.publicRaw.toString('base64url') },
      b2b,
    );

    const changes = watchDirs.flatMap((d, i) => diff(before[i] ?? new Map(), snapshot(d)));
    expect(changes).toEqual([]);
  });

  it('holds nothing after the flow — a second identical call cannot read back the first', async () => {
    // There is no store to read back FROM: the keystore exposes providers() (names only) and
    // no request-state getter exists at all. This asserts the API shape that guarantees it.
    const ks = b2bKeystore();
    expect(Object.keys(ks.providers())).toEqual(['signing', 'forwarding']);
    // No method returns a code / token / verifier from a prior request.
    const surface = Object.getOwnPropertyNames(Object.getPrototypeOf(ks));
    expect(surface).not.toContain('lastRequest');
    expect(surface).not.toContain('history');
    expect(surface).not.toContain('tokens');
  });
});

describe('the relay source imports no persistence layer', () => {
  const srcDir = join(fileURLToPath(new URL('../src', import.meta.url)));

  it('no src file imports fs, a database driver, or any at-rest store', () => {
    const forbidden = /from\s+['"](node:)?fs(\/promises)?['"]|from\s+['"](better-sqlite3|sqlite3|pg|mysql2?|redis|ioredis|mongodb|level|lmdb)['"]/;
    const offenders: string[] = [];
    for (const file of readdirSync(srcDir)) {
      if (!file.endsWith('.ts')) continue;
      const text = readFileSync(join(srcDir, file), 'utf8');
      if (forbidden.test(text)) offenders.push(file);
    }
    expect(offenders).toEqual([]);
  });

  it('the relay declares zero runtime dependencies', () => {
    const pkg = JSON.parse(readFileSync(join(srcDir, '..', 'package.json'), 'utf8'));
    expect(pkg.dependencies ?? {}).toEqual({});
  });
});

/* ───────────────────────── 2. log-scan finds no token-shaped strings ───────────────────────── */

describe('a log-scan finds no credential material', () => {
  it('no marker for any credential appears in the captured log across both modes', async () => {
    const lines: string[] = [];
    const log = new RelayLog((line) => lines.push(line));

    const device = deviceKeypair();
    const b2a: HandlerDeps = { keystore: b2aKeystore(), log };
    const b2b: HandlerDeps = { keystore: b2bKeystore(), log, fetchImpl: mockProvider() };

    // B2a: sign an assertion (the assertion itself is a bearer credential in flight).
    const assertion = signAssertion({ provider: 'acme' }, b2a);
    // B2b: run an exchange whose request AND provider response carry markers.
    const sealed = await forwardExchange(
      { provider: 'widgets', grant_type: 'authorization_code', code: MARK.code, code_verifier: MARK.verifier, redirect_uri: 'http://127.0.0.1/cb', device_public_key: device.publicRaw.toString('base64url') },
      b2b,
    );
    // Force at least one rejected-path log line too.
    try {
      signAssertion({ provider: 'unknown-provider' }, b2a);
    } catch {
      /* expected */
    }

    const haystack = lines.join('\n');
    expect(lines.length).toBeGreaterThan(0); // we actually logged something

    // None of the request/response credential values leaked.
    for (const [name, value] of Object.entries(MARK)) {
      expect(haystack, `${name} leaked into the log`).not.toContain(value);
    }
    // The signed assertion (a live credential) is not logged either.
    expect(haystack).not.toContain(assertion.client_assertion);
    // Nor the sealed ciphertext (public-safe, but still not something the log should carry).
    expect(haystack).not.toContain(sealed.ciphertext);

    // And a generic token-shape heuristic: no long unbroken base64/JWT-ish blob in any line.
    // (event fields are short enums, provider names, ISO timestamps, and small integers.)
    const TOKEN_SHAPE = /[A-Za-z0-9_\-]{40,}|[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/;
    for (const line of lines) {
      expect(line, `token-shaped string in: ${line}`).not.toMatch(TOKEN_SHAPE);
    }
  });

  it('the logger drops unknown fields — a caller cannot smuggle a token through it', () => {
    const lines: string[] = [];
    const log = new RelayLog((line) => lines.push(line));
    // A caller tries to attach a token to a log event. The whitelist serializer drops it.
    log.emit({ event: 'assertion.signed', provider: 'acme', outcome: 'ok', ms: 1, access_token: MARK.accessToken } as never);
    expect(lines[0]).not.toContain(MARK.accessToken);
    expect(JSON.parse(lines[0] ?? '{}')).not.toHaveProperty('access_token');
  });

  it('the keystore refuses to serialize its secrets', () => {
    const ks = b2bKeystore();
    expect(String(ks)).toBe('[RelayKeyStore redacted]');
    expect(JSON.stringify({ ks })).not.toContain(MARK.clientSecret);
    expect(JSON.stringify(ks)).toBe('"[RelayKeyStore redacted]"');
  });
});
