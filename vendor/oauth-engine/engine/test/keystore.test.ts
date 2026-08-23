/**
 * C-9 — the pluggable KeyStore (SPEC §6): interface, mac `/usr/bin/security` backend,
 * encrypted-file fallback, and the selector that never picks the weak backend silently.
 *
 * Like vault.test.ts, the mac backend runs against the REAL Keychain (the whole risk is in
 * the parts we did not write); the encrypted-file backend runs against a real temp directory.
 * Both clean up on success and failure.
 */

import { afterEach, describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { MacSecurityKeyStore, SECURITY_ACCOUNT } from '../src/keystore/security-backend.ts';
import { EncryptedFileKeyStore } from '../src/keystore/encrypted-file-backend.ts';
import { selectKeyStore } from '../src/keystore/select.ts';
import { assertLegalKey } from '../src/keystore/key.ts';
import { EngineError } from '../src/errors.ts';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));

/* ───────────────────────────── shared: key validation ───────────────────────────── */

describe('keystore — key validation (path/command injection surface)', () => {
  it('accepts a legal dotted service key and rejects traversal/metacharacters', () => {
    expect(() => assertLegalKey('com.voiceos.connect.slack')).not.toThrow();
    expect(() => assertLegalKey('slack')).not.toThrow();
    for (const bad of ['../../etc/passwd', 'a b', 'a/b', 'a;rm', '', '.leading', 'a$b', 'a\nb']) {
      expect(() => assertLegalKey(bad)).toThrowError(EngineError);
    }
  });
});

/* ───────────────────────────── mac /usr/bin/security backend ───────────────────────────── */

describe('keystore — macOS security CLI backend (real Keychain)', () => {
  const store = new MacSecurityKeyStore();
  const KEY = 'com.voiceos.connect.test-ks-scratch';

  afterEach(async () => {
    await store.delete(KEY).catch(() => undefined);
  });

  it('reports its identity: strong, mac-security, labeled', () => {
    expect(store.id).toBe('macos-security-cli');
    expect(store.strength).toBe('strong');
    expect(store.label.length).toBeGreaterThan(0);
  });

  it('writes, reads back and deletes an opaque secret', async () => {
    expect(await store.get(KEY)).toBeNull();
    await store.put(KEY, 'scratch-secret-value');
    expect(await store.get(KEY)).toBe('scratch-secret-value');
    await store.delete(KEY);
    expect(await store.get(KEY)).toBeNull();
  });

  it('replaces rather than duplicates on a second write', async () => {
    await store.put(KEY, 'first');
    await store.put(KEY, 'second');
    expect(await store.get(KEY)).toBe('second');
  });

  it('is idempotent on delete (disconnect what was never connected)', async () => {
    await expect(store.delete(KEY)).resolves.toBeUndefined();
    await expect(store.delete(KEY)).resolves.toBeUndefined();
  });

  it('survives characters that break naive shell/stdin transports', async () => {
    const nasty = `a"b'c\`d $HOME \\e; rm -rf /f & g|h <i> j%k+l=m`;
    await store.put(KEY, nasty);
    expect(await store.get(KEY)).toBe(nasty);
  });

  it('round-trips non-ASCII and emoji byte-for-byte', async () => {
    const s = 'héllo — Rithvík 🐂 — ☃';
    await store.put(KEY, s);
    expect(await store.get(KEY)).toBe(s);
  });

  it('round-trips far past the 128-byte getpass ceiling (the truncation bug)', async () => {
    const long = 'A1b2C3d4'.repeat(64); // 512 chars, assembled — no secret-shaped literal
    await store.put(KEY, long);
    expect(await store.get(KEY)).toBe(long);
  });

  it('INVARIANT: never passes the secret as an argv element (ps would show it)', async () => {
    const secret = `argv-visibility-canary-${Date.now()}`;
    const writing = store.put(KEY, secret);
    let sawInProcessTable = false;
    for (let i = 0; i < 40; i += 1) {
      const { stdout } = await run('/bin/ps', ['-Ao', 'args']).catch(() => ({ stdout: '' }));
      if (stdout.includes(secret)) {
        sawInProcessTable = true;
        break;
      }
    }
    await writing;
    expect(sawInProcessTable).toBe(false);
    expect(await store.get(KEY)).toBe(secret);
  });

  it('INVARIANT: ACL is not broadened — the write never emits the -A (all-apps) flag', () => {
    // -A grants read access to EVERY application; its absence keeps the default ACL restricted
    // to the creating (signing) identity. Pinned at the source so a future edit cannot quietly
    // add it. (§6 invariant 3.)
    const src = readFileSync(join(HERE, '..', 'src', 'keystore', 'security-backend.ts'), 'utf8');
    expect(src).toMatch(/add-generic-password/);
    expect(src).not.toMatch(/add-generic-password[^\n]*\s-A(\s|`)/);
  });

  it('returns a typed error (not the bytes) for an item in a foreign format', async () => {
    // Store a non-hex value directly, simulating an item written by something else.
    await run('/usr/bin/security', [
      'add-generic-password',
      '-a',
      SECURITY_ACCOUNT,
      '-s',
      KEY,
      '-w',
      'definitely-not-hex-!!',
    ]);
    const err = await store.get(KEY).catch((e: unknown) => e as EngineError);
    expect(err).toBeInstanceOf(EngineError);
    expect((err as EngineError).code).toBe('vault_unavailable');
    expect(`${(err as EngineError).message} ${(err as EngineError).hint}`).not.toContain(
      'definitely-not-hex',
    );
  });
});

/* ───────────────────────────── encrypted-file backend ───────────────────────────── */

describe('keystore — encrypted-file backend (weak, explicit)', () => {
  const dirs: string[] = [];
  function freshDir(): string {
    const d = mkdtempSync(join(tmpdir(), 'ks-encfile-'));
    dirs.push(d);
    return d;
  }
  afterEach(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
    dirs.length = 0;
  });

  const KEY = 'com.voiceos.connect.encfile-scratch';

  it('reports its identity honestly: weak, encrypted-file, labeled WEAKER', () => {
    const s = new EncryptedFileKeyStore(freshDir());
    expect(s.id).toBe('encrypted-file');
    expect(s.strength).toBe('weak');
    expect(s.label.toLowerCase()).toContain('weak');
  });

  it('refuses construction without an explicit directory', () => {
    expect(() => new EncryptedFileKeyStore('')).toThrowError(EngineError);
  });

  it('writes, reads back and deletes an opaque secret', async () => {
    const s = new EncryptedFileKeyStore(freshDir());
    expect(await s.get(KEY)).toBeNull();
    await s.put(KEY, 'encfile-secret');
    expect(await s.get(KEY)).toBe('encfile-secret');
    await s.delete(KEY);
    expect(await s.get(KEY)).toBeNull();
  });

  it('round-trips nasty, non-ASCII and long values', async () => {
    const s = new EncryptedFileKeyStore(freshDir());
    for (const v of [`a"b'c\`d $X \\e;`, 'héllo 🐂 ☃', 'Z9y8X7'.repeat(100)]) {
      await s.put(KEY, v);
      expect(await s.get(KEY)).toBe(v);
    }
  });

  it('INVARIANT: the secret never appears on disk in plaintext (final file is ciphertext)', async () => {
    const dir = freshDir();
    const s = new EncryptedFileKeyStore(dir);
    const secret = `plaintext-canary-${Date.now()}-should-never-hit-disk`;
    await s.put(KEY, secret);

    // Scan EVERY file in the dir (final + any lingering temp) for the plaintext substring.
    let sawPlaintext = false;
    for (const name of readdirSync(dir)) {
      const bytes = readFileSync(join(dir, name));
      if (bytes.includes(Buffer.from(secret, 'utf8'))) sawPlaintext = true;
    }
    expect(sawPlaintext).toBe(false);

    // And the round trip still works — it really is encrypted, not just absent.
    expect(await s.get(KEY)).toBe(secret);
  });

  it('INVARIANT: no plaintext temp file is left behind after a write', async () => {
    const dir = freshDir();
    const s = new EncryptedFileKeyStore(dir);
    await s.put(KEY, 'temp-phase-secret');
    const leftovers = readdirSync(dir).filter((n) => n.endsWith('.tmp'));
    expect(leftovers).toEqual([]);
  });

  it('INVARIANT: the stored file is owner-only (mode 0600), the ACL this backend supports', () => {
    const dir = freshDir();
    const s = new EncryptedFileKeyStore(dir);
    return s.put(KEY, 'acl-secret').then(() => {
      const file = join(dir, `${KEY}.enc`);
      const mode = statSync(file).mode & 0o777;
      expect(mode).toBe(0o600);
    });
  });

  it('a tampered ciphertext fails authentication and never echoes stored bytes', async () => {
    const dir = freshDir();
    const s = new EncryptedFileKeyStore(dir);
    await s.put(KEY, 'to-be-tampered');
    const file = join(dir, `${KEY}.enc`);
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as { ct: string };
    // Flip the ciphertext.
    const ctBuf = Buffer.from(parsed.ct, 'base64');
    ctBuf[0] = ctBuf[0]! ^ 0xff;
    parsed.ct = ctBuf.toString('base64');
    writeFileSync(file, JSON.stringify(parsed));

    const err = await s.get(KEY).catch((e: unknown) => e as EngineError);
    expect(err).toBeInstanceOf(EngineError);
    expect((err as EngineError).code).toBe('vault_unavailable');
    const surface = `${(err as EngineError).message} ${(err as EngineError).hint}`;
    expect(surface).not.toContain(parsed.ct);
  });

  it('a corrupt (non-JSON) file returns a typed error, not a crash', async () => {
    const dir = freshDir();
    const s = new EncryptedFileKeyStore(dir);
    writeFileSync(join(dir, `${KEY}.enc`), 'not json at all');
    const err = await s.get(KEY).catch((e: unknown) => e as EngineError);
    expect(err).toBeInstanceOf(EngineError);
    expect((err as EngineError).code).toBe('vault_unavailable');
  });

  it('delete is idempotent and local-only (no network, no throw on absence)', async () => {
    const s = new EncryptedFileKeyStore(freshDir());
    await expect(s.delete(KEY)).resolves.toBeUndefined();
    await s.put(KEY, 'x');
    await expect(s.delete(KEY)).resolves.toBeUndefined();
    await expect(s.delete(KEY)).resolves.toBeUndefined();
  });
});

/* ───────────────────────────── selector — never silent downgrade ───────────────────────────── */

describe('keystore — selectKeyStore never silently picks the weak backend', () => {
  it('picks the strong mac backend on darwin', () => {
    const s = selectKeyStore({ platform: 'darwin' });
    expect(s.id).toBe('macos-security-cli');
    expect(s.strength).toBe('strong');
  });

  it('THROWS on a platform with no strong backend rather than downgrading silently', () => {
    const err = (() => {
      try {
        selectKeyStore({ platform: 'linux' });
        return null;
      } catch (e) {
        return e as EngineError;
      }
    })();
    expect(err).toBeInstanceOf(EngineError);
    expect((err as EngineError).code).toBe('config_invalid');
  });

  it('returns the weak backend ONLY on explicit opt-in with an explicit dir', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ks-select-'));
    try {
      const s = selectKeyStore({
        platform: 'linux',
        allowWeakEncryptedFile: true,
        encryptedFileDir: dir,
      });
      expect(s.id).toBe('encrypted-file');
      expect(s.strength).toBe('weak');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('opt-in without a directory is a config error, not a guessed path', () => {
    expect(() => selectKeyStore({ platform: 'linux', allowWeakEncryptedFile: true })).toThrowError(
      EngineError,
    );
  });
});
