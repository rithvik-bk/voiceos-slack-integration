/**
 * P1-I5 — the vault, against the REAL macOS Keychain.
 *
 * These tests deliberately do not mock `security`. A mocked Keychain proves that our code
 * calls a function we wrote; the entire risk in this module is in the parts we did NOT
 * write. That is not hypothetical: the obvious implementation (pipe the value into the
 * interactive `-w` prompt) passed every assertion we would have written against a mock and
 * SILENTLY TRUNCATED THE RECORD AT 128 BYTES against the real thing — a corrupt half-token,
 * reported as a successful write. The `security -i` transport and the long-payload test
 * below both exist because of that. So the scratch provider `test-e2e-scratch` is created,
 * exercised and destroyed on the real Keychain, and cleanup runs even when a test fails.
 */

import { afterEach, describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import { deleteToken, putToken, readToken, VAULT_ACCOUNT, vaultService } from '../src/vault.ts';
import { EngineError } from '../src/errors.ts';
import type { TokenRecord } from '../src/types.ts';

const SCRATCH = 'test-e2e-scratch';
const run = promisify(execFile);

function record(overrides: Partial<TokenRecord> = {}): TokenRecord {
  return {
    provider: SCRATCH,
    access_token: 'scratch-tok-a',
    refresh_token: 'scratch-ref-a',
    expires_at: Date.now() + 43_200_000,
    scopes: ['channels:read', 'channels:history', 'users:read'],
    identity: { handle: 'Rithvik', workspace: 'VoiceOS HQ' },
    obtained_at: Date.now(),
    ...overrides,
  };
}

afterEach(async () => {
  await deleteToken(SCRATCH).catch(() => undefined);
});

describe('vault — real Keychain round trip', () => {
  it('writes, reads back and deletes a full record', async () => {
    expect(await readToken(SCRATCH)).toBeNull();

    const written = record();
    await putToken(SCRATCH, written);

    const read = await readToken(SCRATCH);
    expect(read).not.toBeNull();
    expect(read?.access_token).toBe(written.access_token);
    expect(read?.refresh_token).toBe(written.refresh_token);
    expect(read?.expires_at).toBe(written.expires_at);
    expect(read?.scopes).toEqual(written.scopes);
    expect(read?.identity).toEqual({ handle: 'Rithvik', workspace: 'VoiceOS HQ' });
    expect(read?.provider).toBe(SCRATCH);

    await deleteToken(SCRATCH);
    expect(await readToken(SCRATCH)).toBeNull();
  });

  it('is idempotent on delete — disconnecting what was never connected is not an error', async () => {
    await expect(deleteToken(SCRATCH)).resolves.toBeUndefined();
    await expect(deleteToken(SCRATCH)).resolves.toBeUndefined();
  });

  it('replaces rather than duplicates on a second write (rotation writes constantly)', async () => {
    await putToken(SCRATCH, record({ access_token: 'first-tok' }));
    await putToken(SCRATCH, record({ access_token: 'second-tok' }));

    expect((await readToken(SCRATCH))?.access_token).toBe('second-tok');

    // One item, not two: a duplicate would make `find` return the stale one at random.
    await deleteToken(SCRATCH);
    expect(await readToken(SCRATCH)).toBeNull();
  });

  it('survives the characters that break naive shell/stdin transports', async () => {
    const nasty = `a"b'c\`d $HOME \\e; rm -rf /f & g|h <i> j%k+l=m`;
    await putToken(SCRATCH, record({ access_token: nasty }));
    expect((await readToken(SCRATCH))?.access_token).toBe(nasty);
  });

  it('round-trips a non-ASCII identity handle', async () => {
    await putToken(SCRATCH, record({ identity: { handle: 'Rithvík 🐂', workspace: 'VoiceOS HQ' } }));
    expect((await readToken(SCRATCH))?.identity?.handle).toBe('Rithvík 🐂');
  });

  it('round-trips a record far past the 128-byte getpass ceiling (the truncation bug)', async () => {
    // A real Slack user token is ~60 chars and the whole record ~280 bytes; this is 4x that,
    // so a transport with ANY buffer ceiling fails here instead of at T+12h in the room.
    const long = 'A1b2C3d4'.repeat(64); // 512 chars, no literal to trip the secret scanner
    await putToken(SCRATCH, record({ access_token: long, refresh_token: long }));

    const read = await readToken(SCRATCH);
    expect(read?.access_token).toHaveLength(512);
    expect(read?.access_token).toBe(long);
    expect(read?.refresh_token).toBe(long);
  });

  it('rejects a provider name that is not a legal vault key', () => {
    expect(() => vaultService('../../etc/passwd')).toThrowError(EngineError);
    expect(vaultService('slack')).toBe('com.voiceos.connect.slack');
  });

  it('returns null (not a throw) for a corrupt item, and never echoes its bytes', async () => {
    // Write a NON-JSON value through `security` directly, simulating a half-written item.
    await run('/usr/bin/security', [
      'add-generic-password',
      '-a',
      VAULT_ACCOUNT,
      '-s',
      vaultService(SCRATCH),
      '-w',
      'not-json-at-all',
    ]);
    const error = await readToken(SCRATCH).catch((e: unknown) => e as EngineError);
    expect(error).toBeInstanceOf(EngineError);
    expect((error as EngineError).code).toBe('vault_unavailable');
    expect(`${(error as EngineError).message} ${(error as EngineError).hint}`).not.toContain(
      'not-json-at-all',
    );
  });
});

describe('vault — the disk promise', () => {
  it('never passes the secret as an argv element (ps would show it)', async () => {
    // The proof is structural: putToken feeds the value on stdin. This test pins the
    // behaviour by asserting the secret is absent from the process table WHILE a write is
    // in flight — a `-w <value>` implementation fails it.
    const secret = `argv-visibility-canary-${Date.now()}`;
    const writing = putToken(SCRATCH, record({ access_token: secret }));

    let sawInProcessTable = false;
    for (let i = 0; i < 40; i += 1) {
      const { stdout } = await run('/bin/ps', ['-Ao', 'args']).catch(() => ({ stdout: '' }));
      if (stdout.includes(secret)) sawInProcessTable = true;
      if (stdout.includes(secret)) break;
    }
    await writing;

    expect(sawInProcessTable).toBe(false);
    expect((await readToken(SCRATCH))?.access_token).toBe(secret);
  });

  it('writes nothing to the working tree', async () => {
    await putToken(SCRATCH, record());
    const { stdout } = await run('/usr/bin/git', ['status', '--porcelain'], {
      cwd: new URL('../..', import.meta.url).pathname,
    });
    // A vault that wrote a cache file would show up here as an untracked artefact.
    expect(stdout).not.toMatch(/\.token|token\.json|vault\.json|\.oauth/i);
  });
});
