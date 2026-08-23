/**
 * KeyStore backend: macOS `/usr/bin/security` CLI (SPEC §6 ladder, "zero-dependency fallback,
 * correct for development, documented as such").
 *
 * This is the existing `vault.ts` transport, lifted behind the KeyStore interface and made
 * generic (opaque string in, opaque string out). Every scar the vault earned is preserved:
 *
 *   - The secret is NEVER an argv element. `security add-generic-password -w <value>` puts the
 *     token in the process table where any user can `ps` it. The write instead goes through
 *     `security -i`, which reads its COMMAND from stdin: `ps` shows `/usr/bin/security -i` and
 *     nothing else. The value rides as `-X <hex>` — hex because `security -i`'s tokenizer is
 *     shell-free and hex has no quotes, spaces or backslashes to interpret.
 *
 *   - No `shell: true`, ever. `spawn` with an argv ARRAY; the only string `security -i` parses
 *     is hex.
 *
 *   - The interactive `-w` prompt SILENTLY TRUNCATES AT 128 BYTES (a getpass buffer; measured
 *     2026-08-16). `security -i` has no such ceiling — that is the whole reason for this path.
 *
 *   - Write-then-verify: a Keychain write that silently failed looks identical to one that
 *     succeeded until the value is needed, so `put` reads the value back and compares.
 *
 * ENCODING. The stored password is the ASCII-hex of the secret's UTF-8 bytes, so `find -w`
 * always returns pure ASCII (verbatim, never `security`'s own hex-for-binary rendering) and
 * the round trip is byte-identical for ANY content — control chars, emoji, 512-byte tokens.
 * That ASCII-hex is written with `-w <value>` inside the `security -i` stdin stream (see the
 * note in `put`): value-present `-w` skips the truncating getpass prompt, and single-hex stays
 * under `security -i`'s ~4KB command-line limit that a double-hex `-X` payload overflows.
 *
 * ACL (§6 invariant 3). `add-generic-password` is called WITHOUT `-A`, so the item keeps the
 * default ACL restricting access to the creating (signing) identity. `-A` would broaden read
 * access to every application on the machine; a test asserts this backend never emits it.
 */

import { spawn } from 'node:child_process';

import { EngineError } from '../errors.ts';
import type { KeyStore, KeyStoreBackendId, KeyStoreStrength } from './types.ts';
import { assertLegalKey } from './key.ts';

const SECURITY = '/usr/bin/security';
/** Keychain account for every engine item. The KeyStore key is the Keychain *service*. */
export const SECURITY_ACCOUNT = 'voiceos';
/** Shown in Keychain Access. No spaces: it is a token in the `security -i` command stream. */
const KIND = 'VoiceOS-Connect-OAuth-token';
/** `security`'s exit code for "the item is not there." Not an error for us. */
const ERR_ITEM_NOT_FOUND = 44;

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Run `security` with an argv array and an optional stdin payload. No `shell: true`, ever:
 * the payload carries provider-controlled bytes and a shell in this path turns a token into
 * a command.
 */
function run(args: readonly string[], stdin?: string): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(SECURITY, [...args], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk: string) => {
      stderr += chunk;
    });
    child.once('error', (error) => {
      reject(
        new EngineError('vault_unavailable', 'could not run the macOS Keychain helper', {
          hint: `${SECURITY} failed to start. This backend stores secrets only in the Keychain; there is no plaintext file fallback.`,
          cause: error,
        }),
      );
    });
    child.once('close', (code) => resolve({ code: code ?? -1, stdout, stderr }));
    if (stdin !== undefined) child.stdin.end(stdin);
    else child.stdin.end();
  });
}

function isNotFound(result: RunResult): boolean {
  return result.code === ERR_ITEM_NOT_FOUND || /could not be found/i.test(result.stderr);
}

function firstLine(text: string): string {
  return text.split('\n')[0]?.trim() ?? '';
}

/** ASCII-hex of the secret's UTF-8 bytes — the value actually stored in the Keychain. */
function encodeStored(secret: string): string {
  return Buffer.from(secret, 'utf8').toString('hex');
}

/** Inverse of `encodeStored`. Returns `null` if the stored value is not our ASCII-hex format. */
function decodeStored(stored: string): string | null {
  const trimmed = stored.trim();
  if (trimmed === '' || trimmed.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(trimmed)) return null;
  return Buffer.from(trimmed, 'hex').toString('utf8');
}

export class MacSecurityKeyStore implements KeyStore {
  readonly id: KeyStoreBackendId = 'macos-security-cli';
  readonly strength: KeyStoreStrength = 'strong';
  readonly label = 'macOS Keychain via /usr/bin/security (dev-grade, on-device)';

  async put(key: string, secret: string): Promise<void> {
    assertLegalKey(key);

    // The stored value is the ASCII-hex of the secret's UTF-8 bytes (see `encodeStored`), so
    // `find -w` always returns pure ASCII and the round trip is byte-identical for ANY content.
    // It is delivered with `-w <value>` — the value is PRESENT, so this is not the interactive
    // getpass prompt and there is no 128-byte truncation — inside the `security -i` stdin
    // command stream, so the secret never enters argv/the process table. Hex is [0-9a-f] only,
    // carrying nothing the -i tokenizer treats as a second command.
    //
    // (History: an earlier version hex-encoded a SECOND time and passed `-X <double-hex>`. That
    // 4x blowup overflows `security -i`'s ~4KB command-line parser on a full TokenRecord with
    // two long tokens — the overflow tail is read as an "unknown command" and the write fails.
    // Measured 2026-08-22; `-w <single-hex>` stays well under the limit and round-trips 512-byte
    // tokens byte-for-byte.)
    const stored = encodeStored(secret);

    await this.delete(key);

    const result = await run(
      ['-i'],
      `add-generic-password -a ${SECURITY_ACCOUNT} -s ${key} -D ${KIND} -w ${stored}\n`,
    );
    if (result.code !== 0) {
      throw new EngineError('vault_unavailable', 'the Keychain refused the write', {
        hint: `security add-generic-password exited ${result.code} for ${key}. ${firstLine(result.stderr)}`,
      });
    }

    // Write-then-verify. A truncated or mangled payload is the failure a bare exit check misses.
    const readBack = await this.get(key);
    if (readBack !== secret) {
      throw new EngineError('vault_unavailable', 'the Keychain write did not survive a read-back', {
        hint: `Wrote ${key} and read back ${readBack === null ? 'nothing' : 'a different value'}. Nothing is cached in plaintext, so the safe state is disconnected.`,
      });
    }
  }

  async get(key: string): Promise<string | null> {
    assertLegalKey(key);
    const result = await run(['find-generic-password', '-a', SECURITY_ACCOUNT, '-s', key, '-w']);
    if (result.code !== 0) {
      if (isNotFound(result)) return null;
      throw new EngineError('vault_unavailable', 'the Keychain refused the read', {
        hint: `security find-generic-password exited ${result.code} for ${key}. ${firstLine(result.stderr)}`,
      });
    }

    const raw = result.stdout.trim();
    if (raw === '') return null;

    const decoded = decodeStored(raw);
    if (decoded === null) {
      // The stored bytes are NEVER echoed into the error: they may be the secret.
      throw new EngineError('vault_unavailable', 'the Keychain item is not in the expected format', {
        hint: `Keychain item ${key} holds ${raw.length} bytes that are not this backend's encoding. Reconnect to rewrite it.`,
      });
    }
    return decoded;
  }

  async delete(key: string): Promise<void> {
    assertLegalKey(key);
    // Local-only, no network. Idempotent: deleting what was never stored succeeds silently.
    const result = await run(['delete-generic-password', '-a', SECURITY_ACCOUNT, '-s', key]);
    if (result.code === 0 || isNotFound(result)) return;
    throw new EngineError('vault_unavailable', 'the Keychain refused the delete', {
      hint: `security delete-generic-password exited ${result.code} for ${key}. ${firstLine(result.stderr)}`,
    });
  }
}
