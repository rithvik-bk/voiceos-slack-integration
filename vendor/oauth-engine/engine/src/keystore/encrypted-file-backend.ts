/**
 * KeyStore backend: encrypted file with an OS-derived key (SPEC §6 ladder, "Last resort,
 * explicitly labeled as weaker, never silently selected").
 *
 * This exists so a platform with no OS keyring still has a home for secrets that is not a
 * plaintext dotfile. It is HONESTLY WEAK and says so (`strength: 'weak'`, and the selector in
 * `select.ts` refuses to return it unless the caller opts in explicitly):
 *
 *   THE HONEST LIMIT. The encryption key is derived from stable machine attributes (platform,
 *   hostname, user) plus a per-item random salt. Anyone who can both read this file AND read
 *   those attributes — i.e. any code already running as this user on this machine — can derive
 *   the key. It defends against a stolen file (a backup, a synced folder, a lost disk) and
 *   against casual `grep`, NOT against a local attacker running as the user. A real OS keyring
 *   (Keychain / DPAPI / libsecret) binds decryption to the login session and the signing
 *   identity; this cannot. That is exactly why it is the bottom rung and never a silent default.
 *
 * The §6 invariants it DOES uphold, each with a test:
 *   - Secret never on argv: it never spawns a process at all.
 *   - Secret never on disk unencrypted, INCLUDING the atomic-write temp phase: the plaintext
 *     exists only in memory; only AES-256-GCM ciphertext is ever written — to the temp file
 *     and to the final file. There is no plaintext-then-encrypt temp stage.
 *   - ACL where supported: the file (and its temp) are created mode 0600, owner-only.
 *   - Disconnect deletes locally, unconditionally, first: `delete` is a local `rm`, idempotent,
 *     no network.
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeSync } from 'node:fs';
import { homedir, hostname, platform, userInfo } from 'node:os';
import { join } from 'node:path';

import { EngineError } from '../errors.ts';
import type { KeyStore, KeyStoreBackendId, KeyStoreStrength } from './types.ts';
import { assertLegalKey } from './key.ts';

const FORMAT_VERSION = 1;
const SALT_BYTES = 16;
const IV_BYTES = 12; // GCM standard nonce length
const KEY_BYTES = 32; // AES-256
const OWNER_ONLY = 0o600;

interface OnDisk {
  v: number;
  /** base64 — per-item KDF salt. Not secret; binds the key to this item. */
  salt: string;
  /** base64 — GCM nonce. */
  iv: string;
  /** base64 — GCM auth tag. */
  tag: string;
  /** base64 — the ciphertext. The ONLY representation of the secret ever written. */
  ct: string;
}

/**
 * Stable per-machine, per-user seed for the KDF. This is the "OS-derived" part — and its
 * weakness. It is derivable by any code running as this user, which is the documented limit.
 */
function machineSeed(): string {
  const info = userInfo();
  return [platform(), hostname(), info.username, String(info.uid), homedir()].join('');
}

function deriveKey(salt: Buffer): Buffer {
  return scryptSync(machineSeed(), salt, KEY_BYTES);
}

export class EncryptedFileKeyStore implements KeyStore {
  readonly id: KeyStoreBackendId = 'encrypted-file';
  readonly strength: KeyStoreStrength = 'weak';
  readonly label = 'encrypted file, OS-derived key (WEAKER — last resort, no OS keyring)';

  readonly #dir: string;

  /**
   * @param dir Directory the encrypted items live in. Required and explicit: this backend is
   *   never a silent default, so it never guesses a path. Created 0700 if absent.
   */
  constructor(dir: string) {
    if (typeof dir !== 'string' || dir.trim() === '') {
      throw new EngineError('config_invalid', 'encrypted-file key store needs an explicit directory', {
        hint: 'Pass the directory the encrypted items should live in.',
      });
    }
    this.#dir = dir;
  }

  #path(key: string): string {
    return join(this.#dir, `${key}.enc`);
  }

  async put(key: string, secret: string): Promise<void> {
    assertLegalKey(key);

    const salt = randomBytes(SALT_BYTES);
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', deriveKey(salt), iv);
    // Plaintext lives only in these two Buffers, only in memory.
    const plaintext = Buffer.from(secret, 'utf8');
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    plaintext.fill(0); // best-effort zeroization of the plaintext buffer

    const onDisk: OnDisk = {
      v: FORMAT_VERSION,
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ct: ct.toString('base64'),
    };
    // The bytes hitting disk are this JSON: version + salt + iv + tag + CIPHERTEXT. No plaintext.
    const bytes = Buffer.from(JSON.stringify(onDisk), 'utf8');

    mkdirSync(this.#dir, { recursive: true, mode: 0o700 });

    // Atomic write: ciphertext -> temp (0600) -> fsync -> rename. The temp file never holds
    // plaintext, so invariant 2 holds even mid-write and even if we crash between steps.
    const finalPath = this.#path(key);
    const tmpPath = `${finalPath}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
    try {
      const fd = openSync(tmpPath, 'wx', OWNER_ONLY);
      try {
        writeSync(fd, bytes);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(tmpPath, finalPath);
    } catch (error) {
      rmSync(tmpPath, { force: true });
      throw new EngineError('vault_unavailable', 'could not write the encrypted key store file', {
        hint: `Writing ${finalPath} failed. Nothing was written in plaintext; the safe state is disconnected.`,
        cause: error,
      });
    }

    // Write-then-verify, same contract as every backend.
    const readBack = await this.get(key);
    if (readBack !== secret) {
      throw new EngineError('vault_unavailable', 'the encrypted write did not survive a read-back', {
        hint: `Wrote ${finalPath} and read back ${readBack === null ? 'nothing' : 'a different value'}.`,
      });
    }
  }

  async get(key: string): Promise<string | null> {
    assertLegalKey(key);
    let raw: Buffer;
    try {
      raw = readFileSync(this.#path(key));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw new EngineError('vault_unavailable', 'could not read the encrypted key store file', {
        hint: `Reading ${this.#path(key)} failed.`,
        cause: error,
      });
    }

    let parsed: OnDisk;
    try {
      const obj = JSON.parse(raw.toString('utf8')) as OnDisk;
      if (obj === null || typeof obj !== 'object' || obj.v !== FORMAT_VERSION) throw new Error('shape');
      parsed = obj;
    } catch {
      throw new EngineError('vault_unavailable', 'the encrypted key store file is not in the expected format', {
        hint: `${this.#path(key)} is corrupt or from another version. Reconnect to rewrite it.`,
      });
    }

    try {
      const salt = Buffer.from(parsed.salt, 'base64');
      const iv = Buffer.from(parsed.iv, 'base64');
      const tag = Buffer.from(parsed.tag, 'base64');
      const ct = Buffer.from(parsed.ct, 'base64');
      const decipher = createDecipheriv('aes-256-gcm', deriveKey(salt), iv);
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
      const secret = plaintext.toString('utf8');
      plaintext.fill(0);
      return secret;
    } catch {
      // GCM auth failure: tampered file, or a different machine/user (wrong derived key).
      // Never echo any stored bytes — they are ciphertext of the secret.
      throw new EngineError('vault_unavailable', 'the encrypted key store item failed authentication', {
        hint: `${this.#path(key)} did not decrypt on this machine — it was tampered with, or moved from another machine/user. Reconnect to rewrite it.`,
      });
    }
  }

  async delete(key: string): Promise<void> {
    assertLegalKey(key);
    // Local-only, no network. Idempotent: `force` swallows ENOENT.
    rmSync(this.#path(key), { force: true });
  }
}
