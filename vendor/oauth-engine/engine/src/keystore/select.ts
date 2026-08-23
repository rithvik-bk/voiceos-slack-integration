/**
 * KeyStore selection (SPEC §6): pick the strongest backend the platform offers, and NEVER
 * fall back to the weak encrypted-file backend silently.
 *
 * The ladder today:
 *   - macOS  -> MacSecurityKeyStore (strong). The N-API native binding is the production
 *              upgrade above it, but that requires code-signing + a keychain-access-group
 *              entitlement (human-gated), so the CLI backend is the shipped strong rung here.
 *   - other  -> no strong backend is implemented yet. The selector REFUSES to return the
 *              weak encrypted-file backend unless the caller opts in explicitly, because a
 *              silent downgrade to weaker custody is exactly the failure §6 forbids.
 *
 * "Never silently selected" is enforced structurally: the encrypted-file backend is only ever
 * returned when `allowWeakEncryptedFile: true` AND an explicit `encryptedFileDir` are passed.
 * Absent that, an unsupported platform throws a `config_invalid` telling the operator to opt
 * in on purpose.
 */

import { EngineError } from '../errors.ts';
import type { KeyStore } from './types.ts';
import { MacSecurityKeyStore } from './security-backend.ts';
import { EncryptedFileKeyStore } from './encrypted-file-backend.ts';

export interface SelectOptions {
  /** Override the detected platform. Testing seam; defaults to `process.platform`. */
  platform?: NodeJS.Platform;
  /**
   * Explicit, deliberate opt-in to the WEAK encrypted-file backend when no strong backend
   * exists on this platform. Without this the selector throws rather than downgrade silently.
   */
  allowWeakEncryptedFile?: boolean;
  /** Directory for the encrypted-file backend. Required whenever it is the chosen backend. */
  encryptedFileDir?: string;
}

export function selectKeyStore(options: SelectOptions = {}): KeyStore {
  const plat = options.platform ?? process.platform;

  if (plat === 'darwin') return new MacSecurityKeyStore();

  // No strong backend implemented for this platform yet (Windows DPAPI / Linux libsecret are
  // future rungs). The ONLY remaining option is the weak backend — and it is never automatic.
  if (options.allowWeakEncryptedFile === true) {
    if (options.encryptedFileDir === undefined || options.encryptedFileDir.trim() === '') {
      throw new EngineError('config_invalid', 'encrypted-file key store requires an explicit directory', {
        hint: 'Set encryptedFileDir when allowWeakEncryptedFile is true.',
      });
    }
    return new EncryptedFileKeyStore(options.encryptedFileDir);
  }

  throw new EngineError('config_invalid', `no strong key store backend for platform ${plat}`, {
    hint:
      'This platform has no OS keyring backend yet. The encrypted-file backend is WEAKER and is ' +
      'never selected automatically; pass { allowWeakEncryptedFile: true, encryptedFileDir } to ' +
      'opt into it on purpose.',
  });
}
