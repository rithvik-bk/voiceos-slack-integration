/**
 * Key validation shared by every KeyStore backend.
 *
 * A KeyStore key becomes part of a Keychain service name AND a filesystem path. Both are
 * injection surfaces: a key like `../../etc/passwd` or one carrying a shell metacharacter is
 * a path-traversal or command-injection bug depending on the backend. The charset here is the
 * one `vault.ts` already enforced for provider names, widened to nothing — leading char must
 * be alphanumeric, the rest `[A-Za-z0-9._-]`. Dots are allowed (keys look like
 * `com.voiceos.connect.slack`); slashes, spaces, and every shell/path metacharacter are not.
 */

import { EngineError } from '../errors.ts';

const LEGAL_KEY = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

export function assertLegalKey(key: string): void {
  if (typeof key !== 'string' || !LEGAL_KEY.test(key)) {
    throw new EngineError('config_invalid', 'key store key is not a legal key', {
      hint: `Keys are [A-Za-z0-9] then [A-Za-z0-9._-]; got ${JSON.stringify(key)}.`,
    });
  }
}
