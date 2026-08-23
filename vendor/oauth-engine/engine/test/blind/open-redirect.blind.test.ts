// ATTACK: open redirect via redirect_uri — steering the callback to an attacker host,
// or breaking the byte-identity requirement between authorize and token requests.
// SPEC §7, §12 (open redirect; exact byte-identical redirect_uri). INV-REDIR-2/3.
import { describe, test, expect } from 'vitest';
import {
  REDIRECT_URIS,
  IP_REDIRECT_URIS,
  SANCTIONED_FALLBACK_REDIRECTS,
  CALLBACK_PATH,
  redirectUri,
} from '../../src/config.ts';

// The only hosts an on-device loopback flow may ever redirect to. Everything else is an
// open redirect. `voiceos.test` is the project's claimed custom-scheme test host.
const ALLOWED_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1', 'voiceos.test']);

const allSanctioned = [
  ...REDIRECT_URIS,
  ...IP_REDIRECT_URIS,
  ...SANCTIONED_FALLBACK_REDIRECTS,
];

describe('open redirect via redirect_uri', () => {
  test('every sanctioned redirect targets an allowlisted loopback/registered host only', () => {
    for (const uri of allSanctioned) {
      const u = new URL(uri);
      expect(ALLOWED_HOSTS.has(u.hostname)).toBe(true); // no attacker host
      expect(u.username).toBe('');                       // no user@ confusion
      expect(u.password).toBe('');
    }
  });

  test('every sanctioned redirect is an exact registered URI: exact path, no wildcard/query/fragment', () => {
    for (const uri of allSanctioned) {
      const u = new URL(uri);
      expect(u.pathname).toBe(CALLBACK_PATH);  // exact, byte-identical path (INV-REDIR-2)
      expect(u.search).toBe('');
      expect(u.hash).toBe('');
      expect(uri).not.toContain('*');           // no wildcard match
    }
  });

  test('redirectUri() cannot be driven to an external host by its input', () => {
    // redirect_uri is engine-controlled, never attacker/profile-controlled. Whatever port
    // is passed, the host stays an allowlisted loopback literal on the exact callback path.
    for (const port of [0, 80, 443, 33418, 65535, 8080]) {
      const u = new URL(redirectUri(port));
      expect(ALLOWED_HOSTS.has(u.hostname)).toBe(true);
      expect(u.pathname).toBe(CALLBACK_PATH);
      expect(u.protocol === 'http:' || u.protocol === 'https:').toBe(true);
    }
  });

  test('no sanctioned redirect points at a public/attacker domain', () => {
    const joined = allSanctioned.join(' ');
    for (const bad of ['evil.com', 'attacker', 'ngrok', 'http://169.254.169.254', 'xn--']) {
      expect(joined.toLowerCase()).not.toContain(bad);
    }
  });
});
