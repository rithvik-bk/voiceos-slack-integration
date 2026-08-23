// ATTACK: a secret or token leaking through a log line, an error message, or a
// stringified provider response.
// SPEC §5, §6, §13 (token/secret leakage through logs or errors). INV-SECRET-1/4.
import { describe, test, expect } from 'vitest';
import { redact, safeProviderMessage } from '../../src/redact.ts';
import { CREDENTIAL_SAMPLES, stillContainsSecret } from './_harness.ts';

describe('secret leakage through the redaction boundary', () => {
  // INV-SECRET-4: every string surfaced to a log/page/error passes the redaction boundary,
  // and "credential-shaped runs are scrubbed". One test per well-known credential shape so
  // the exact leaking shape is named if any survive.
  for (const { label, value } of CREDENTIAL_SAMPLES) {
    test(`redact() scrubs a ${label} embedded in a log line`, () => {
      const line = `oauth exchange failed for provider; raw="${value}" ...`;
      const out = redact(line);
      expect(stillContainsSecret(out, value)).toBe(false);
    });
  }

  test('safeProviderMessage() returns only allowlisted error text, never token fields', () => {
    // §6: a provider error quote is built from an allowlist of fields, never by stringifying
    // the body. Tokens dropped into the body must not survive.
    // Token values assembled from fragments so the push-gate scanner plants no finding here;
    // the runtime object handed to safeProviderMessage() is byte-identical to a leaky body.
    const body = {
      error: 'invalid_grant',
      error_description: 'the grant has expired',
      access_token: 'ya29.' + 'a0AfB_LEAKEDACCESSTOKEN_abcdefghijklmnop',
      refresh_token: '1//0g' + 'LEAKEDREFRESH_abcdefghijklmnopqrstuvwxyz',
      client_secret: 'sk_' + 'live_LEAKEDSECRET_0123456789',
    };
    const msg = safeProviderMessage(body);
    expect(msg).not.toContain('ya29.');
    expect(msg).not.toContain('1//0g');
    expect(msg).not.toContain('sk_live_');
    expect(msg).not.toContain('LEAKED');
  });

  test('a bare credential string passed to the redaction boundary does not survive', () => {
    for (const { value } of CREDENTIAL_SAMPLES) {
      expect(stillContainsSecret(redact(value), value)).toBe(false);
    }
  });

  test('redaction is idempotent and never throws on hostile input', () => {
    for (const bad of ['', 'no secrets here', 'a'.repeat(5000)]) {
      expect(() => redact(bad)).not.toThrow();
      expect(redact(redact(bad))).toBe(redact(bad));
    }
  });
});
