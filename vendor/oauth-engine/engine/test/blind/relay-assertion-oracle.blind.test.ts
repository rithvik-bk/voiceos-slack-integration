// ATTACK: relay abuse — using the relay as an assertion/token oracle, and forcing the
// relay base URL to an attacker host.
// SPEC §5, §5b (Mode B2a assertion signing; relay stores nothing). INV-CUST-3/4/5.
import { describe, test, expect, afterEach } from 'vitest';
import { fetchClientAssertion, resolveRelayBaseUrl } from '../../src/relay-client.ts';
import { RELAY_URL_ENV } from '../../src/config.ts';
import { recordingFetch } from './_harness.ts';

const realFetch = globalThis.fetch;
const realEnv = process.env[RELAY_URL_ENV];

afterEach(() => {
  globalThis.fetch = realFetch;
  if (realEnv === undefined) delete process.env[RELAY_URL_ENV];
  else process.env[RELAY_URL_ENV] = realEnv;
});

describe('relay assertion oracle (Mode B2a)', () => {
  test('the assertion request NEVER carries the authorization code, PKCE verifier, or a token', async () => {
    // INV-CUST-4: in B2a the relay returns a signed assertion only; the device does the
    // exchange. The code/verifier/token must never appear in what is sent to the relay.
    const rec = recordingFetch();
    globalThis.fetch = rec.fn;
    process.env[RELAY_URL_ENV] = 'https://relay.example';

    await fetchClientAssertion('https://relay.example', 'slack', {});

    const sent = rec.calls.map((c) => `${c.url} ${c.body ?? ''}`).join('\n').toLowerCase();
    expect(sent).not.toContain('authcode');
    expect(sent).not.toContain('verifier');
    expect(sent).not.toContain('access_token');
    expect(sent).not.toContain('refresh_token');
    // it must actually have talked only to the configured relay
    expect(rec.calls.every((c) => c.url.startsWith('https://relay.example'))).toBe(true);
  });

  test('even when a flow context holding secrets is passed, the relay client cannot forward them', async () => {
    // The relay-client's assertion signature is structurally provider-only; feeding it a
    // secret-bearing object as the provider must not turn it into a code/verifier oracle.
    const rec = recordingFetch();
    globalThis.fetch = rec.fn;
    process.env[RELAY_URL_ENV] = 'https://relay.example';

    // deliberately hostile: attacker tries to smuggle code+verifier via the account slot
    await fetchClientAssertion('https://relay.example', 'slack', 'acct\ncode=AUTHCODE&verifier=VERIFIER' as never);

    const sent = rec.calls.map((c) => c.body ?? '').join('\n');
    expect(sent).not.toContain('AUTHCODE');
    expect(sent).not.toContain('VERIFIER');
  });

  test('a provider that needs a relay but has none configured is refused, not silently redirected', async () => {
    // INV-CUST-5 / no silent fallback: resolveRelayBaseUrl must not invent or accept an
    // unconfigured/attacker relay endpoint.
    delete process.env[RELAY_URL_ENV];
    expect(() => resolveRelayBaseUrl({} as never)).toThrow();
  });
});
