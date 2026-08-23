// ATTACK: RFC 9207 mix-up — a response from provider A satisfying provider B's flow.
// SPEC §12 (mix-up between concurrent providers). INV-STATE-3.
import { describe, test, expect, beforeEach } from 'vitest';
import { bindFlow, checkFlow, assertFlow, clearFlows, clearFlow } from '../../src/mixup.ts';

describe('provider mix-up (RFC 9207)', () => {
  beforeEach(() => clearFlows());

  test('a callback that arrives for a different provider than it was bound to is refused', () => {
    // Two flows are in flight; the attacker replays provider A's code into provider B's pending flow.
    bindFlow('state-A', 'slack');
    const wrongProvider = checkFlow('state-A', 'notion', 'https://notion.so');
    expect(wrongProvider.ok).toBe(false);            // INV-STATE-3
    expect(() => assertFlow('state-A', 'notion', 'https://notion.so')).toThrow();
  });

  test('the matching provider on the matching state is accepted', () => {
    bindFlow('state-ok', 'slack');
    expect(checkFlow('state-ok', 'slack', 'https://slack.com').ok).toBe(true);
    expect(() => assertFlow('state-ok', 'slack', 'https://slack.com')).not.toThrow();
  });

  test('an unknown / never-bound state is refused (no default-accept)', () => {
    const r = checkFlow('state-never-bound', 'slack', 'https://slack.com');
    expect(r.ok).toBe(false);
    expect(() => assertFlow('state-never-bound', 'slack', 'https://slack.com')).toThrow();
  });

  test('a spoofed issuer cannot override the provider binding (iss is not a bypass)', () => {
    // Attacker holds provider A (notion) code, and spoofs the victim provider (slack)
    // issuer string hoping `iss` matching is trusted over the provider binding. The
    // provider binding must dominate: notion can never satisfy slack's flow. INV-STATE-3.
    bindFlow('state-iss', 'slack');
    const spoofed = checkFlow('state-iss', 'notion', 'https://slack.com');
    expect(spoofed.ok).toBe(false);
  });

  test('clearing one flow does not leave a sibling flow satisfiable by the wrong provider', () => {
    bindFlow('s1', 'slack');
    bindFlow('s2', 'notion');
    clearFlow('s1');
    expect(checkFlow('s2', 'slack', 'https://slack.com').ok).toBe(false);
  });
});
