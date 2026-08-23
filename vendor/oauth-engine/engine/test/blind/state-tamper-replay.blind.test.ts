// ATTACK: tampered / replayed `state`, and admission of a superseded flow.
// SPEC §12 (CSRF on callback), §14 (supersession). INV-STATE-1/2, INV-FLOW-1/2.
import { describe, test, expect, beforeEach } from 'vitest';
import { mintState, consumeState, clearStates } from '../../src/state.ts';
import { begin, admit, clearFlows } from '../../src/singleflight.ts';
import { b64urlBytes } from './_harness.ts';

describe('state tampering & replay', () => {
  beforeEach(() => { clearStates(); clearFlows(); });

  test('a valid state is single-use: a replay of the same state is refused', () => {
    const s = mintState();
    expect(consumeState(s)).toBe(true);   // first, legitimate callback
    expect(consumeState(s)).toBe(false);  // attacker replays the captured state
  });

  test('a forged state that the engine never minted is refused', () => {
    expect(consumeState('totally-forged-state-value-not-minted')).toBe(false);
    expect(consumeState('')).toBe(false);
    // @ts-expect-error attacker sends a non-string
    expect(consumeState(undefined)).toBe(false);
  });

  test('a single flipped character in a real state is refused (no fuzzy match)', () => {
    const s = mintState();
    const tampered = (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
    expect(consumeState(tampered)).toBe(false);
  });

  test('state carries >=32 bytes of entropy and never repeats', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 500; i++) {
      const s = mintState();
      expect(b64urlBytes(s)).toBeGreaterThanOrEqual(32); // INV-STATE-1
      expect(seen.has(s)).toBe(false);
      seen.add(s);
    }
  });

  test('admission is authoritative: a superseded flow\'s state is refused even if valid', () => {
    // §14 / INV-FLOW-2: a second connect() for the same (provider,account) supersedes the first.
    const s1 = mintState();
    begin('slack', s1);
    expect(admit(s1)).toBe(true);        // first flow is live

    const s2 = mintState();
    begin('slack', s2);                  // supersedes s1
    expect(admit(s1)).toBe(false);       // the abandoned flow's callback must NOT be admitted
    expect(admit(s2)).toBe(true);        // only the live flow admits
  });
});
