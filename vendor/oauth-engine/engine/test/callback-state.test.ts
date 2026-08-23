/**
 * C-2 tests — the callback `state` gate. The point is the three refusals, exactly as with
 * state.ts, but proven THROUGH the gate loopback.ts actually calls, against the real store.
 *
 * Time is faked so the 60s TTL is proven without a 60s wait: vitest's fake timers move the
 * Date.now() that consumeState() reads.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { evaluateCallbackState } from '../src/callbackState.ts';
import { STATE_TTL_MS } from '../src/config.ts';
import { clearStates, mintState, pendingStates } from '../src/state.ts';

beforeEach(() => {
  clearStates();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  clearStates();
});

describe('evaluateCallbackState (C-2 single-use + TTL wiring)', () => {
  it('accepts the state this listener minted, exactly once', () => {
    const state = mintState();
    expect(evaluateCallbackState(state, state)).toBe('accept');
    // The store is now empty: the accepting call redeemed it.
    expect(pendingStates()).toBe(0);
  });

  it('refuses a replay of an already-redeemed state (CSRF replay)', () => {
    const state = mintState();
    expect(evaluateCallbackState(state, state)).toBe('accept');
    // Browser back button, a copied callback URL, an attacker resending the same callback.
    expect(evaluateCallbackState(state, state)).toBe('stale');
  });

  it('refuses a state that has outlived STATE_TTL_MS', () => {
    const state = mintState();
    vi.advanceTimersByTime(STATE_TTL_MS + 1);
    // The listener still expects it, but the store has aged it out: a stale bearer token.
    expect(evaluateCallbackState(state, state)).toBe('stale');
    expect(pendingStates()).toBe(0);
  });

  it('accepts a state redeemed one millisecond before it would expire', () => {
    const state = mintState();
    vi.advanceTimersByTime(STATE_TTL_MS - 1);
    expect(evaluateCallbackState(state, state)).toBe('accept');
  });

  it('treats a state that is not this listener\'s as foreign, and NEVER consumes it', () => {
    // Two concurrent connects mint into the one store.
    const mine = mintState();
    const sibling = mintState();
    expect(pendingStates()).toBe(2);

    // A callback carrying the sibling flow's state lands on THIS listener. It must be
    // rejected as foreign AND the sibling's one-shot state must survive untouched — otherwise
    // one flow could cancel another just by echoing its state at the wrong socket.
    expect(evaluateCallbackState(sibling, mine)).toBe('foreign');
    expect(pendingStates()).toBe(2);

    // Both flows can still complete on their own listeners.
    expect(evaluateCallbackState(sibling, sibling)).toBe('accept');
    expect(evaluateCallbackState(mine, mine)).toBe('accept');
  });

  it('treats a forgery of the same length as foreign (no timing/length oracle)', () => {
    const state = mintState();
    const forged = `${state.slice(0, -1)}${state.endsWith('A') ? 'B' : 'A'}`;
    expect(forged).toHaveLength(state.length);
    expect(evaluateCallbackState(forged, state)).toBe('foreign');
    // The real state is intact and still redeemable.
    expect(evaluateCallbackState(state, state)).toBe('accept');
  });

  it('treats a length-mismatched guess as foreign without throwing', () => {
    const state = mintState();
    expect(evaluateCallbackState('', state)).toBe('foreign');
    expect(evaluateCallbackState('too-short', state)).toBe('foreign');
    expect(evaluateCallbackState(`${state}extra`, state)).toBe('foreign');
    expect(evaluateCallbackState(state, state)).toBe('accept');
  });
});
