/**
 * state tests — the three rejects are the point, not the happy path.
 *
 * Time is faked rather than slept: a 60s TTL proven by a real 60s wait is a test nobody
 * runs, and vitest's fake timers move Date.now() with them, which is what the TTL reads.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { STATE_TTL_MS } from '../src/config.ts';
import { clearStates, consumeState, mintState, pendingStates } from '../src/state.ts';

beforeEach(() => {
  clearStates();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  clearStates();
});

describe('state', () => {
  it('mints an unguessable base64url value', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 500; i += 1) {
      const value = mintState();
      expect(value).toMatch(/^[A-Za-z0-9_-]{43}$/); // 32 random bytes, no padding
      seen.add(value);
    }
    expect(seen.size).toBe(500);
  });

  it('accepts the state it minted (happy path)', () => {
    const value = mintState();
    expect(consumeState(value)).toBe(true);
  });

  it('rejects a replay of an already-consumed state', () => {
    const value = mintState();
    expect(consumeState(value)).toBe(true);
    expect(consumeState(value)).toBe(false);
    expect(pendingStates()).toBe(0);
  });

  it('rejects a state that has outlived its TTL', () => {
    const value = mintState();
    vi.advanceTimersByTime(STATE_TTL_MS - 1);
    expect(pendingStates()).toBe(1);

    vi.advanceTimersByTime(2);
    expect(consumeState(value)).toBe(false);
    expect(pendingStates()).toBe(0);
  });

  it('rejects anything it did not mint', () => {
    mintState();
    expect(consumeState('')).toBe(false);
    expect(consumeState('not-a-state')).toBe(false);
    // Same shape, same length, one byte different: the forgery a length check would miss.
    const real = mintState();
    const forged = `${real.slice(0, -1)}${real.endsWith('A') ? 'B' : 'A'}`;
    expect(forged).toHaveLength(real.length);
    expect(consumeState(forged)).toBe(false);
    expect(consumeState(real)).toBe(true);
  });

  it('keeps concurrent connects independent', () => {
    const first = mintState();
    const second = mintState();
    expect(pendingStates()).toBe(2);
    expect(consumeState(second)).toBe(true);
    expect(pendingStates()).toBe(1);
    expect(consumeState(first)).toBe(true);
  });

  it('does not leak minted-but-never-used states forever', () => {
    for (let i = 0; i < 10; i += 1) mintState();
    expect(pendingStates()).toBe(10);
    vi.advanceTimersByTime(STATE_TTL_MS + 1);
    mintState(); // minting sweeps
    expect(pendingStates()).toBe(1);
  });
});
