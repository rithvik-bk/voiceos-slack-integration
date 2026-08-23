/**
 * C-16 single-flight + supersession tests (SPEC §14).
 *
 * The properties, each a real production failure if dropped:
 *   INV-FLOW-1  one live flow per (provider, account); a second connect() supersedes the first.
 *   INV-FLOW-2  admission is authoritative — a superseded flow's state is refused regardless of
 *               whether its listener was torn down in time; teardown is advisory.
 *
 * Time is faked (vitest fake timers move Date.now(), which the TTL reads) rather than slept.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { STATE_TTL_MS } from '../src/config.ts';
import {
  DEFAULT_ACCOUNT,
  admit,
  begin,
  clearFlows,
  complete,
  live,
  pending,
  statusOf,
} from '../src/singleflight.ts';

beforeEach(() => {
  clearFlows();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  clearFlows();
});

describe('begin — the flow token', () => {
  it('carries (provider, account, state, nonce, started_at)', () => {
    const now = Date.now();
    const flow = begin('slack', 'state-1', { account: 'acct-a' });
    expect(flow.token.provider).toBe('slack');
    expect(flow.token.account).toBe('acct-a');
    expect(flow.token.state).toBe('state-1');
    expect(flow.token.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(flow.token.startedAt).toBe(now);
  });

  it('defaults the account slot when none is given', () => {
    const flow = begin('zoom', 'state-z');
    expect(flow.token.account).toBe(DEFAULT_ACCOUNT);
  });

  it('respects a caller-supplied nonce', () => {
    const flow = begin('slack', 'state-1', { nonce: 'fixed-nonce' });
    expect(flow.token.nonce).toBe('fixed-nonce');
  });

  it('mints a distinct nonce per flow', () => {
    const a = begin('slack', 'state-a');
    const b = begin('zoom', 'state-b');
    expect(a.token.nonce).not.toBe(b.token.nonce);
  });

  it('refuses an empty state', () => {
    expect(() => begin('slack', '')).toThrow(/state must not be empty/);
  });

  it('refuses reusing a live state for a second flow', () => {
    begin('slack', 'dupe');
    expect(() => begin('zoom', 'dupe')).toThrow(/already registered/);
  });
});

describe('admission (INV-FLOW-2)', () => {
  it('admits the live flow', () => {
    begin('slack', 'state-1');
    expect(admit('state-1')).toBe(true);
    expect(statusOf('state-1')).toBe('live');
  });

  it('refuses a state it never registered', () => {
    begin('slack', 'state-1');
    expect(admit('forged')).toBe(false);
    expect(statusOf('forged')).toBe('unknown');
  });
});

describe('supersession (INV-FLOW-1)', () => {
  it('a second connect for the same slot supersedes the first', () => {
    const teardown = vi.fn();
    begin('slack', 'first', { teardown });
    begin('slack', 'second');

    expect(admit('first')).toBe(false);
    expect(statusOf('first')).toBe('superseded');
    expect(admit('second')).toBe(true);
    expect(pending()).toBe(1);
    expect(teardown).toHaveBeenCalledTimes(1);
  });

  it('a superseded flow is refused even if its valid code arrives (admission is authoritative)', () => {
    // No teardown at all: the prior listener is NOT torn down. Admission must still refuse it.
    begin('slack', 'first');
    begin('slack', 'second');
    expect(admit('first')).toBe(false);
  });

  it('supersession is per (provider, account): different accounts coexist', () => {
    const teardown = vi.fn();
    begin('slack', 'work', { account: 'work', teardown });
    begin('slack', 'personal', { account: 'personal' });

    expect(admit('work')).toBe(true);
    expect(admit('personal')).toBe(true);
    expect(pending()).toBe(2);
    expect(teardown).not.toHaveBeenCalled();
  });

  it('different providers coexist', () => {
    begin('slack', 'sk');
    begin('zoom', 'zm');
    expect(admit('sk')).toBe(true);
    expect(admit('zm')).toBe(true);
    expect(pending()).toBe(2);
  });

  it('a teardown that throws cannot make a superseded flow admissible', () => {
    begin('slack', 'first', {
      teardown: () => {
        throw new Error('teardown blew up');
      },
    });
    expect(() => begin('slack', 'second')).not.toThrow();
    expect(admit('first')).toBe(false);
    expect(admit('second')).toBe(true);
  });

  it('a teardown returning a rejected promise is swallowed', () => {
    begin('slack', 'first', { teardown: () => Promise.reject(new Error('async fail')) });
    expect(() => begin('slack', 'second')).not.toThrow();
    expect(admit('second')).toBe(true);
  });

  it('reports the live flow for a slot', () => {
    expect(live('slack')).toBeNull();
    begin('slack', 'state-1');
    expect(live('slack')?.token.state).toBe('state-1');
    begin('slack', 'state-2');
    expect(live('slack')?.token.state).toBe('state-2');
  });
});

describe('complete — freeing the slot', () => {
  it('a completed flow is no longer admissible and frees its slot', () => {
    begin('slack', 'state-1');
    complete('state-1');
    expect(admit('state-1')).toBe(false);
    expect(statusOf('state-1')).toBe('completed');
    expect(live('slack')).toBeNull();
    expect(pending()).toBe(0);
  });

  it('a fresh connect after completion does not supersede (teardown not fired)', () => {
    const teardown = vi.fn();
    begin('slack', 'first', { teardown });
    complete('first');
    begin('slack', 'second');
    expect(teardown).not.toHaveBeenCalled();
    expect(admit('second')).toBe(true);
  });
});

describe('TTL', () => {
  it('a flow past its TTL is neither admissible nor live', () => {
    begin('slack', 'state-1');
    vi.advanceTimersByTime(STATE_TTL_MS + 1);
    expect(admit('state-1')).toBe(false);
    expect(statusOf('state-1')).toBe('expired');
    expect(live('slack')).toBeNull();
    expect(pending()).toBe(0);
  });

  it('an expired flow is not treated as superseded (no teardown fired) by a later connect', () => {
    const teardown = vi.fn();
    begin('slack', 'first', { teardown });
    vi.advanceTimersByTime(STATE_TTL_MS + 1);
    begin('slack', 'second');
    expect(teardown).not.toHaveBeenCalled();
    expect(admit('second')).toBe(true);
  });

  it('honors a custom ttl', () => {
    begin('slack', 'state-1', { ttlMs: 1000 });
    vi.advanceTimersByTime(1001);
    expect(admit('state-1')).toBe(false);
  });
});

describe('clearFlows', () => {
  it('forgets everything', () => {
    begin('slack', 'state-1');
    begin('zoom', 'state-2');
    clearFlows();
    expect(pending()).toBe(0);
    expect(admit('state-1')).toBe(false);
  });
});
