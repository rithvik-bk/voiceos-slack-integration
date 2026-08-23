/**
 * C-23 — observability: the credential-free auth-event log and its metrics (SPEC §16, §29).
 * These tests own INV-OBS-1 (no credential in the log) and the three headline metrics:
 * connect success rate per provider, time-to-token p50/p95, and silent-refresh rate.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  log,
  metrics,
  metricsFor,
  percentile,
  record,
  recordConnectAttempt,
  recordConnectResult,
  recordTokenServed,
  reset,
  subscribe,
} from '../src/observability.ts';

/** Assembled, never a literal — a real token here would plant a scan-secrets finding. */
const SLACK = `xox${'p'}-A1b2C3d4E5f6G7h8i9J0kLmNoPqRsTuV`;

beforeEach(() => reset());
afterEach(() => reset());

describe('percentile — nearest-rank, pure', () => {
  it('returns undefined on an empty sample', () => {
    expect(percentile([], 50)).toBeUndefined();
  });

  it('computes p50 and p95 by nearest rank', () => {
    const s = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
    expect(percentile(s, 50)).toBe(50);
    expect(percentile(s, 95)).toBe(100);
    expect(percentile(s, 100)).toBe(100);
  });

  it('does not mutate its input', () => {
    const s = [3, 1, 2];
    percentile(s, 50);
    expect(s).toEqual([3, 1, 2]);
  });

  it('handles a single sample', () => {
    expect(percentile([42], 50)).toBe(42);
    expect(percentile([42], 95)).toBe(42);
  });
});

describe('INV-OBS-1 — the log carries no credential material', () => {
  it('scrubs a credential-shaped value out of every string field', () => {
    // A mis-wired caller shoves a token where a provider name belongs. It must not survive.
    record({ type: 'connect_result', provider: `slack ${SLACK}`, outcome: 'connected' });
    const [event] = log();
    expect(event).toBeDefined();
    expect(JSON.stringify(event)).not.toContain(SLACK);
    expect(JSON.stringify(event)).toContain('[redacted]');
  });

  it('has no field capable of holding a token — account_id is the opaque hash only', () => {
    record({ type: 'health_result', provider: 'slack', account_id: 'a1b2c3', outcome: 'healthy' });
    const [event] = log();
    // The event shape is closed: ts, type, provider, account_id, outcome, error_code, duration_ms.
    expect(Object.keys(event!).sort()).toEqual(
      ['account_id', 'outcome', 'provider', 'ts', 'type'].sort(),
    );
  });

  it('stamps its own timestamp — a caller cannot forge one', () => {
    const before = Date.now();
    record({ type: 'revocation', provider: 'zoom', outcome: 'forgotten' });
    const [event] = log();
    expect(event!.ts).toBeGreaterThanOrEqual(before);
  });
});

describe('the log', () => {
  it('is bounded — a long-lived process never grows it without limit', () => {
    for (let i = 0; i < 600; i++) record({ type: 'token_served', provider: 'slack', outcome: 'fresh' });
    expect(log().length).toBeLessThanOrEqual(500);
  });

  it('returns a copy — callers cannot mutate the store', () => {
    record({ type: 'revocation', provider: 'zoom', outcome: 'forgotten' });
    const snapshot = log();
    snapshot.length = 0;
    expect(log().length).toBe(1);
  });

  it('pushes every event to subscribers, and unsubscribe stops them', () => {
    const seen: string[] = [];
    const off = subscribe((e) => seen.push(e.type));
    record({ type: 'revocation', provider: 'zoom', outcome: 'forgotten' });
    off();
    record({ type: 'revocation', provider: 'zoom', outcome: 'forgotten' });
    expect(seen).toEqual(['revocation']);
  });

  it('a throwing sink never breaks the record path', () => {
    subscribe(() => {
      throw new Error('bad sink');
    });
    expect(() => record({ type: 'revocation', provider: 'zoom', outcome: 'forgotten' })).not.toThrow();
    expect(log().length).toBe(1);
  });
});

describe('connect success rate + time-to-token (§29)', () => {
  it('counts a fresh mint as a success with a measured time-to-token', () => {
    recordConnectAttempt('c_1', 'slack');
    recordConnectResult('c_1', 'slack', 'connected', { accountId: 'acct1' });
    const m = metricsFor('slack')!;
    expect(m.connectSuccess).toBe(1);
    expect(m.connectFailure).toBe(0);
    expect(m.connectSuccessRate).toBe(1);
    expect(m.timeToTokenP50Ms).toBeGreaterThanOrEqual(0);
    expect(m.timeToTokenP95Ms).toBeGreaterThanOrEqual(0);
  });

  it('counts a cache hit as a success but NOT as a time-to-token sample', () => {
    recordConnectAttempt('c_1', 'slack');
    recordConnectResult('c_1', 'slack', 'already_connected');
    const m = metricsFor('slack')!;
    expect(m.connectSuccess).toBe(1);
    expect(m.timeToTokenP50Ms).toBeUndefined();
  });

  it('counts denied/timeout/error as failures and computes the rate', () => {
    recordConnectAttempt('c_1', 'slack');
    recordConnectResult('c_1', 'slack', 'connected');
    recordConnectAttempt('c_2', 'slack');
    recordConnectResult('c_2', 'slack', 'denied', { errorCode: 'denied_by_user' });
    recordConnectAttempt('c_3', 'slack');
    recordConnectResult('c_3', 'slack', 'error', { errorCode: 'provider_error' });
    const m = metricsFor('slack')!;
    expect(m.connectSuccess).toBe(1);
    expect(m.connectFailure).toBe(2);
    expect(m.connectSuccessRate).toBeCloseTo(1 / 3, 5);
  });

  it('is undefined before any terminal connect', () => {
    recordConnectAttempt('c_1', 'slack');
    expect(metricsFor('slack')!.connectSuccessRate).toBeUndefined();
  });
});

describe('silent-refresh rate (§29 — target 1.0)', () => {
  it('a fresh serve and a successful refresh are both silent', () => {
    recordTokenServed('slack', 'fresh');
    recordTokenServed('slack', 'refreshed');
    expect(metricsFor('slack')!.silentRefreshRate).toBe(1);
  });

  it('a reauth-required serve drops the rate below 1', () => {
    recordTokenServed('slack', 'fresh');
    recordTokenServed('slack', 'fresh');
    recordTokenServed('slack', 'fresh');
    recordTokenServed('slack', 'reauth_required', { errorCode: 'expired_or_revoked' });
    expect(metricsFor('slack')!.silentRefreshRate).toBeCloseTo(3 / 4, 5);
    expect(metricsFor('slack')!.reauthCount).toBe(1);
  });
});

describe('needs-attention ranking (§16)', () => {
  it('ranks providers worst-first by failures + reauths + broken-health', () => {
    // healthy provider: only successes
    recordConnectAttempt('a', 'good');
    recordConnectResult('a', 'good', 'connected');
    // troubled provider: failures + a reauth + a broken probe
    recordConnectAttempt('b', 'bad');
    recordConnectResult('b', 'bad', 'error', { errorCode: 'provider_error' });
    recordTokenServed('bad', 'reauth_required', { errorCode: 'expired_or_revoked' });
    record({ type: 'health_result', provider: 'bad', outcome: 'broken', error_code: 'expired_or_revoked' });

    const { needsAttention } = metrics();
    expect(needsAttention[0]).toBe('bad');
    expect(needsAttention).not.toContain('good');
  });

  it('omits providers with nothing wrong', () => {
    recordConnectAttempt('a', 'good');
    recordConnectResult('a', 'good', 'connected');
    expect(metrics().needsAttention).toEqual([]);
  });
});

describe('metrics snapshot shape', () => {
  it('lists every provider seen, sorted, and revocations are counted', () => {
    record({ type: 'revocation', provider: 'zoom', outcome: 'revoked' });
    recordConnectAttempt('a', 'slack');
    recordConnectResult('a', 'slack', 'connected');
    const providers = metrics().providers.map((p) => p.provider);
    expect(providers).toEqual(['slack', 'zoom']);
    expect(metricsFor('zoom')!.revocations).toBe(1);
  });
});
