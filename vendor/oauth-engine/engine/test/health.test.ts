/**
 * C-12 — background token-health probe (SPEC §10). Owns INV-REL-3: budgeted, backoff-on-failure,
 * never-during-an-active-turn, idle/connectivity-aware, silent-unless-broken. Every test drives a
 * fake clock and injected gates/deps, so the whole discipline is deterministic and touches no
 * keychain, no network, and no real timer.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import * as obs from '../src/observability.ts';
import {
  DEFAULT_BACKOFF_BASE_MS,
  DEFAULT_DAILY_BUDGET,
  DEFAULT_GATES,
  DEFAULT_MIN_INTERVAL_MS,
  HealthMonitor,
  configFor,
  initialState,
  runProbe,
  shouldProbe,
  type HealthConfig,
  type HealthDeps,
  type HealthGates,
  type HealthTarget,
} from '../src/health.ts';
import { EngineError } from '../src/errors.ts';
import type { ProviderProfile } from '../src/types.ts';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

const CONFIG: HealthConfig = {
  dailyBudget: 3,
  minIntervalMs: 4 * HOUR,
  backoffBaseMs: 15 * 60_000,
  backoffMaxMs: 12 * HOUR,
};

/** A profile stub — runProbe only reads it through the injected probe + configFor. */
function profile(name: string, hint?: { daily_budget?: number; min_interval_ms?: number }): ProviderProfile {
  return { name, ...(hint === undefined ? {} : { health_probe: hint }) } as unknown as ProviderProfile;
}

/** Deps whose probe outcome the test controls. */
function deps(probeResult: () => Promise<void>, token: string | null = 'tok'): HealthDeps {
  return {
    resolveProfile: (name) => Promise.resolve(profile(name)),
    readAccessToken: () => Promise.resolve(token),
    probe: () => probeResult(),
  };
}

const ok = (): Promise<void> => Promise.resolve();
const dead = (): Promise<void> =>
  Promise.reject(new EngineError('expired_or_revoked', 'token revoked'));
const transient = (): Promise<void> =>
  Promise.reject(new EngineError('provider_error', 'network down'));

beforeEach(() => obs.reset());
afterEach(() => obs.reset());

/* ─────────────────────────── shouldProbe: the §10 gates ─────────────────────────── */

describe('shouldProbe — INV-REL-3 gates (pure)', () => {
  const now = 1_000_000;
  const fresh = () => initialState('slack', undefined, now);

  it('runs when every gate is clear', () => {
    expect(shouldProbe(fresh(), CONFIG, now, DEFAULT_GATES)).toBe('ok');
  });

  it('NEVER runs during an active turn — the first and most important gate', () => {
    const gates: HealthGates = { ...DEFAULT_GATES, isActiveTurn: () => true };
    expect(shouldProbe(fresh(), CONFIG, now, gates)).toBe('active_turn');
  });

  it('does not run while the machine is asleep', () => {
    const gates: HealthGates = { ...DEFAULT_GATES, isMachineAwake: () => false };
    expect(shouldProbe(fresh(), CONFIG, now, gates)).toBe('asleep');
  });

  it('does not run on a metered connection', () => {
    const gates: HealthGates = { ...DEFAULT_GATES, isConnectivityMetered: () => true };
    expect(shouldProbe(fresh(), CONFIG, now, gates)).toBe('metered');
  });

  it('does not run on low power', () => {
    const gates: HealthGates = { ...DEFAULT_GATES, isPowerOk: () => false };
    expect(shouldProbe(fresh(), CONFIG, now, gates)).toBe('low_power');
  });

  it('refuses once the daily budget is exhausted', () => {
    const state = fresh();
    state.probesToday = CONFIG.dailyBudget;
    expect(shouldProbe(state, CONFIG, now, DEFAULT_GATES)).toBe('budget_exhausted');
  });

  it('rolls the daily window forward — yesterday’s spend does not block today', () => {
    const state = fresh();
    state.probesToday = CONFIG.dailyBudget;
    state.windowStartMs = now - DAY - 1;
    expect(shouldProbe(state, CONFIG, now, DEFAULT_GATES)).toBe('ok');
  });

  it('respects the minimum interval / backoff via nextEligibleMs', () => {
    const state = fresh();
    state.nextEligibleMs = now + HOUR;
    expect(shouldProbe(state, CONFIG, now, DEFAULT_GATES)).toBe('too_soon');
  });

  it('an environmental refusal is checked before budget (a shed probe spends nothing)', () => {
    const state = fresh();
    state.probesToday = CONFIG.dailyBudget;
    const gates: HealthGates = { ...DEFAULT_GATES, isActiveTurn: () => true };
    expect(shouldProbe(state, CONFIG, now, gates)).toBe('active_turn');
  });
});

/* ─────────────────────────── runProbe: outcomes + backoff ─────────────────────────── */

describe('runProbe — silent success, loud-once break, backoff', () => {
  const now = 5_000_000;

  it('a healthy probe is SILENT (no transition, no reauth event) and spaces the next check', async () => {
    const state = initialState('slack', undefined, now);
    const badges: HealthTarget[] = [];
    const report = await runProbe(state, CONFIG, deps(ok), now, (t) => badges.push(t));
    expect(report.status).toBe('healthy');
    expect(report.transitionedToBroken).toBe(false);
    expect(badges).toEqual([]);
    expect(state.nextEligibleMs).toBe(now + CONFIG.minIntervalMs);
    expect(state.probesToday).toBe(1);
    // A health_result:healthy is logged, but no reauth serve is recorded.
    expect(obs.metricsFor('slack')?.reauthCount ?? 0).toBe(0);
  });

  it('a dead credential breaks the target and fires onBroken exactly ONCE on transition', async () => {
    const state = initialState('slack', undefined, now);
    const badges: HealthTarget[] = [];
    const first = await runProbe(state, CONFIG, deps(dead), now, (t) => badges.push(t));
    expect(first.status).toBe('broken');
    expect(first.transitionedToBroken).toBe(true);
    expect(badges).toEqual([{ provider: 'slack' }]);

    // A second dead probe stays broken and does NOT fire the badge again.
    const second = await runProbe(state, CONFIG, deps(dead), now + DAY, (t) => badges.push(t));
    expect(second.transitionedToBroken).toBe(false);
    expect(badges.length).toBe(1);
  });

  it('a broken transition records a reauth serve, feeding the re-auth rate (§16)', async () => {
    const state = initialState('slack', undefined, now);
    await runProbe(state, CONFIG, deps(dead), now);
    expect(obs.metricsFor('slack')!.reauthCount).toBe(1);
    expect(obs.metricsFor('slack')!.healthBroken).toBeGreaterThanOrEqual(1);
  });

  it('a TRANSIENT failure does NOT mark the token broken (a provider outage is not a dead token)', async () => {
    const state = initialState('slack', undefined, now);
    const badges: HealthTarget[] = [];
    const report = await runProbe(state, CONFIG, deps(transient), now, (t) => badges.push(t));
    expect(report.status).toBe('unknown'); // unchanged from initial
    expect(report.transitionedToBroken).toBe(false);
    expect(badges).toEqual([]);
    expect(obs.metricsFor('slack')?.reauthCount ?? 0).toBe(0);
  });

  it('backs off exponentially on consecutive failures, not a retry storm', async () => {
    const state = initialState('slack', undefined, now);
    await runProbe(state, CONFIG, deps(transient), now);
    const after1 = state.nextEligibleMs - now;
    expect(after1).toBe(CONFIG.backoffBaseMs);

    await runProbe(state, CONFIG, deps(transient), state.nextEligibleMs);
    const after2 = state.nextEligibleMs - state.lastProbeMs!;
    expect(after2).toBe(CONFIG.backoffBaseMs * 2);
  });

  it('caps the backoff at backoffMaxMs', async () => {
    const state = initialState('slack', undefined, now);
    state.consecutiveFailures = 20; // would explode without the cap
    await runProbe(state, CONFIG, deps(transient), now);
    expect(state.nextEligibleMs - now).toBe(CONFIG.backoffMaxMs);
  });

  it('recovery from broken to healthy is silent (no badge, no reauth)', async () => {
    const state = initialState('slack', undefined, now);
    await runProbe(state, CONFIG, deps(dead), now); // break it
    const badges: HealthTarget[] = [];
    const report = await runProbe(state, CONFIG, deps(ok), now + DAY, (t) => badges.push(t));
    expect(report.status).toBe('healthy');
    expect(report.transitionedToBroken).toBe(false);
    expect(badges).toEqual([]);
    expect(state.consecutiveFailures).toBe(0);
  });

  it('nothing vaulted is not a health problem — silent, no break', async () => {
    const state = initialState('slack', undefined, now);
    const report = await runProbe(state, CONFIG, deps(ok, null), now);
    expect(report.status).toBe('unknown');
    expect(report.transitionedToBroken).toBe(false);
  });
});

/* ─────────────────────────── configFor: per-profile budget ─────────────────────────── */

describe('configFor — the profile states its own ceiling', () => {
  it('falls back to the conservative defaults', () => {
    const c = configFor(profile('slack'));
    expect(c.dailyBudget).toBe(DEFAULT_DAILY_BUDGET);
    expect(c.minIntervalMs).toBe(DEFAULT_MIN_INTERVAL_MS);
    expect(c.backoffBaseMs).toBe(DEFAULT_BACKOFF_BASE_MS);
  });

  it('honors a profile-declared daily budget and interval', () => {
    const c = configFor(profile('slack', { daily_budget: 2, min_interval_ms: HOUR }));
    expect(c.dailyBudget).toBe(2);
    expect(c.minIntervalMs).toBe(HOUR);
  });

  it('ignores a nonsensical (zero/negative) budget', () => {
    expect(configFor(profile('slack', { daily_budget: 0 })).dailyBudget).toBe(DEFAULT_DAILY_BUDGET);
  });
});

/* ─────────────────────────── HealthMonitor: the loop ─────────────────────────── */

describe('HealthMonitor.tick — enumerate, gate, probe, prune', () => {
  it('probes each enumerated target and exposes broken ones as badges', async () => {
    let clock = 10_000_000;
    const targets: HealthTarget[] = [
      { provider: 'slack', accountId: 'a1' },
      { provider: 'zoom', accountId: 'b1' },
    ];
    const monitor = new HealthMonitor({
      deps: {
        resolveProfile: (name) => Promise.resolve(profile(name)),
        readAccessToken: () => Promise.resolve('tok'),
        // slack is dead, zoom is healthy — branch on the provider NAME only as a test fixture
        // (this is test code, not engine/src, so INV-CONFIG-1's grep does not apply here).
        probe: (p) => (p.name === 'slack' ? dead() : ok()),
      },
      listTargets: () => Promise.resolve(targets),
      now: () => clock,
    });

    const reports = await monitor.tick();
    expect(reports.length).toBe(2);
    expect(monitor.badges()).toEqual([{ provider: 'slack', accountId: 'a1' }]);
    clock += 1;
  });

  it('runs nothing during an active turn', async () => {
    const monitor = new HealthMonitor({
      deps: deps(ok),
      listTargets: () => Promise.resolve([{ provider: 'slack' }]),
      gates: { isActiveTurn: () => true },
      now: () => 1,
    });
    const reports = await monitor.tick();
    expect(reports).toEqual([]);
  });

  it('drops the state of a target that has disconnected', async () => {
    let live: HealthTarget[] = [{ provider: 'slack', accountId: 'a1' }];
    let clock = 20_000_000;
    const monitor = new HealthMonitor({
      deps: deps(ok),
      listTargets: () => Promise.resolve(live),
      now: () => clock,
    });
    await monitor.tick();
    expect(monitor.stateOf({ provider: 'slack', accountId: 'a1' })).toBeDefined();

    live = [];
    clock += DAY;
    await monitor.tick();
    expect(monitor.stateOf({ provider: 'slack', accountId: 'a1' })).toBeUndefined();
  });

  it('does not re-probe a target inside its min interval on a later tick', async () => {
    let clock = 30_000_000;
    let probes = 0;
    const monitor = new HealthMonitor({
      deps: {
        resolveProfile: (name) => Promise.resolve(profile(name)),
        readAccessToken: () => Promise.resolve('tok'),
        probe: () => {
          probes += 1;
          return ok();
        },
      },
      listTargets: () => Promise.resolve([{ provider: 'slack' }]),
      now: () => clock,
    });
    await monitor.tick();
    expect(probes).toBe(1);
    clock += 60_000; // one minute later — well inside the 4h default interval
    await monitor.tick();
    expect(probes).toBe(1); // not probed again
  });

  it('start()/stop() are idempotent and do not keep the process alive', () => {
    const monitor = new HealthMonitor({
      deps: deps(ok),
      listTargets: () => Promise.resolve([]),
      tickMs: 60_000,
    });
    expect(() => {
      monitor.start();
      monitor.start();
      monitor.stop();
      monitor.stop();
    }).not.toThrow();
  });
});
