/**
 * C-12 — background token-health probe (SPEC §10). Closes INV-REL-3.
 *
 * A token can be dead long before anyone tries to use it: the user revoked access from the
 * provider's dashboard, changed a password, left the workspace, or a rotation anomaly revoked
 * the refresh-token family. Under the plain design nobody learns this until a voice command
 * fails — the worst moment. A low-frequency identity-endpoint probe per connected account turns
 * that failed turn into a quiet reconnect badge minutes or hours earlier.
 *
 * The probe is only worth having if it is disciplined, so the discipline IS the module
 * (INV-REL-3, each bullet a real gate in {@link shouldProbe}):
 *
 *   - BUDGETED. A hard cap on probes per (provider, account) per day, well inside any published
 *     rate limit. The cap is read from the profile (`health_probe.daily_budget`, else a
 *     conservative default) so a provider states its own ceiling.
 *   - BACKOFF ON FAILURE, NOT RETRY STORMS. A provider that is down is probed LESS, not harder:
 *     each consecutive failure pushes the next-eligible time out exponentially, capped.
 *   - NEVER DURING AN ACTIVE TURN. Background work is preemptible and shed first; a health check
 *     that competes with a real command for rate limit or network has inverted its purpose.
 *   - IDLE AND CONNECTIVITY AWARE. No probing on a metered connection, none on battery below a
 *     threshold, none when the machine is not otherwise awake. All four are injected gates so a
 *     host wires them to real OS signals and a test drives them deterministically.
 *   - SILENT BY DEFAULT. A successful probe produces no output at all. ONLY a transition from
 *     healthy to broken calls `onBroken` (the reconnect badge) — never a modal, never an
 *     interruption, and never a peep on the healthy→healthy or broken→broken path.
 *
 * Every probe result also feeds the observability layer (observability.ts), so re-auth rate per
 * provider becomes a measured number rather than an anecdote (§10 last paragraph, §16).
 *
 * INV-CONFIG-1 holds: the loop keys everything by the provider name as DATA (Map keys, event
 * fields) and branches only on capability values and probe outcomes — never on a provider name.
 */

import { EngineError } from './errors.ts';
import * as obs from './observability.ts';
import type { ProviderProfile } from './types.ts';

/* ─────────────────────────────── config & state ─────────────────────────────── */

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;

/** Conservative default when a profile does not state its own `health_probe.daily_budget`. */
export const DEFAULT_DAILY_BUDGET = 6;
/** A healthy target is re-checked no more often than this (also the floor between probes). */
export const DEFAULT_MIN_INTERVAL_MS = 4 * HOUR_MS;
/** First failure backs off this far; each further failure doubles it, capped at the max. */
export const DEFAULT_BACKOFF_BASE_MS = 15 * 60_000;
export const DEFAULT_BACKOFF_MAX_MS = 12 * HOUR_MS;

export interface HealthConfig {
  dailyBudget: number;
  minIntervalMs: number;
  backoffBaseMs: number;
  backoffMaxMs: number;
}

/**
 * Optional per-profile override. Additive to ProviderProfile via structural typing so the engine
 * type need not change: a profile may carry `health_probe: { daily_budget, min_interval_ms }`.
 */
interface HealthProbeProfileHint {
  health_probe?: { daily_budget?: number; min_interval_ms?: number };
}

export function configFor(profile: ProviderProfile): HealthConfig {
  const hint = (profile as ProviderProfile & HealthProbeProfileHint).health_probe;
  const budget = hint?.daily_budget;
  const interval = hint?.min_interval_ms;
  return {
    dailyBudget: typeof budget === 'number' && budget > 0 ? Math.floor(budget) : DEFAULT_DAILY_BUDGET,
    minIntervalMs:
      typeof interval === 'number' && interval > 0 ? interval : DEFAULT_MIN_INTERVAL_MS,
    backoffBaseMs: DEFAULT_BACKOFF_BASE_MS,
    backoffMaxMs: DEFAULT_BACKOFF_MAX_MS,
  };
}

export type HealthStatus = 'healthy' | 'broken' | 'unknown';

/** The mutable per-target bookkeeping the scheduler reads and updates. */
export interface HealthState {
  provider: string;
  accountId?: string;
  status: HealthStatus;
  /** Probes spent in the current UTC-independent 24h window. */
  probesToday: number;
  /** Start of the current budget window (epoch ms). */
  windowStartMs: number;
  lastProbeMs?: number;
  consecutiveFailures: number;
  /** No probe before this time — carries both the min-interval spacing and the failure backoff. */
  nextEligibleMs: number;
}

export function initialState(provider: string, accountId: string | undefined, now: number): HealthState {
  return {
    provider,
    ...(accountId === undefined ? {} : { accountId }),
    status: 'unknown',
    probesToday: 0,
    windowStartMs: now,
    consecutiveFailures: 0,
    nextEligibleMs: now, // eligible immediately on first sight
  };
}

/* ─────────────────────────────── the gates ─────────────────────────────── */

/**
 * The four environmental gates from §10, injected so a host binds them to real OS signals
 * (power management, `navigator.connection`, an idle detector, the foreground-turn flag) and a
 * test drives them deterministically. Defaults are permissive EXCEPT `isActiveTurn`, which
 * defaults to "no turn in progress" — a host that never wires it still gets budget/backoff
 * discipline, and one that does wires the single most important gate first.
 */
export interface HealthGates {
  /** True while a foreground command is running — the probe MUST NOT run then. */
  isActiveTurn(): boolean;
  /** True on a metered/cellular link — no background probing there. */
  isConnectivityMetered(): boolean;
  /** True when power is adequate (plugged in, or battery above the host's threshold). */
  isPowerOk(): boolean;
  /** True when the machine is awake and not idle-suspended. */
  isMachineAwake(): boolean;
}

export const DEFAULT_GATES: HealthGates = {
  isActiveTurn: () => false,
  isConnectivityMetered: () => false,
  isPowerOk: () => true,
  isMachineAwake: () => true,
};

/* ─────────────────────────────── the decision (pure) ─────────────────────────────── */

/** Why a probe was (not) run — surfaced for tests and for a "why is my token stale" answer. */
export type ProbeDecision =
  | 'ok'
  | 'active_turn'
  | 'asleep'
  | 'metered'
  | 'low_power'
  | 'budget_exhausted'
  | 'too_soon';

/**
 * Should this target be probed right now? Pure: no clock, no network, no mutation — every input
 * is an argument, so the whole discipline of §10 is one testable function. Order matters: the
 * cheap environmental refusals come before the budget check so a shed probe never spends budget.
 */
export function shouldProbe(
  state: HealthState,
  config: HealthConfig,
  now: number,
  gates: HealthGates,
): ProbeDecision {
  if (gates.isActiveTurn()) return 'active_turn';
  if (!gates.isMachineAwake()) return 'asleep';
  if (gates.isConnectivityMetered()) return 'metered';
  if (!gates.isPowerOk()) return 'low_power';

  // Roll the daily window forward before checking the cap, so a probe at hour 25 is not blocked
  // by yesterday's spend.
  const probesToday = now - state.windowStartMs >= DAY_MS ? 0 : state.probesToday;
  if (probesToday >= config.dailyBudget) return 'budget_exhausted';

  if (now < state.nextEligibleMs) return 'too_soon';
  return 'ok';
}

/* ─────────────────────────────── the probe (effectful) ─────────────────────────────── */

/** Injected side-effecting dependencies, so the loop is testable without a keychain or a network. */
export interface HealthDeps {
  /** Resolve a profile from a provider name (index.ts wires resolveProviderProfile). */
  resolveProfile(provider: string): Promise<ProviderProfile>;
  /** Read the vaulted access token for (provider, account), or null when nothing is stored. */
  readAccessToken(provider: string, accountId?: string): Promise<string | null>;
  /** The identity probe — the same call connect uses to prove a credential still resolves. */
  probe(profile: ProviderProfile, accessToken: string): Promise<void>;
}

/** What a single probe pass did, for the caller/test — never surfaced to the user on success. */
export interface ProbeReport {
  provider: string;
  accountId?: string;
  decision: ProbeDecision;
  /** The status AFTER this pass. */
  status: HealthStatus;
  /** True only on a healthy→broken transition — the one case that surfaces a badge. */
  transitionedToBroken: boolean;
}

/**
 * Run one probe pass for a target, mutating `state` in place and returning what happened.
 *
 * On success: status → healthy, failures reset, next probe spaced by `minIntervalMs`, and NOTHING
 * is surfaced (a healthy→healthy or broken→healthy recovery is silent by design). On an
 * auth/dead-grant failure: status → broken, backoff applied, and `onBroken` fires ONLY if this is
 * the healthy→broken (or unknown→broken) transition. On a transient failure (network, 5xx): the
 * status is left as-is and only a short backoff is applied — a provider being down is not a dead
 * token.
 *
 * Every outcome is recorded to observability credential-free, so re-auth rate becomes measured.
 */
export async function runProbe(
  state: HealthState,
  config: HealthConfig,
  deps: HealthDeps,
  now: number,
  onBroken?: (target: { provider: string; accountId?: string }) => void,
): Promise<ProbeReport> {
  // Budget-window bookkeeping (mirror of shouldProbe's roll-forward), then spend one.
  if (now - state.windowStartMs >= DAY_MS) {
    state.windowStartMs = now;
    state.probesToday = 0;
  }
  state.probesToday += 1;
  state.lastProbeMs = now;

  const target = {
    provider: state.provider,
    ...(state.accountId === undefined ? {} : { accountId: state.accountId }),
  };

  const token = await deps.readAccessToken(state.provider, state.accountId);
  if (token === null) {
    // Nothing vaulted: not a health problem, just nothing to probe. Space it and stay silent.
    state.nextEligibleMs = now + config.minIntervalMs;
    return { ...target, decision: 'ok', status: state.status, transitionedToBroken: false };
  }

  let profile: ProviderProfile;
  try {
    profile = await deps.resolveProfile(state.provider);
  } catch {
    // A config we cannot resolve is not a dead token; back off briefly and try later.
    applyBackoff(state, config, now);
    return { ...target, decision: 'ok', status: state.status, transitionedToBroken: false };
  }

  try {
    await deps.probe(profile, token);
    // Success: silent. Reset failure state and space the next check.
    state.status = 'healthy';
    state.consecutiveFailures = 0;
    state.nextEligibleMs = now + config.minIntervalMs;
    obs.record({
      type: 'health_result',
      provider: state.provider,
      outcome: 'healthy',
      ...(state.accountId === undefined ? {} : { account_id: state.accountId }),
    });
    return { ...target, decision: 'ok', status: 'healthy', transitionedToBroken: false };
  } catch (error) {
    const dead = isDeadCredential(error);
    applyBackoff(state, config, now);

    if (!dead) {
      // Transient (network / 5xx / timeout): the provider is unavailable, the token is NOT proven
      // dead. Leave status untouched, stay silent, and let backoff avoid a retry storm.
      obs.record({
        type: 'health_result',
        provider: state.provider,
        outcome: state.status === 'broken' ? 'broken' : 'healthy',
        error_code: errorCodeOf(error),
        ...(state.accountId === undefined ? {} : { account_id: state.accountId }),
      });
      return { ...target, decision: 'ok', status: state.status, transitionedToBroken: false };
    }

    const wasHealthy = state.status !== 'broken';
    state.status = 'broken';
    obs.record({
      type: 'health_result',
      provider: state.provider,
      outcome: 'broken',
      error_code: errorCodeOf(error),
      ...(state.accountId === undefined ? {} : { account_id: state.accountId }),
    });
    if (wasHealthy) {
      // The one case that surfaces anything: the reconnect badge, once, on transition.
      obs.recordTokenServed(state.provider, 'reauth_required', {
        errorCode: errorCodeOf(error),
        ...(state.accountId === undefined ? {} : { accountId: state.accountId }),
      });
      try {
        onBroken?.(target);
      } catch {
        // A badge callback that throws must not break the probe loop.
      }
    }
    return { ...target, decision: 'ok', status: 'broken', transitionedToBroken: wasHealthy };
  }
}

function applyBackoff(state: HealthState, config: HealthConfig, now: number): void {
  state.consecutiveFailures += 1;
  const grown = config.backoffBaseMs * 2 ** (state.consecutiveFailures - 1);
  const delay = Math.min(config.backoffMaxMs, grown);
  state.nextEligibleMs = now + delay;
}

/** A dead credential (revoked / expired / left workspace) vs a transient provider outage. */
function isDeadCredential(error: unknown): boolean {
  return error instanceof EngineError && error.code === 'expired_or_revoked';
}

function errorCodeOf(error: unknown): string {
  return error instanceof EngineError ? error.code : 'provider_error';
}

/* ─────────────────────────────── the monitor ─────────────────────────────── */

/** A connected target to watch — supplied by the host's enumeration (registry + account index). */
export interface HealthTarget {
  provider: string;
  accountId?: string;
}

export interface HealthMonitorOptions {
  deps: HealthDeps;
  /** Enumerate what is connected right now. Called each tick so new connects join the watch. */
  listTargets(): Promise<HealthTarget[]>;
  gates?: Partial<HealthGates>;
  /** Fires on a healthy→broken transition. The host turns this into a quiet reconnect badge. */
  onBroken?: (target: HealthTarget) => void;
  /** Overridable clock for tests. */
  now?: () => number;
  /** How often the loop wakes to consider probing (NOT how often it probes — budget/interval gate that). */
  tickMs?: number;
  /** Per-target config resolver; defaults to reading the profile hint via {@link configFor}. */
  config?: (profile: ProviderProfile) => HealthConfig;
}

/** How often the loop considers work. The actual probe cadence is governed by interval + budget. */
export const DEFAULT_TICK_MS = 5 * 60_000;

function targetKey(t: HealthTarget): string {
  return t.accountId === undefined ? t.provider : `${t.provider} ${t.accountId}`;
}

/**
 * The background loop. It never probes on its own schedule — every tick it re-enumerates targets
 * and asks {@link shouldProbe} per target, running a probe only when every §10 gate says yes. A
 * healthy install is therefore near-silent: a handful of identity calls a day, none during a turn,
 * none on battery or a metered link, and no output unless a token actually died.
 *
 * Created and owned by the host (via index.ts's re-export); `tick()` is exposed so a test drives
 * the whole discipline with a fake clock and no timers.
 */
export class HealthMonitor {
  private readonly deps: HealthDeps;
  private readonly listTargets: () => Promise<HealthTarget[]>;
  private readonly gates: HealthGates;
  private readonly onBroken?: (target: HealthTarget) => void;
  private readonly now: () => number;
  private readonly tickMs: number;
  private readonly configOf: (profile: ProviderProfile) => HealthConfig;
  private readonly states = new Map<string, HealthState>();
  private timer: ReturnType<typeof setInterval> | undefined = undefined;
  private running = false;

  constructor(options: HealthMonitorOptions) {
    this.deps = options.deps;
    this.listTargets = options.listTargets;
    this.gates = { ...DEFAULT_GATES, ...(options.gates ?? {}) };
    if (options.onBroken !== undefined) this.onBroken = options.onBroken;
    this.now = options.now ?? Date.now;
    this.tickMs = options.tickMs ?? DEFAULT_TICK_MS;
    this.configOf = options.config ?? configFor;
  }

  /** Start the background loop. `unref()` so a probe timer never keeps the process alive. */
  start(): void {
    if (this.timer !== undefined) return;
    this.timer = setInterval(() => {
      void this.tick();
    }, this.tickMs);
    this.timer.unref?.();
  }

  /** Stop the loop. Idempotent. */
  stop(): void {
    if (this.timer !== undefined) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  /** The current health of every watched target — the source of the reconnect badges. */
  badges(): HealthTarget[] {
    const broken: HealthTarget[] = [];
    for (const state of this.states.values()) {
      if (state.status === 'broken') {
        broken.push({
          provider: state.provider,
          ...(state.accountId === undefined ? {} : { accountId: state.accountId }),
        });
      }
    }
    return broken;
  }

  /** Read-only snapshot of a target's state, for tests and diagnostics. */
  stateOf(target: HealthTarget): HealthState | undefined {
    return this.states.get(targetKey(target));
  }

  /**
   * One pass of the loop: re-enumerate targets, then probe each one that {@link shouldProbe}
   * clears. Re-entrancy guarded so a slow probe never overlaps the next tick. Returns the reports
   * for the probes that actually ran (empty when every target was gated out) — handy for a test.
   */
  async tick(): Promise<ProbeReport[]> {
    if (this.running) return [];
    this.running = true;
    const reports: ProbeReport[] = [];
    try {
      const now = this.now();
      const targets = await this.listTargets().catch(() => [] as HealthTarget[]);
      const live = new Set(targets.map(targetKey));

      // Drop states for targets no longer connected (disconnected since the last tick).
      for (const key of [...this.states.keys()]) {
        if (!live.has(key)) this.states.delete(key);
      }

      for (const target of targets) {
        const key = targetKey(target);
        let state = this.states.get(key);
        if (state === undefined) {
          state = initialState(target.provider, target.accountId, now);
          this.states.set(key, state);
        }

        let config: HealthConfig;
        try {
          config = this.configOf(await this.deps.resolveProfile(target.provider));
        } catch {
          config = {
            dailyBudget: DEFAULT_DAILY_BUDGET,
            minIntervalMs: DEFAULT_MIN_INTERVAL_MS,
            backoffBaseMs: DEFAULT_BACKOFF_BASE_MS,
            backoffMaxMs: DEFAULT_BACKOFF_MAX_MS,
          };
        }

        if (shouldProbe(state, config, now, this.gates) !== 'ok') continue;
        reports.push(await runProbe(state, config, this.deps, now, this.onBroken));
      }
    } finally {
      this.running = false;
    }
    return reports;
  }
}

/** Convenience constructor mirroring the engine's other `create*` factories. */
export function createHealthMonitor(options: HealthMonitorOptions): HealthMonitor {
  return new HealthMonitor(options);
}
