/**
 * C-23 — observability: the credential-free auth-event log and the metrics computed from it
 * (SPEC §16, §29). Closes INV-OBS-1.
 *
 * SPEC §16 asks for "an auth event log containing NO credential material: connect attempts and
 * outcomes by provider, time to connect, refresh successes and failures, re-auth rate,
 * revocations. From it: connect success rate per provider, p50 and p95 time-to-token, silent
 * refresh rate, and the ranked list of providers whose configs need attention."
 *
 * The whole file is built around one non-negotiable property (INV-OBS-1): **an event can never
 * carry a credential.** Two structural defences, not one:
 *
 *   1. THE TYPE HAS NOWHERE TO PUT A SECRET. An {@link AuthEvent} is a closed shape of a
 *      provider name, an account id (already the opaque hash from account.ts, never a handle or
 *      token), an outcome enum, a normalized error code, and integer millisecond durations.
 *      There is no free-form `message`, no `body`, no `token` field — so the common leak (a
 *      provider error body stringified whole, a token logged "for debugging") has no field to
 *      ride in.
 *   2. EVERY STRING STILL PASSES THE REDACTION BOUNDARY. Belt and braces: provider names and
 *      error codes are run through {@link redact} at record time, so even a mis-wired caller
 *      that somehow put a credential-shaped run into one of those fields is scrubbed before the
 *      event is stored. The `guard-no-secret-in-build` invariant already scans the log path;
 *      this keeps that path honest.
 *
 * Metrics do NOT read the ring buffer (which rotates and would make a long-lived process forget
 * its own history). Percentiles come from a bounded reservoir of durations and rates come from
 * monotonic counters, so the numbers are stable regardless of how many events have scrolled off
 * the audit log. INV-CONFIG-1 holds: `provider` is a Map key (data), never a branch.
 */

import { redact } from './redact.ts';

/* ─────────────────────────────── event shapes ─────────────────────────────── */

/**
 * What happened. A closed set so a dashboard branches on a known vocabulary, never on a
 * free-form string. `connect_*` cover the consent flow, `token_*` cover every getToken()
 * serve, `health_*` come from the background probe (health.ts), `revocation` from disconnect.
 */
export type AuthEventType =
  | 'connect_attempt'
  | 'connect_result'
  | 'token_served'
  | 'refresh_result'
  | 'health_result'
  | 'revocation';

/**
 * The outcome of an event. `connected`/`already_connected` are the two connect successes (a
 * fresh mint vs a cache hit — only the fresh mint contributes a time-to-token). `denied`,
 * `timeout`, `error` are connect failures. `fresh`/`refreshed` are silent token serves,
 * `reauth_required` is a serve that needs a human. `healthy`/`broken` come from the probe.
 */
export type AuthOutcome =
  | 'connected'
  | 'already_connected'
  | 'denied'
  | 'timeout'
  | 'error'
  | 'fresh'
  | 'refreshed'
  | 'reauth_required'
  | 'healthy'
  | 'broken'
  | 'revoked'
  | 'forgotten';

/**
 * One entry in the auth-event log. Structurally incapable of holding a credential: every field
 * is a provider name, the opaque account hash, an enum, a normalized error code, or an integer.
 */
export interface AuthEvent {
  /** Epoch ms when the event was recorded. */
  ts: number;
  type: AuthEventType;
  /** The profile `name` (data, never branched on). */
  provider: string;
  /** The opaque, hashed account id from account.ts — never a handle, email, or token. */
  account_id?: string;
  outcome: AuthOutcome;
  /** Normalized taxonomy/engine error code (e.g. `expired_or_revoked`). Never a raw provider body. */
  error_code?: string;
  /** Milliseconds the operation took (time-to-token for a connect_result:connected). */
  duration_ms?: number;
}

/** The fields a caller supplies; `ts` is stamped here so a caller cannot forge a timestamp. */
export type AuthEventInput = Omit<AuthEvent, 'ts'>;

/* ─────────────────────────────── the store ─────────────────────────────── */

/** Recent events, bounded — a long-lived MCP process must not grow an unbounded log in memory. */
const MAX_EVENTS = 500;
/** Per-provider time-to-token samples kept for percentiles — a bounded reservoir (most recent). */
const MAX_SAMPLES = 256;

interface ConnectCounters {
  attempts: number;
  /** Fresh mints + cache hits — every connect that ended usable. */
  success: number;
  /** denied + timeout + error. */
  failure: number;
}

interface RefreshCounters {
  /** Served without user interaction: a still-fresh token or a successful silent refresh. */
  silent: number;
  /** A serve that could not complete without a human re-authorizing. */
  reauth: number;
}

interface ProviderAggregate {
  connect: ConnectCounters;
  refresh: RefreshCounters;
  revocations: number;
  /** Time-to-token samples (ms), most recent MAX_SAMPLES, for p50/p95. */
  timeToToken: number[];
  /** Last health outcome seen, for the "configs needing attention" ranking. */
  healthBroken: number;
}

const events: AuthEvent[] = [];
const aggregates = new Map<string, ProviderAggregate>();

/** Attempt-start timestamps keyed by connect_id, so an out-of-band success measures true latency. */
const attemptStart = new Map<string, number>();
/** Bound the attempt map the same way the status board is bounded (index.ts MAX_TRACKED). */
const MAX_ATTEMPTS = 100;

/** Anyone who wants events as they happen (a live dashboard, a file sink). */
type Sink = (event: AuthEvent) => void;
const sinks = new Set<Sink>();

function aggregateFor(provider: string): ProviderAggregate {
  let agg = aggregates.get(provider);
  if (agg === undefined) {
    agg = {
      connect: { attempts: 0, success: 0, failure: 0 },
      refresh: { silent: 0, reauth: 0 },
      revocations: 0,
      timeToToken: [],
      healthBroken: 0,
    };
    aggregates.set(provider, agg);
  }
  return agg;
}

/**
 * Record an auth event. The timestamp is stamped here, every string field is scrubbed through
 * the redaction boundary, and the running aggregates are updated. The event is appended to the
 * bounded log and pushed to every subscribed sink.
 *
 * This is the single write path — connect (index.ts), refresh (refresh.ts), and the health
 * probe (health.ts) all funnel through it, which is what makes "no credential in the log" a
 * property of one place rather than a hope spread across three.
 */
export function record(input: AuthEventInput): AuthEvent {
  const event: AuthEvent = {
    ts: Date.now(),
    type: input.type,
    // INV-OBS-1 belt-and-braces: even these already-safe fields pass the scrubber.
    provider: redact(input.provider),
    outcome: input.outcome,
    ...(input.account_id === undefined ? {} : { account_id: redact(input.account_id) }),
    ...(input.error_code === undefined ? {} : { error_code: redact(input.error_code) }),
    ...(input.duration_ms === undefined ? {} : { duration_ms: Math.max(0, Math.round(input.duration_ms)) }),
  };

  const agg = aggregateFor(event.provider);
  applyToAggregate(agg, event);

  events.push(event);
  while (events.length > MAX_EVENTS) events.shift();

  for (const sink of sinks) {
    try {
      sink(event);
    } catch {
      // A broken sink must never take down the auth path it is only observing.
    }
  }
  return event;
}

function applyToAggregate(agg: ProviderAggregate, event: AuthEvent): void {
  switch (event.type) {
    case 'connect_attempt':
      agg.connect.attempts += 1;
      break;
    case 'connect_result':
      if (event.outcome === 'connected' || event.outcome === 'already_connected') {
        agg.connect.success += 1;
        if (event.outcome === 'connected' && event.duration_ms !== undefined) {
          agg.timeToToken.push(event.duration_ms);
          while (agg.timeToToken.length > MAX_SAMPLES) agg.timeToToken.shift();
        }
      } else {
        agg.connect.failure += 1;
      }
      break;
    case 'refresh_result':
    case 'token_served':
      if (event.outcome === 'reauth_required') agg.refresh.reauth += 1;
      else agg.refresh.silent += 1;
      break;
    case 'health_result':
      if (event.outcome === 'broken') agg.healthBroken += 1;
      break;
    case 'revocation':
      agg.revocations += 1;
      break;
  }
}

/* ─────────────────────────── convenience recorders ─────────────────────────── */

/**
 * Mark the start of a real consent flow (not a cache hit) so its terminal outcome can be
 * measured as a true time-to-token. Stores the start keyed by `connect_id`.
 */
export function recordConnectAttempt(connectId: string, provider: string, accountId?: string): void {
  attemptStart.set(connectId, Date.now());
  while (attemptStart.size > MAX_ATTEMPTS) {
    const oldest = attemptStart.keys().next().value;
    if (oldest === undefined) break;
    attemptStart.delete(oldest);
  }
  record({
    type: 'connect_attempt',
    provider,
    outcome: 'fresh',
    ...(accountId === undefined ? {} : { account_id: accountId }),
  });
}

/**
 * Record a connect's terminal outcome. When it is a fresh `connected` and an attempt start was
 * recorded for this `connect_id`, the elapsed time is attached as the time-to-token sample.
 */
export function recordConnectResult(
  connectId: string,
  provider: string,
  outcome: Extract<AuthOutcome, 'connected' | 'already_connected' | 'denied' | 'timeout' | 'error'>,
  extra: { accountId?: string; errorCode?: string } = {},
): void {
  const started = attemptStart.get(connectId);
  attemptStart.delete(connectId);
  const durationMs = outcome === 'connected' && started !== undefined ? Date.now() - started : undefined;
  record({
    type: 'connect_result',
    provider,
    outcome,
    ...(extra.accountId === undefined ? {} : { account_id: extra.accountId }),
    ...(extra.errorCode === undefined ? {} : { error_code: extra.errorCode }),
    ...(durationMs === undefined ? {} : { duration_ms: durationMs }),
  });
}

/**
 * Record how a getToken() serve completed. `fresh` = a still-valid vaulted token, `refreshed` =
 * a successful silent rotation, `reauth_required` = the grant is dead and a human must act. The
 * first two are silent (no user interaction); the last is the "bug with a user attached" §29
 * counts against the silent-refresh rate.
 */
export function recordTokenServed(
  provider: string,
  outcome: Extract<AuthOutcome, 'fresh' | 'refreshed' | 'reauth_required'>,
  extra: { accountId?: string; errorCode?: string } = {},
): void {
  record({
    type: outcome === 'fresh' ? 'token_served' : 'refresh_result',
    provider,
    outcome,
    ...(extra.accountId === undefined ? {} : { account_id: extra.accountId }),
    ...(extra.errorCode === undefined ? {} : { error_code: extra.errorCode }),
  });
}

/* ─────────────────────────────── metrics ─────────────────────────────── */

/** Nearest-rank percentile over a copy of the samples. `undefined` when there is no data. */
export function percentile(samples: readonly number[], p: number): number | undefined {
  if (samples.length === 0) return undefined;
  const sorted = [...samples].sort((a, b) => a - b);
  const rank = Math.ceil((p / 100) * sorted.length);
  const index = Math.min(sorted.length - 1, Math.max(0, rank - 1));
  return sorted[index];
}

export interface ProviderMetrics {
  provider: string;
  connectAttempts: number;
  connectSuccess: number;
  connectFailure: number;
  /** success / (success + failure); `undefined` with no terminal connects yet. */
  connectSuccessRate?: number;
  /** p50 time-to-token in ms; `undefined` with no fresh mints yet. */
  timeToTokenP50Ms?: number;
  /** p95 time-to-token in ms. */
  timeToTokenP95Ms?: number;
  /** silent / (silent + reauth); target 1.0 (§29). `undefined` with no serves yet. */
  silentRefreshRate?: number;
  reauthCount: number;
  revocations: number;
  healthBroken: number;
}

export interface Metrics {
  providers: ProviderMetrics[];
  /** Providers ranked worst-first by config health (§16 "configs that need attention"). */
  needsAttention: string[];
}

function ratio(numerator: number, denominator: number): number | undefined {
  return denominator === 0 ? undefined : numerator / denominator;
}

function providerMetrics(provider: string, agg: ProviderAggregate): ProviderMetrics {
  const terminals = agg.connect.success + agg.connect.failure;
  const serves = agg.refresh.silent + agg.refresh.reauth;
  const connectSuccessRate = ratio(agg.connect.success, terminals);
  const silentRefreshRate = ratio(agg.refresh.silent, serves);
  const p50 = percentile(agg.timeToToken, 50);
  const p95 = percentile(agg.timeToToken, 95);
  return {
    provider,
    connectAttempts: agg.connect.attempts,
    connectSuccess: agg.connect.success,
    connectFailure: agg.connect.failure,
    ...(connectSuccessRate === undefined ? {} : { connectSuccessRate }),
    ...(p50 === undefined ? {} : { timeToTokenP50Ms: p50 }),
    ...(p95 === undefined ? {} : { timeToTokenP95Ms: p95 }),
    ...(silentRefreshRate === undefined ? {} : { silentRefreshRate }),
    reauthCount: agg.refresh.reauth,
    revocations: agg.revocations,
    healthBroken: agg.healthBroken,
  };
}

/**
 * The full metrics snapshot: per-provider connect success rate, time-to-token p50/p95, and
 * silent-refresh rate, plus the ranked "needs attention" list (most connect failures + reauths
 * + broken-health signals first). Computed from counters and the reservoir, never the log ring.
 */
export function metrics(): Metrics {
  const providers: ProviderMetrics[] = [];
  for (const [provider, agg] of aggregates) providers.push(providerMetrics(provider, agg));
  providers.sort((a, b) => a.provider.localeCompare(b.provider));

  const needsAttention = [...providers]
    .map((p) => ({
      provider: p.provider,
      badness: p.connectFailure + p.reauthCount + p.healthBroken,
    }))
    .filter((p) => p.badness > 0)
    .sort((a, b) => b.badness - a.badness)
    .map((p) => p.provider);

  return { providers, needsAttention };
}

/** Provider-scoped metrics, or `undefined` if the engine has recorded nothing for it. */
export function metricsFor(provider: string): ProviderMetrics | undefined {
  const agg = aggregates.get(provider);
  return agg === undefined ? undefined : providerMetrics(provider, agg);
}

/* ─────────────────────────────── the log & sinks ─────────────────────────────── */

/** The recent auth-event log (a copy, newest last). Credential-free by construction (INV-OBS-1). */
export function log(): AuthEvent[] {
  return [...events];
}

/** Subscribe to events as they are recorded. Returns an unsubscribe function. */
export function subscribe(sink: Sink): () => void {
  sinks.add(sink);
  return () => {
    sinks.delete(sink);
  };
}

/** Test seam: wipe the log, aggregates, in-flight attempts, and sinks. Never called in production. */
export function reset(): void {
  events.length = 0;
  aggregates.clear();
  attemptStart.clear();
  sinks.clear();
}
