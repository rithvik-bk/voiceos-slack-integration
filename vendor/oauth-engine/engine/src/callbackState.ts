/**
 * C-2 — the callback `state` gate, WIRED.
 *
 * `state.ts` already mints a single-use, TTL-bound, unguessable `state` and exposes
 * `consumeState()`. The bug this file closes is that `loopback.ts` only ever compared the
 * callback's `state` to the one THIS listener is waiting for (`constantTimeEqual`) and never
 * called `consumeState()` — so the two properties that make `state` more than a per-listener
 * nonce were dead code:
 *
 *   - single-use across the whole process. Two concurrent connects mint into one store; a
 *     state must be redeemable exactly once, by exactly the flow it was minted for, no matter
 *     which listener's socket a callback lands on.
 *   - a TTL. A `state` that is honoured 90 seconds after it was minted is a long-lived bearer
 *     credential, which is precisely what a TTL exists to deny. STATE_TTL_MS lives in
 *     config.ts and is enforced HERE, at redemption, not merely at mint.
 *
 * The order is load-bearing and is the whole reason this is a function rather than an inline
 * `consumeState()` call:
 *
 *   1. Constant-time compare against THIS listener's expected state FIRST. A callback whose
 *      state belongs to a *different* concurrent flow (or is a blind guess) must be treated as
 *      foreign and left untouched — consuming it would destroy the other flow's one-shot state
 *      and hand an attacker a cross-flow denial of service. Foreign states are never consumed.
 *   2. Only once we know the state is ours do we `consumeState()`. That single call enforces
 *      single-use (a replay returns false) and the TTL (an expired state returns false).
 *
 * loopback.ts calls this exactly where it used to do the bare `constantTimeEqual` check.
 */

import { timingSafeEqual } from 'node:crypto';

import { consumeState } from './state.ts';

/**
 * The verdict on one callback's `state`.
 *
 *   - `accept` — the state is ours, live, and unredeemed; consumed now, valid exactly once.
 *   - `foreign` — not this listener's state (another concurrent flow, or a guess). NOT
 *     consumed. The caller shows the mismatch page and KEEPS LISTENING.
 *   - `stale` — this listener's state, but already redeemed (replay) or past its TTL
 *     (expired). The caller shows the mismatch page and KEEPS LISTENING.
 */
export type CallbackStateVerdict = 'accept' | 'foreign' | 'stale';

/** Length-safe constant-time compare. A `state` check must not become a timing oracle. */
function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Decide, and — for the one accepting case — atomically redeem, a callback's `state`.
 *
 * `received` is whatever the browser sent on the callback (never null here: the caller only
 * reaches this once it has a non-null `state` in hand). `expected` is the state THIS listener
 * minted for its flow.
 *
 * A `foreign` verdict never touches the store, so a wrong guess or a sibling flow's state can
 * neither be redeemed here nor invalidated for its rightful owner. Only an exact match is put
 * to `consumeState()`, which returns true at most once and only within the TTL.
 */
export function evaluateCallbackState(received: string, expected: string): CallbackStateVerdict {
  if (!constantTimeEqual(received, expected)) return 'foreign';
  // Ours. Single-use + TTL now decide whether it is still redeemable.
  return consumeState(received) ? 'accept' : 'stale';
}
