/**
 * `state` — the single-use CSRF token bound to one authorize request (work item P1-I2).
 *
 * Three properties, each of which is a real attack if dropped:
 *   1. unguessable   — 32 crypto-random bytes, same floor as the PKCE verifier
 *   2. single-use    — consuming deletes; a replayed callback (browser back button,
 *                      a copied callback URL) is rejected, not honoured a second time
 *   3. short-lived   — STATE_TTL_MS from config.ts (sized to outlive one connect window so a
 *                      within-timeout callback is never rejected as stale), because a state that
 *                      outlives the tab it was minted for is just a long-lived bearer credential
 *
 * The store is deliberately in-memory and process-local: a state is meaningful only to
 * the loopback listener that is currently waiting, and persisting it to disk would put
 * one more secret-shaped thing on disk for exactly zero benefit.
 */

import { randomBytes, timingSafeEqual } from 'node:crypto';

import { STATE_TTL_MS } from './config.ts';

const STATE_BYTES = 32;

/** state value → absolute expiry (epoch ms). */
const live = new Map<string, number>();

/**
 * Constant-time equality over two strings of the same length.
 *
 * Length is compared first and in variable time on purpose: every state we mint is the
 * same 43 characters, so a length mismatch reveals only that the caller sent something
 * that is not one of ours, which the reject already reveals.
 */
function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/** Drop everything already expired. Cheap, and it keeps a long-lived process bounded. */
function sweep(now: number): void {
  for (const [value, expiresAt] of live) {
    if (expiresAt <= now) live.delete(value);
  }
}

/** Mint a state for exactly one authorize request. */
export function mintState(): string {
  const now = Date.now();
  sweep(now);
  const value = randomBytes(STATE_BYTES).toString('base64url');
  live.set(value, now + STATE_TTL_MS);
  return value;
}

/**
 * Redeem `value`. True exactly once, for a state that is live and matches; false for a
 * replay, an expired state, a forged state, or anything at all we did not mint.
 *
 * The scan does not break on the first match: returning early would make the response
 * time a function of where the match sat in the map, which is the timing leak
 * `timingSafeEqual` exists to avoid. The map holds at most a handful of in-flight
 * connects, so the full walk is free.
 */
export function consumeState(value: string): boolean {
  const now = Date.now();
  let matched: string | null = null;

  for (const [candidate, expiresAt] of live) {
    if (expiresAt <= now) {
      live.delete(candidate);
      continue;
    }
    if (constantTimeEquals(candidate, value)) matched = candidate;
  }

  if (matched === null) return false;
  live.delete(matched);
  return true;
}

/** Number of states still redeemable right now. Diagnostics and tests only. */
export function pendingStates(): number {
  sweep(Date.now());
  return live.size;
}

/** Forget every in-flight state (process shutdown, test isolation). */
export function clearStates(): void {
  live.clear();
}
