/**
 * C-10 — rotating-refresh reuse detection.
 *
 * Under rotation (`refresh: rotating`) a refresh token is single-use: the provider retires it
 * the instant it is redeemed and hands back a new one. Sending a retired token a second time is
 * not a benign retry — it is the canonical sign of a stolen token, and a conformant AS responds
 * by revoking the ENTIRE token family (RFC 6819 §5.2.2.3, the OAuth 2.0 Security BCP). After
 * that, every access and refresh token for that grant is dead and the only repair is a human
 * re-authorizing. refresh.ts already persists a rotated pair before it is used and serializes
 * refreshes with a cross-process lock, which shrinks the window; this file closes what remains:
 *
 *   1. Never retry a refresh with a token we have already spent. refresh.ts's on-401 path can,
 *      after a crash that lost the persist, re-read a vault that still holds the OLD token and
 *      try it again — the exact move that trips family revocation. A process-local record of
 *      every token we have handed to the provider lets us refuse that retry BEFORE it leaves the
 *      machine, turning a family-killing network call into a clean, local re-auth prompt.
 *   2. Turn a family revocation into a clean re-auth, not a cryptic failure. When the provider
 *      answers a refresh with a dead-grant error, that is surfaced as `expired_or_revoked` with
 *      a "reconnect" hint the product surface already knows how to speak.
 *
 * Secret hygiene (Dr. M's rule, non-negotiable): a refresh token is never stored, compared, or
 * logged in the clear. The consumed-set holds only SHA-256 digests, so neither a memory image
 * nor any accidental serialization of this module reveals a token. The raw token is touched
 * only to hash it and is never retained.
 */

import { createHash } from 'node:crypto';

import { EngineError } from './errors.ts';
import type { ProviderProfile } from './types.ts';

/** Digests of refresh tokens this process has already handed to a provider. */
const consumed = new Set<string>();

/** Hash a token to its storage key. The raw value never enters the set, a log, or an error. */
function digest(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/**
 * Refuse a refresh that would reuse a token we have already spent.
 *
 * Call this immediately before a refresh attempt. A hit means a rotated token is about to be
 * sent twice — the family-revocation trigger — so we stop it here and ask for a clean re-auth
 * instead of letting the provider kill the whole grant.
 *
 * @throws EngineError `expired_or_revoked` when `refreshToken` has already been consumed.
 */
export function assertRefreshUnconsumed(refreshToken: string, profile: ProviderProfile): void {
  if (!consumed.has(digest(refreshToken))) return;
  throw new EngineError(
    'expired_or_revoked',
    `${profile.name}: refresh token already used — refusing to replay it`,
    {
      hint: `A rotating refresh token for ${profile.display_name} was already spent; replaying it would revoke the whole token family. Say "connect ${profile.display_name}" to re-authorize.`,
    },
  );
}

/**
 * Record that a refresh token has been spent and must never be sent again.
 *
 * Call this only when the token is PROVEN consumed: after a successful rotation (the provider
 * handed back a different refresh token), and on a family-revocation response (a dead-grant
 * error — the provider processed the token and retired the grant). Do NOT mark on a transient
 * or transport failure (a 5xx, "could not reach the token endpoint"): the token is not proven
 * spent, so the caller's backoff retry must remain free to try it again.
 */
export function markRefreshConsumed(refreshToken: string): void {
  consumed.add(digest(refreshToken));
}

/**
 * Is this refresh failure a family revocation — the provider declaring the grant dead?
 *
 * exchange.ts already collapses every dead-grant signal (`invalid_grant`,
 * `invalid_refresh_token`, `token_revoked`, a 401/403, …) into the `expired_or_revoked` code,
 * which for a REFRESH grant means exactly one thing: this grant is gone and only a human can
 * bring it back.
 */
export function isFamilyRevocation(error: unknown): boolean {
  return error instanceof EngineError && error.code === 'expired_or_revoked';
}

/**
 * Build the clean re-auth error the product surface renders for a revoked family.
 *
 * Keeps the provider's own words when there are any (they are already redaction-checked by
 * exchange.ts before they reach an EngineError), and adds the one instruction that actually
 * repairs the situation. No token bytes are ever interpolated.
 */
export function familyRevocationReauth(profile: ProviderProfile, cause?: unknown): EngineError {
  const providerMessage = cause instanceof EngineError ? cause.providerMessage : undefined;
  return new EngineError(
    'expired_or_revoked',
    `${profile.name}: refresh token family revoked — reconnect required`,
    {
      hint: `${profile.display_name} rejected the refresh and revoked the token family (a reused or stolen rotating token does this). Say "connect ${profile.display_name}" to re-authorize.`,
      ...(cause === undefined ? {} : { cause }),
      ...(providerMessage === undefined ? {} : { providerMessage }),
    },
  );
}

/** Number of consumed-token digests held. Diagnostics and tests only. */
export function consumedCount(): number {
  return consumed.size;
}

/** Forget every consumed-token digest (process shutdown, test isolation). */
export function clearConsumed(): void {
  consumed.clear();
}
