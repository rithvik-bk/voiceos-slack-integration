/**
 * C-14 — the closed error taxonomy (SPEC §15).
 *
 * "Every provider invents its own error vocabulary. Integration authors should never see it."
 * The engine normalizes every failure — an `EngineError` code, an HTTP status, a provider's
 * verbatim OAuth error token — down to ONE of nine codes. Tool code branches on nine cases
 * forever, regardless of how many providers exist.
 *
 * Each normalized error carries two things beyond the code:
 *   - `rawProviderError` — the provider's own words, verbatim, for debugging. Never our
 *     paraphrase, and (per the redaction rule) never a stringified body: the caller passes
 *     an already-extracted, already-redacted field, and this module only forwards it.
 *   - `action` — a recommended, user-facing next step. Safe to display and to log.
 *
 * This is a leaf module: it imports only the `EngineErrorCode` *type*, so it can be consumed
 * anywhere in the engine without an import cycle. It classifies; it never throws.
 */

import type { EngineErrorCode } from './types.ts';

/** The nine, and only nine, normalized failure codes (SPEC §15). Closed set. */
export type TaxonomyCode =
  | 'NOT_CONNECTED'
  | 'CONSENT_DENIED'
  | 'SCOPE_INSUFFICIENT'
  | 'TOKEN_EXPIRED'
  | 'REFRESH_FAILED'
  | 'REVOKED'
  | 'RATE_LIMITED'
  | 'PROVIDER_UNAVAILABLE'
  | 'CONFIG_INVALID';

/** Frozen enumeration — the single source of "how many cases are there?" for tests and UIs. */
export const TAXONOMY_CODES: readonly TaxonomyCode[] = [
  'NOT_CONNECTED',
  'CONSENT_DENIED',
  'SCOPE_INSUFFICIENT',
  'TOKEN_EXPIRED',
  'REFRESH_FAILED',
  'REVOKED',
  'RATE_LIMITED',
  'PROVIDER_UNAVAILABLE',
  'CONFIG_INVALID',
] as const;

/** A failure, normalized. The shape every integration author branches on. */
export interface NormalizedError {
  code: TaxonomyCode;
  /** Recommended, user-facing next step. Always present; safe to display and log. */
  action: string;
  /** The provider's own error text, verbatim, when there is one. Never our paraphrase. */
  rawProviderError?: string;
}

/** Everything we might know about a failure. Every field optional — normalize copes with any subset. */
export interface NormalizeInput {
  /** The engine's own failure code, when the failure originated inside the engine. */
  engineCode?: EngineErrorCode;
  /** HTTP status the provider returned, when there was an HTTP round-trip. */
  status?: number;
  /** The provider's verbatim error text or extracted `error` field. Forwarded, never parsed for control flow beyond token matching. */
  providerError?: string;
  /**
   * Set true when reuse-detection / family-revocation was observed (C-10): a rotated refresh
   * token was replayed and the provider killed the family. This is REVOKED, not REFRESH_FAILED,
   * and it outranks every other signal.
   */
  revoked?: boolean;
}

/* ─────────────────────────── recommended actions (one per code) ─────────────────────────── */

const ACTIONS: Record<TaxonomyCode, string> = {
  NOT_CONNECTED: 'Connect this provider to continue.',
  CONSENT_DENIED: 'Approval was declined. Say "connect" again to retry when you are ready.',
  SCOPE_INSUFFICIENT: 'This action needs a permission that was not granted. Reconnect to approve it.',
  TOKEN_EXPIRED: 'The session expired. It refreshes automatically — retry the action.',
  REFRESH_FAILED: 'Could not refresh the session. Reconnect this provider.',
  REVOKED: 'Access was revoked. Reconnect this provider to restore it.',
  RATE_LIMITED: 'The provider is rate-limiting requests. Wait a moment and retry.',
  PROVIDER_UNAVAILABLE: 'The provider is temporarily unavailable. Try again shortly.',
  CONFIG_INVALID: 'This integration is misconfigured. Check the provider setup and retry.',
};

/** The recommended next step for a code, on its own. `normalize()` uses this as the default. */
export function recommendedAction(code: TaxonomyCode): string {
  return ACTIONS[code];
}

/* ─────────────────────────── the three classifiers, then the combiner ─────────────────────────── */

/**
 * Map an engine `EngineErrorCode` to the taxonomy.
 *
 * The engine's internal codes predate the closed set and are finer-grained in some places
 * (`state_mismatch`, `port_blocked`) and coarser in others (`provider_error`,
 * `expired_or_revoked`). Two judgment calls, documented on purpose:
 *   - `port_blocked` / `state_mismatch` / `vault_unavailable` / `not_implemented` →
 *     `CONFIG_INVALID`. None of the nine is a "local environment" bucket; CONFIG_INVALID is
 *     the "a human must fix the setup, then retry" bucket, which is the honest action for an
 *     occupied port, a keychain that will not open, or a mismatched callback. It never blames
 *     the provider for a local problem (which PROVIDER_UNAVAILABLE would).
 *   - `expired_or_revoked` → `REVOKED`. At the point this fires there is no automatic
 *     recovery left, so the action is "reconnect" either way; REVOKED says that plainly.
 */
export function fromEngineCode(code: EngineErrorCode): TaxonomyCode {
  switch (code) {
    case 'not_connected':
      return 'NOT_CONNECTED';
    case 'denied_by_user':
      return 'CONSENT_DENIED';
    case 'expired_or_revoked':
      return 'REVOKED';
    case 'refresh_failed':
      return 'REFRESH_FAILED';
    case 'timeout':
      return 'PROVIDER_UNAVAILABLE';
    case 'provider_error':
      return 'PROVIDER_UNAVAILABLE';
    case 'port_blocked':
    case 'state_mismatch':
    case 'vault_unavailable':
    case 'not_implemented':
    case 'config_invalid':
      return 'CONFIG_INVALID';
    default:
      // Exhaustiveness guard: a new EngineErrorCode must be classified here, not silently
      // defaulted. Until then the most conservative bucket is CONFIG_INVALID.
      return 'CONFIG_INVALID';
  }
}

/** OAuth / provider error tokens, most-specific first. Matched as whole tokens, case-insensitively. */
const OAUTH_TOKENS: ReadonlyArray<readonly [RegExp, TaxonomyCode]> = [
  // Scope
  [/\binsufficient_scope\b/i, 'SCOPE_INSUFFICIENT'],
  [/\binvalid_scope\b/i, 'SCOPE_INSUFFICIENT'],
  [/\bmissing_scope\b/i, 'SCOPE_INSUFFICIENT'],
  // Revocation (checked before generic invalid_grant so a revoked family reads as REVOKED)
  [/\btoken_revoked\b/i, 'REVOKED'],
  [/\baccount_inactive\b/i, 'REVOKED'],
  [/\binvalid_auth\b/i, 'REVOKED'],
  // Expiry (refreshable)
  [/\btoken_expired\b/i, 'TOKEN_EXPIRED'],
  [/\bexpired_token\b/i, 'TOKEN_EXPIRED'],
  [/\binvalid_token\b/i, 'TOKEN_EXPIRED'],
  // Refresh grant failure
  [/\binvalid_grant\b/i, 'REFRESH_FAILED'],
  // Consent
  [/\baccess_denied\b/i, 'CONSENT_DENIED'],
  // Not connected
  [/\bnot_authed\b/i, 'NOT_CONNECTED'],
  // Rate limiting
  [/\bslow_down\b/i, 'RATE_LIMITED'],
  [/\bratelimited\b/i, 'RATE_LIMITED'],
  [/\brate_limited\b/i, 'RATE_LIMITED'],
  [/\btoo_many_requests\b/i, 'RATE_LIMITED'],
  // Provider-side transient
  [/\btemporarily_unavailable\b/i, 'PROVIDER_UNAVAILABLE'],
  [/\bserver_error\b/i, 'PROVIDER_UNAVAILABLE'],
  // Misconfiguration
  [/\binvalid_client\b/i, 'CONFIG_INVALID'],
  [/\bunauthorized_client\b/i, 'CONFIG_INVALID'],
  [/\bunsupported_grant_type\b/i, 'CONFIG_INVALID'],
  [/\bunsupported_response_type\b/i, 'CONFIG_INVALID'],
  [/\binvalid_request\b/i, 'CONFIG_INVALID'],
];

/**
 * Classify from a provider's verbatim error string, when it carries a recognizable token.
 * Returns undefined when nothing matches — the string is opaque and a coarser signal decides.
 */
export function fromOAuthError(providerError: string): TaxonomyCode | undefined {
  for (const [re, code] of OAUTH_TOKENS) {
    if (re.test(providerError)) return code;
  }
  return undefined;
}

/**
 * Classify from an HTTP status alone. Only the statuses whose meaning is unambiguous map;
 * everything else returns undefined so a more specific signal decides.
 *   429 → RATE_LIMITED · 5xx → PROVIDER_UNAVAILABLE · 401 → TOKEN_EXPIRED · 403 → SCOPE_INSUFFICIENT
 */
export function fromHttpStatus(status: number): TaxonomyCode | undefined {
  if (status === 429) return 'RATE_LIMITED';
  if (status >= 500 && status <= 599) return 'PROVIDER_UNAVAILABLE';
  if (status === 401) return 'TOKEN_EXPIRED';
  if (status === 403) return 'SCOPE_INSUFFICIENT';
  return undefined;
}

/**
 * The combiner. Precedence, highest first:
 *   1. an explicit `revoked` flag (reuse-detection is the strongest possible signal)
 *   2. a recognizable provider error token (the most specific thing the provider told us)
 *   3. the HTTP status
 *   4. the engine's own code
 *   5. PROVIDER_UNAVAILABLE (a failure we could not attribute is conservatively transient)
 *
 * The result always carries an `action`; it carries `rawProviderError` only when a non-empty
 * `providerError` was supplied.
 */
export function normalize(input: NormalizeInput): NormalizedError {
  const code = classify(input);
  const raw =
    input.providerError !== undefined && input.providerError !== '' ? input.providerError : undefined;
  return {
    code,
    action: recommendedAction(code),
    ...(raw === undefined ? {} : { rawProviderError: raw }),
  };
}

function classify(input: NormalizeInput): TaxonomyCode {
  if (input.revoked === true) return 'REVOKED';

  if (input.providerError !== undefined && input.providerError !== '') {
    const fromToken = fromOAuthError(input.providerError);
    if (fromToken !== undefined) return fromToken;
  }

  if (input.status !== undefined) {
    const fromStatus = fromHttpStatus(input.status);
    if (fromStatus !== undefined) return fromStatus;
  }

  if (input.engineCode !== undefined) return fromEngineCode(input.engineCode);

  return 'PROVIDER_UNAVAILABLE';
}

/**
 * Convenience for the common case: an `EngineError`-shaped object thrown by the engine.
 * Accepts a structural duck (`{ code, providerMessage? }`) rather than importing the
 * `EngineError` class, which lives above this leaf in the import graph.
 */
export function normalizeEngineError(err: {
  code: EngineErrorCode;
  providerMessage?: string;
}): NormalizedError {
  return normalize({
    engineCode: err.code,
    ...(err.providerMessage === undefined ? {} : { providerError: err.providerMessage }),
  });
}
