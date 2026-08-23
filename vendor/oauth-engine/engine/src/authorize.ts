/**
 * The authorize URL. One function, and one non-obvious rule that has already cost the
 * ecosystem real debugging time.
 *
 * `URLSearchParams` is NOT used here. It serialises to
 * `application/x-www-form-urlencoded`, which encodes a space as `+`. That is correct for a
 * form body and wrong in a query string for at least one shipping provider: Zoom returns
 * 4700 — an invalid-REDIRECT code, pointing at entirely the wrong thing — when a multi-scope
 * list is serialised that way [C-ZM-14]. So the query is built with `encodeURIComponent`,
 * which emits `%20`, and the scope delimiter is a profile axis (Slack comma-separates, Zoom
 * and Reddit space-separate).
 *
 * `redirect_uri` is whatever the loopback actually bound, passed in and sent unmodified —
 * the same string the token exchange will send (§A8, D6).
 */

import type { ProviderProfile } from './types.ts';

export interface AuthorizeInput {
  /** Byte-identical to the value the exchange will send. */
  redirectUri: string;
  /** Single-use, 60s TTL, minted by state.ts. */
  state: string;
  /** BASE64URL(SHA256(verifier)). Omitted entirely when `pkce: 'none'` (Reddit). */
  challenge?: string;
}

/** `%20`, never `+`. `encodeURIComponent` also leaves `-._~!*'()` alone, all of which are legal. */
function encodePair(key: string, value: string): string {
  return `${encodeURIComponent(key)}=${encodeURIComponent(value)}`;
}

export function buildAuthorizeUrl(profile: ProviderProfile, input: AuthorizeInput): string {
  const delimiter = profile.scope_delimiter ?? ' ';
  const pairs: Array<[string, string]> = [
    ['client_id', profile.client_id],
    ['response_type', 'code'],
    ['redirect_uri', input.redirectUri],
    [profile.scope_param, profile.scopes.join(delimiter)],
    ['state', input.state],
  ];

  if (profile.pkce === 'S256' && input.challenge !== undefined) {
    pairs.push(['code_challenge', input.challenge], ['code_challenge_method', 'S256']);
  }

  // Provider-specific required extras that are NOT an engine concept: Slack's
  // present-and-empty `scope` (bot scopes are forbidden on a localhost redirect, C-SL-03)
  // and Reddit's `duration=permanent` (without it there is no refresh token at all).
  for (const [key, value] of Object.entries(profile.extra_authorize_params ?? {})) {
    pairs.push([key, value]);
  }

  const separator = profile.authorize_url.includes('?') ? '&' : '?';
  return `${profile.authorize_url}${separator}${pairs.map(([k, v]) => encodePair(k, v)).join('&')}`;
}
