/**
 * The sole source of the redirect string (work item W1, invariant I-P1).
 *
 * Every other file in this repo — any provider.json profile, docs/registration/PORT-STRATEGY.md,
 * docs/ARCHITECTURE.md — must spell the redirect URI the way `redirectUri()` spells it here.
 * `tools/drift-check.mjs` reads THIS file and greps the repo against it, so a second
 * spelling is a failing check rather than a dead port discovered on stage.
 *
 * Why a fixed ladder instead of RFC 8252 §7.3's ephemeral port: none of the three
 * providers honors the "MUST allow any port" rule — Reddit registers exactly one URI and
 * matches it byte-for-byte, so a port must be agreed in advance. Full argument and
 * citations: docs/registration/PORT-STRATEGY.md.
 */

/** RFC 8252 recommends the IP literal; Slack's http blessing names `localhost`. §3.4 of PORT-STRATEGY.md records the deviation. */
export const REDIRECT_HOST = 'localhost';

/** Walk in order; first bindable rung wins. Reddit registers only the first. */
export const PORT_LADDER: readonly number[] = [33418, 33419, 33420];

export const CALLBACK_PATH = '/callback';

/** The exact string sent in BOTH the authorize request and the token exchange (§A8). */
export function redirectUri(port: number): string {
  return `http://${REDIRECT_HOST}:${port}${CALLBACK_PATH}`;
}

/** Every redirect URI this project is allowed to speak, in ladder order. */
export const REDIRECT_URIS: readonly string[] = PORT_LADDER.map(redirectUri);

/**
 * Zoom's registered host. U2 CLOSED 2026-08-16, better than predicted: Zoom's own
 * redirect-field validation said, verbatim — "A secure URL using HTTPS is required.
 * For local testing, you may use http://127.0.0.1 or http://[::1] (localhost is not
 * allowed)." [C-ZM-24, first-party, in-form] So the denylist is the literal hostname
 * `localhost`; the IP literal is blessed. Our single `::` listener already answers
 * 127.0.0.1 (§A3), so Zoom differs from Slack/Reddit by this one config string only.
 */
export const LOOPBACK_IP_HOST = '127.0.0.1';

/** Zoom's ladder: same ports, same path, IP-literal host. */
export const IP_REDIRECT_URIS: readonly string[] = PORT_LADDER.map(
  (port) => `http://${LOOPBACK_IP_HOST}:${port}${CALLBACK_PATH}`,
);

/**
 * Sanctioned non-ladder redirect spellings. These are NOT drift: each is registered on
 * purpose, and the engine selects one with a config change and zero engine lines.
 * Anything outside REDIRECT_URIS ∪ this list (a trailing slash, `https`, another path)
 * is drift and fails tools/drift-check.mjs.
 *   - the 127.0.0.1 ladder: Zoom's registered redirects (C-ZM-24 above)
 *   - voiceos.test: the pre-decided hosts-alias (§A11a) — superseded by C-ZM-24 as the
 *     primary Zoom plan, kept because it is registered in the same visit as insurance.
 */
export const SANCTIONED_FALLBACK_REDIRECTS: readonly string[] = [
  ...IP_REDIRECT_URIS,
  'http://voiceos.test:33418/callback',
];

/** How long a whole connect may take before the copy deck's `timeout` state fires. */
export const CONNECT_TIMEOUT_MS = 120_000;

/**
 * `state` is single-use and dies with the browser tab it was minted for.
 *
 * Enforced at REDEMPTION now (callbackState.ts calls consumeState on the callback), not just
 * at mint, so the TTL must outlive a whole connect window: a user who takes the better part of
 * CONNECT_TIMEOUT_MS to click Allow still lands a redeemable state, and it is CONNECT_TIMEOUT_MS
 * — the deadline the flow actually watches — that fires first, never a state that aged out from
 * under a consent screen still on the projector. The margin covers the mint→wait gap. The C-3
 * mix-up binding (mixup.ts) reads the same constant, so binding and state expire together.
 */
export const STATE_TTL_MS = CONNECT_TIMEOUT_MS + 30_000;

/** Refresh fires this far ahead of expiry — edge-triggered only, never a poll loop (§A1). */
export const REFRESH_SKEW_MS = 600_000;

/**
 * The confidential-custody relay base URL (SPEC §5b, C-6/C-7).
 *
 * B2a/B2b custody route the token exchange through the stateless HANDSHAKE relay — one relay
 * per DEPLOYMENT, serving every confidential provider keyed by name, never a per-provider URL
 * baked into a shipped profile. It is therefore infrastructure config, sourced from the
 * environment (self-hosters point this at their own relay), not a field on provider.json. A
 * public (Class A) or bring-your-own (B1) provider never reads it.
 *
 * Absent = no relay configured: a connect that needs one fails loudly at exchange time with an
 * actionable `config_invalid`, never a silent hang. Trailing slashes are trimmed so the path
 * join (`/v1/assertion`, `/v1/exchange`) is byte-exact.
 */
export const RELAY_URL_ENV = 'HANDSHAKE_RELAY_URL';

export function configuredRelayBaseUrl(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const url = env[RELAY_URL_ENV];
  if (url === undefined || url.trim() === '') return undefined;
  return url.trim().replace(/\/+$/, '');
}
