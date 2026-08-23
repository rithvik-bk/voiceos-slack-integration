/**
 * THE COPY DECK, in code. Frozen strings — no LLM in this path.
 *
 * Every user-visible sentence the engine can produce is here, and nowhere else. Two reasons
 * this is a module rather than string literals scattered through `index.ts`:
 *
 *  1. The deck is a product decision, and the rule it encodes is
 *     "the assistant never narrates progress it cannot verify." A sentence invented at a
 *     call site is a sentence nobody reviewed.
 *  2. Eleven states each have a spoken line AND a branded page, and the pairing was already
 *     wrong once (`provider_error` rendering state-mismatch words). One table, one place to
 *     check.
 *
 * The deck is written for Slack. The provider name is the ONLY substitution — parameterised
 * rather than hard-coded so integration #6 speaks its own name without a copy edit.
 */

import type { ConnectErrorCode } from './types.ts';

/** "Your Slack isn't connected yet. I'm opening the approval page now." */
export function needsConnect(provider: string): string {
  return `Your ${provider} isn't connected yet. I'm opening the approval page now.`;
}

/** "Opening Slack in your browser." */
export function openingBrowser(provider: string): string {
  return `Opening ${provider} in your browser.`;
}

/** "Waiting for you to hit Allow." */
export const AWAITING_CONSENT = 'Waiting for you to hit Allow.';

/**
 * RFC 8628 (C-17) — the spoken instruction for a headless / no-loopback connect: there is no
 * browser to open, so the user is told the URL to visit and the short code to enter on another
 * device. The `user_code` is display material (not the secret `device_code`), safe to speak.
 */
export function deviceCode(provider: string, userCode: string, verificationUri: string): string {
  return `To connect ${provider}, go to ${verificationUri} and enter the code ${userCode}.`;
}

/** "Got it. Verifying." */
export const EXCHANGING = 'Got it. Verifying.';

/** "Connected as Rithvik in VoiceOS HQ." — produced by the identity probe, never by a 200. */
export function connected(handle: string, workspace?: string): string {
  return workspace === undefined || workspace === ''
    ? `Connected as ${handle}.`
    : `Connected as ${handle} in ${workspace}.`;
}

/**
 * "I couldn't open your browser. Nothing was connected." — deck row `browser_open_failed`,
 * ratified 2026-08-16 (audit fix round 1).
 *
 * This one is provider-NEUTRAL on purpose, twice over. It is a failure of this machine, not
 * of the provider, so naming the provider would be a false accusation on a projector — which
 * is exactly the bug it replaces: a browser that would not launch used to be spoken through
 * the `provider_error` row, i.e. "Slack turned that down: …". And because the sentence never
 * varies, the Slack integration can recognise it by frozen-constant equality and render the
 * right card, without the status contract growing a seventh ConnectErrorCode.
 */
export const BROWSER_OPEN_FAILED = "I couldn't open your browser. Nothing was connected.";

/** "Disconnected Slack." — Phase 4 renders this behind a confirmation card (D3). */
export function disconnected(provider: string): string {
  return `Disconnected ${provider}.`;
}

/**
 * The spoken line for every failure the product surface can reach.
 *
 * `providerMessage` is the provider's own words, verbatim — never our paraphrase — and it
 * is only ever interpolated into `provider_error`, the one row of the deck that quotes.
 */
export function errorLine(
  code: ConnectErrorCode,
  provider: string,
  providerMessage?: string,
): string {
  switch (code) {
    case 'denied_by_user':
      return `You declined that one. Say 'connect ${provider}' whenever you want to retry.`;
    case 'port_blocked':
      return "Something else is using my callback port. Close it and I'll retry.";
    case 'expired_or_revoked':
      return 'That connection expired. Reconnecting. One tap on Allow.';
    case 'state_mismatch':
      return "That reply didn't match my request, so I threw it away. Try connecting again.";
    case 'timeout':
      return `I stopped waiting for that approval. Say 'connect ${provider}' when you're ready.`;
    case 'provider_error':
      return providerMessage === undefined || providerMessage === ''
        ? `${provider} turned that down. Nothing was connected.`
        : `${provider} turned that down: ${providerMessage}. Nothing was connected.`;
    default: {
      const exhaustive: never = code;
      throw new Error(`no copy-deck line for ${String(exhaustive)}`);
    }
  }
}

/**
 * The operator-facing next step per failure. Never spoken; safe to log.
 * Kept beside the spoken line so a new error code cannot ship with one and not the other.
 */
export function errorHint(code: ConnectErrorCode): string {
  switch (code) {
    case 'denied_by_user':
      return 'The user pressed Cancel on the provider consent screen. Nothing was stored.';
    case 'port_blocked':
      return 'Every port on the callback ladder is in use. Close whatever holds them and retry.';
    case 'expired_or_revoked':
      return 'The grant is no longer valid at the provider. A new consent is required.';
    case 'state_mismatch':
      return 'The callback carried a state value this engine did not mint. It was discarded.';
    case 'timeout':
      return 'No callback arrived before the deadline. The listener is closed.';
    case 'provider_error':
      return 'The provider refused the request. Its own message is on the status.';
    default: {
      const exhaustive: never = code;
      throw new Error(`no hint for ${String(exhaustive)}`);
    }
  }
}
