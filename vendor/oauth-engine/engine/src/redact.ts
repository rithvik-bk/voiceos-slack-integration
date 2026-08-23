/**
 * The boundary that keeps credentials out of strings (work item W4, Dr. M's rule).
 *
 * VoiceOS writes MCP stderr to disk. So the moment a token, refresh token, authorization
 * code or PKCE verifier reaches an error message, a log line or a rendered page, "tokens
 * never touch disk unencrypted" is false — and it is false in the one file a support
 * engineer is most likely to paste into a ticket.
 *
 * Two defences, both cheap:
 *  1. `safeProviderMessage` builds the provider-facing string from an ALLOWLIST of error
 *     fields. A response body is never stringified wholesale, so a token sitting next to
 *     `error` in the same object cannot ride along.
 *  2. `redact` scrubs known secret values and anything shaped like a bearer credential out
 *     of a string we are about to surface. Belt and braces, because the allowlist is only
 *     as good as the provider's field naming.
 */

/** Fields providers actually use to explain a refusal, in the order we prefer them. */
const MESSAGE_FIELDS = ['error_description', 'error_summary', 'reason', 'message', 'error'] as const;

/** Never render a provider essay onto a projector or into a log line. */
const MAX_MESSAGE = 200;

/**
 * Credential-shaped substrings. Deliberately conservative: these patterns match token
 * *prefixes* real providers use, so a normal English error message is never mangled.
 * (No literal `xox` bigram is written here — see the note below.)
 */
const CREDENTIAL_SHAPES: readonly RegExp[] = [
  // Slack user/bot/app tokens: x + o + x + letter + '-' + body.
  new RegExp(`${'x'}${'o'}${'x'}[a-zA-Z]-[A-Za-z0-9-]{8,}`, 'g'),
  // Long opaque bearer-ish blobs that follow a giveaway key name.
  /\b(?:access_token|refresh_token|code_verifier|client_secret)=[^\s&"']+/g,
  // JWTs.
  /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g,
  // Google OAuth access tokens: `ya29.` + a long opaque run.
  /ya29\.[A-Za-z0-9._-]{20,}/g,
  // Google refresh tokens: `1//` + a long opaque run. Anchored on the literal `1//`, which a
  // normal message (and an ordinary URL's `://`) does not carry.
  /1\/\/[A-Za-z0-9_-]{20,}/g,
  // Stripe secret/restricted keys (live or test) — the exact credential §21 says nobody brokers.
  /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}/g,
  // GitHub tokens: classic PAT (ghp_), OAuth (gho_), user-to-server (ghu_), server-to-server
  // (ghs_), refresh (ghr_), and fine-grained PAT (github_pat_).
  /\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{16,}/g,
];

/**
 * Replace every known secret value, and every credential-shaped run, with `[redacted]`.
 *
 * `secrets` is the caller's list of values it is *holding right now* (the access token it
 * just parsed, the verifier it just used). Passing them is what makes this exact rather
 * than heuristic.
 */
export function redact(text: string, secrets: ReadonlyArray<string | undefined> = []): string {
  let out = text;
  for (const secret of secrets) {
    // A short "secret" (a client_id fragment, an empty string) would carpet-bomb the
    // message; only values long enough to be credentials are worth substituting.
    if (typeof secret !== 'string' || secret.length < 8) continue;
    out = out.split(secret).join('[redacted]');
  }
  for (const shape of CREDENTIAL_SHAPES) out = out.replace(shape, '[redacted]');
  return out;
}

/**
 * The provider's own words for why it said no — built from named fields only, escaped of
 * credentials, and clipped. `undefined` when the body says nothing useful, because an
 * empty quote is worse than no quote in the copy deck's `provider_error` line.
 */
export function safeProviderMessage(
  payload: unknown,
  secrets: ReadonlyArray<string | undefined> = [],
): string | undefined {
  if (payload === null || typeof payload !== 'object') return undefined;
  const body = payload as Record<string, unknown>;

  const parts: string[] = [];
  for (const field of MESSAGE_FIELDS) {
    const value = body[field];
    if (typeof value === 'string' && value.trim() !== '' && !parts.includes(value.trim())) {
      parts.push(value.trim());
    }
    if (parts.length === 2) break; // e.g. `invalid_grant: code already redeemed`
  }
  if (parts.length === 0) return undefined;

  const message = redact(parts.join(': '), secrets);
  return message.length > MAX_MESSAGE ? `${message.slice(0, MAX_MESSAGE - 1)}…` : message;
}
