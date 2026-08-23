/**
 * TOOLKIT — the frozen contract every Slack tool file imports (Phase S, B1).
 *
 * Three things live here and nothing else:
 *
 *   1. `ToolCtx` / `ToolDef` — the shapes B2 (T1), B3 (T2) and B5 (registry) code against,
 *      byte-for-byte the frozen contract in `build-system/briefs/phaseS-common.md`.
 *   2. `slackFetch` — ONE Slack Web API call, with the two failure shapes Slack actually
 *      has (a rare non-2xx, and the specialty: HTTP 200 carrying `{"ok": false}`) mapped to
 *      a single typed `SlackError`. No tool re-implements this and no tool re-reads `ok`.
 *   3. `requireToken` — C2, the not-connected flow: a tool with no usable token opens
 *      consent (under the SAME cooldown guard the startup auto-open uses) and answers with
 *      the `not_connected` card instead of throwing a stack trace at a user.
 *
 * Count the auth code in a tool file that imports this: still zero. `ctx.getToken()` is the
 * engine's `getFreshToken`, so refresh, rotation, the cross-process lock and the retry all
 * happen behind one call — the tools read as if auth did not exist.
 *
 * IMPORT DIRECTION (there is exactly one, on purpose): `toolkit.ts` imports `lifecycle.ts`
 * at runtime for the consent opener; `lifecycle.ts` imports this file **for types only**
 * (`import type`, erased by node's type stripper), so the module graph has no runtime cycle.
 */

import { getToken as engineGetToken } from './engine/index.ts';
import type { ProviderProfile } from './engine/index.ts';
import { openConsentUnderGuard } from './lifecycle.ts';

/* ───────────────────────────────── the frozen contract ───────────────────────────────── */

/**
 * The 11 card functions `cards.ts` (B4) is frozen to export. Declared here as an
 * *intersection partner* rather than a replacement: `CardsModule` is
 * `typeof import('./cards.ts') & FrozenCards`, so
 *
 *   - the contract's `cards: typeof import('./cards.ts')` still holds (the real module is
 *     always assignable to the field), and
 *   - B1/B2/B3 can compile against the frozen names while B4 is still writing them, which
 *     is the entire reason five builders can run in parallel.
 *
 * The parameters are deliberately open: B4 owns the narrow per-card data types, and an
 * intersection turns the two declarations into an overload set, so B4's narrower signature
 * wins wherever it matches and nothing here can constrain their design.
 */
export interface FrozenCards {
  /** A single Slack message, rendered as a literal Slack row. */
  messageRow(data: any): string;
  /** The cross-channel catch-up digest. */
  digest(data: any): string;
  /** Outgoing message + destination pill, the confirm surface. */
  sendConfirm(data: any): string;
  /** Connected as @handle in <workspace>. */
  connectedSuccess(data: any): string;
  /** C2: no token on this Mac (yet). */
  notConnected(data: any): string;
  /** C1/C3: browser opened, waiting on the human. */
  connectProgress(data: any): string;
  /** Every failure surface, including the disambiguation variant. */
  errorCard(data: any): string;
  /** Vault entry destroyed. */
  disconnected(data: any): string;
  /** search.messages / find results. */
  searchResults(data: any): string;
  /** status + DND set. */
  statusSet(data: any): string;
  /** A channel with nothing in it. */
  emptyChannel(data: any): string;
}

export type CardsModule = typeof import('./cards.ts') & FrozenCards;
export type CopyModule = typeof import('./copy.ts');

/** FROZEN — `build-system/briefs/phaseS-common.md`. Do not add members. */
export interface ToolCtx {
  /** engine `getFreshToken` for 'slack' — refresh/rotation/lock all happen behind it. */
  getToken(): Promise<string>;
  /** Bearer + `ok:false` → `SlackError`. */
  slackFetch(
    method: string,
    params?: Record<string, unknown>,
    opts?: { httpMethod?: 'GET' | 'POST' },
  ): Promise<any>;
  cards: CardsModule;
  copy: CopyModule;
}

/** FROZEN — `build-system/briefs/phaseS-common.md`. Do not add members. */
export interface ToolDef {
  /** Exact names from SLACK-COMMAND-SPEC §2. */
  name: string;
  description: string;
  /** JSON Schema. */
  inputSchema: Record<string, unknown>;
  /** true ⇒ listed in the manifest's `confirmTools`. */
  confirm: boolean;
  handler(args: any, ctx: ToolCtx): Promise<{ content: unknown; card: string }>;
}

/* ────────────────────────────────────── errors ────────────────────────────────────── */

/**
 * Slack said no.
 *
 * `code` is Slack's own error string (`not_in_channel`, `missing_scope`, `ratelimited`, …)
 * and is carried VERBATIM — a paraphrase would be us inventing a fact about their API in
 * front of a user. Transport failures get a synthetic code (`http_500`, `network_error`,
 * `invalid_response`) that is visibly not one of Slack's.
 */
export class SlackError extends Error {
  readonly code: string;
  /** The Web API method that refused, for the log line and the error card. */
  readonly method: string;
  readonly httpStatus: number | undefined;
  /** From the `Retry-After` header on a 429 — the only number the rate-limit card may show. */
  readonly retryAfterSec: number | undefined;
  /** `missing_scope` carries these; they are the difference between a fix and a guess. */
  readonly needed: string | undefined;
  readonly provided: string | undefined;

  constructor(
    code: string,
    init: {
      method: string;
      httpStatus?: number | undefined;
      retryAfterSec?: number | undefined;
      needed?: string | undefined;
      provided?: string | undefined;
    },
  ) {
    super(`slack refused ${init.method}: ${code}`);
    this.name = 'SlackError';
    this.code = code;
    this.method = init.method;
    this.httpStatus = init.httpStatus;
    this.retryAfterSec = init.retryAfterSec;
    this.needed = init.needed;
    this.provided = init.provided;
  }
}

/**
 * The five ways Slack says "this token is dead." Anything on this list means *reconnect*,
 * not "try again" — `requireToken` and every tool's failure mapping key off this, so the
 * list exists once.
 */
export const AUTH_FAILURE_CODES: readonly string[] = [
  'invalid_auth',
  'not_authed',
  'token_expired',
  'token_revoked',
  'account_inactive',
];

export function isAuthFailure(error: unknown): boolean {
  return error instanceof SlackError && AUTH_FAILURE_CODES.includes(error.code);
}

/* ─────────────────────────────────── the HTTP call ─────────────────────────────────── */

/** Just enough of `fetch` to call a JSON API — structurally satisfied by `globalThis.fetch`. */
export type FetchLike = (
  input: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{
  ok: boolean;
  status: number;
  headers?: { get(name: string): string | null };
  json(): Promise<unknown>;
}>;

export interface ToolkitOptions {
  profile: ProviderProfile;
  fetch?: FetchLike;
  /** Overrides the engine — tests inject; production never passes this. */
  getToken?: () => Promise<string>;
  /** stderr only, and never a token, code or verifier. */
  log?: (line: string) => void;
  cards: CardsModule;
  copy: CopyModule;
}

/** `https://slack.com/api` — derived from the profile, so the host lives in config, not code. */
export function apiBase(profile: ProviderProfile): string {
  if (profile.api_base !== undefined && profile.api_base !== '') {
    return profile.api_base.replace(/\/$/, '');
  }
  return `${new URL(profile.identity_probe.url).origin}/api`;
}

/**
 * Slack's wire convention, not ours: POST bodies are
 * `application/x-www-form-urlencoded; charset=utf-8` with the token in the Authorization
 * header (their docs' own default for user tokens), and a handful of read methods are
 * happier as a GET with a query string. `opts.httpMethod` picks; POST is the default
 * because every write method requires it.
 *
 * Values are stringified once, here: `true` → `"true"`, arrays → CSV (Slack's `types=` and
 * `channels=` params), objects → JSON (`blocks`, `attachments`). `undefined`/`null` params
 * are dropped rather than sent as the literal string "undefined" — which Slack would
 * cheerfully accept and then fail on with a confusing error.
 */
function encodeParams(params: Record<string, unknown>): URLSearchParams {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    if (typeof value === 'string') search.set(key, value);
    else if (typeof value === 'number' || typeof value === 'boolean') search.set(key, String(value));
    else if (Array.isArray(value)) search.set(key, value.map((item) => String(item)).join(','));
    else search.set(key, JSON.stringify(value));
  }
  return search;
}

function headerValue(response: { headers?: { get(name: string): string | null } }, name: string): string | null {
  return response.headers?.get(name) ?? null;
}

function stringField(body: Record<string, unknown>, key: string): string | undefined {
  const value = body[key];
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/**
 * One Slack Web API call, with every failure already shaped.
 *
 * Order matters: the `ok:false` body is checked BEFORE the HTTP status is trusted, because
 * Slack answers HTTP 200 for almost every refusal (C-SL-20) — a call that only looked at
 * `response.ok` would report success for `channel_not_found`.
 */
export async function callSlack(
  options: { profile: ProviderProfile; fetch: FetchLike; getToken: () => Promise<string> },
  method: string,
  params: Record<string, unknown> = {},
  opts: { httpMethod?: 'GET' | 'POST' } = {},
): Promise<Record<string, unknown>> {
  const token = await options.getToken();
  const httpMethod = opts.httpMethod ?? 'POST';
  const encoded = encodeParams(params);

  const url = new URL(`${apiBase(options.profile)}/${method}`);
  if (httpMethod === 'GET') url.search = encoded.toString();

  let response;
  try {
    response = await options.fetch(url.toString(), {
      method: httpMethod,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        ...(httpMethod === 'POST'
          ? { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' }
          : {}),
        ...(options.profile.static_headers ?? {}),
      },
      ...(httpMethod === 'POST' ? { body: encoded.toString() } : {}),
    });
  } catch {
    // The network, not Slack — `network_error` is deliberately not one of Slack's own error
    // strings, so no card can ever quote it as "Slack turned that down".
    throw new SlackError('network_error', { method });
  }

  // 429 is the one status Slack answers with a real HTTP code, and the Retry-After header
  // is the only place the wait number may come from (never a guess on the card).
  if (response.status === 429) {
    const retryAfter = Number.parseInt(headerValue(response, 'retry-after') ?? '', 10);
    throw new SlackError('ratelimited', {
      method,
      httpStatus: 429,
      ...(Number.isFinite(retryAfter) ? { retryAfterSec: retryAfter } : {}),
    });
  }

  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }

  if (typeof body !== 'object' || body === null) {
    throw new SlackError(response.ok ? 'invalid_response' : `http_${response.status}`, {
      method,
      httpStatus: response.status,
    });
  }

  const shaped = body as Record<string, unknown>;
  if (shaped['ok'] !== true) {
    const code = stringField(shaped, 'error') ?? (response.ok ? 'unknown_error' : `http_${response.status}`);
    throw new SlackError(code, {
      method,
      httpStatus: response.status,
      ...(stringField(shaped, 'needed') === undefined ? {} : { needed: stringField(shaped, 'needed') }),
      ...(stringField(shaped, 'provided') === undefined ? {} : { provided: stringField(shaped, 'provided') }),
    });
  }
  if (!response.ok) {
    // ok:true on a non-2xx is not a shape Slack produces; treat it as transport damage
    // rather than believing the body.
    throw new SlackError(`http_${response.status}`, { method, httpStatus: response.status });
  }

  return shaped;
}

/* ──────────────────────────────────── the context ──────────────────────────────────── */

/**
 * Build the `ToolCtx` every handler receives. One place assembles it, so `server.ts` (B5)
 * has nothing to get wrong and a test can build the same object with a stub fetch.
 */
export function createToolCtx(options: ToolkitOptions): ToolCtx {
  const fetchImpl: FetchLike = options.fetch ?? (globalThis.fetch as unknown as FetchLike);
  const getToken = options.getToken ?? (() => engineGetToken(options.profile.name));

  return {
    getToken,
    slackFetch: (method, params, opts) =>
      callSlack({ profile: options.profile, fetch: fetchImpl, getToken }, method, params ?? {}, opts ?? {}),
    cards: options.cards,
    copy: options.copy,
  };
}

/* ────────────────────────────────── C2 — requireToken ────────────────────────────────── */

export type TokenGate =
  | { ok: true; token: string }
  | { ok: false; result: { content: unknown; card: string } };

/**
 * C2, the not-connected flow — the helper every T1/T2 handler calls first.
 *
 * ```ts
 * const gate = await requireToken(ctx);
 * if (!gate.ok) return gate.result;          // card + structured content, already shaped
 * ```
 *
 * On a missing/dead token it opens the consent page **through the same cooldown guard the
 * startup auto-open uses** (`lifecycle.openConsentUnderGuard`) — so a user who fires six
 * tools at a disconnected Slack gets one browser tab, not six — and returns the
 * `not_connected` card. It never throws: a tool that cannot authenticate is a product
 * state, not a stack trace.
 */
export async function requireToken(ctx: ToolCtx): Promise<TokenGate> {
  let token: string | null = null;
  try {
    token = await ctx.getToken();
  } catch {
    token = null;
  }
  if (token !== null && token !== '') return { ok: true, token };

  const opened = await openConsentUnderGuard('first-command').catch(() => ({
    opened: false,
    reason: 'open_failed' as const,
  }));

  return {
    ok: false,
    result: {
      content: {
        error: 'not_connected',
        provider: 'slack',
        consent_opened: opened.opened,
        spoken: ctx.copy.DECK.needs_connect,
      },
      card: ctx.cards.notConnected({
        state: 'needs_connect',
        spoken: ctx.copy.DECK.needs_connect,
        consentOpened: opened.opened,
      }),
    },
  };
}
