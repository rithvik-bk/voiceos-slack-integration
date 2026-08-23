/**
 * T2 — the production-parity eight (Phase S, builder B3).
 *
 * `SLACK-COMMAND-SPEC.md §2 T2` is law for this file: `slack_react`, `slack_schedule_message`,
 * `slack_set_reminder`, `slack_upload_file`, `slack_thread_reply`, `slack_set_status`,
 * `slack_disconnect`, `slack_health`. Seven of them change something in a workspace, so seven
 * are `confirm: true` and are mirrored into the manifest's `confirmTools` by B5.
 *
 * Three rules shape every handler below, and each one is a failure that only ever shows up in
 * front of a user:
 *
 *  1. **Nothing is guessed.** Every parameter of a gated call must trace to something the user
 *     said or something already resolved on-screen. A spoken name that resolves to zero or 2+
 *     conversations blocks with the real candidates (`ambiguous_target`); a `ts` with no prior
 *     grounding blocks (`ungrounded_message`); a duration with no number blocks
 *     (`missing_duration`); a time that isn't an absolute instant blocks (`ambiguous_time`).
 *     Blocking is a *feature* — it is the deliberate unhappy path.
 *  2. **No prose is minted here.** This file writes no sentence a user hears. `spoken` is only
 *     ever a row looked up out of the frozen deck (`copy.ts`), and everything else the user
 *     reads is composed by the card layer from structured data. There is no model in this path.
 *  3. **A card can never break a tool.** Card composition is wrapped: if the card layer throws,
 *     the tool still returns its structured content with an empty card string. A missing card is
 *     a worse demo; a thrown card is a dead tool.
 *
 * Every handler returns `{ content, card }` — structured JSON *and* a rendered card, never one
 * without the other.
 */

import { readFileSync, statSync } from 'node:fs';
import { basename } from 'node:path';

import { disconnect as engineDisconnect } from './engine/index.ts';
import { openConsentUnderGuard } from './lifecycle.ts';
import { decodeSlackText, getDirectory, humanTime, invalidateDirectory, labelForUser, resolveSendTarget } from './resolve.ts';
import type { CandidateSummary, Directory, SendTarget } from './resolve.ts';
import { AUTH_FAILURE_CODES, SlackError, requireToken } from './toolkit.ts';
import type { FrozenCards, ToolCtx, ToolDef } from './toolkit.ts';

export type { ToolDef };

/* ───────────────────────────────── the frozen contract ─────────────────────────────────
 *
 * `ToolCtx`/`ToolDef`/`SlackError`/`requireToken` all come from `toolkit.ts` (B1) — this file
 * declares no copy of them, so there is nothing to drift.
 *
 * `T2Ctx` adds four OPTIONAL seams a production ctx simply will not have; each falls back to
 * the engine / the global fetch / the clock. They exist for one reason: no test in this repo
 * may touch the Keychain, the network or the wall clock, and a size-checked file upload and a
 * vault delete are otherwise untestable. A plain `ToolCtx` is assignable to `T2Ctx`, so every
 * handler below still satisfies the frozen `ToolDef` and B5's `[...t1, ...t2]` needs no cast.
 */

/** Just enough of `fetch` to PUSH BYTES to Slack's one non-Web-API endpoint (the upload URL). */
export type UploadFetch = (
  url: string,
  init: { method: string; headers?: Record<string, string>; body?: unknown },
) => Promise<{ ok: boolean; status: number }>;

export interface T2Ctx extends ToolCtx {
  /** Test seam: engine vault delete. Falls back to the engine's own `disconnect`. */
  disconnect?(provider: string): Promise<void>;
  /** Test seam: raw byte upload. Falls back to `globalThis.fetch`. */
  fetch?: UploadFetch;
  /** Test seam: the clock, in ms. Falls back to `Date.now`. */
  now?(): number;
  /** stderr only, and never a token — VoiceOS writes MCP stderr to disk. */
  log?(line: string): void;
}

/* ───────────────────────────────── card assignment table ─────────────────────────────────
 *
 * The 11 frozen card names cover 14 tools, so the mapping is written down ONCE, here, rather
 * than being implicit in eight call sites. T2 draws on six of the eleven; `digest`,
 * `connectProgress`, `searchResults` and `emptyChannel` belong to T1/lifecycle.
 */
export const T2_CARDS = {
  slack_react: 'messageRow',
  slack_schedule_message: 'sendConfirm',
  slack_set_reminder: 'statusSet',
  slack_upload_file: 'sendConfirm',
  slack_thread_reply: 'sendConfirm',
  slack_set_status: 'statusSet',
  slack_disconnect: 'disconnected',
  slack_health: 'connectedSuccess',
  /** Every blocked preflight and every provider refusal. */
  _error: 'errorCard',
  /** No token in the vault — the C2 surface. */
  _not_connected: 'notConnected',
} as const;

/* ─────────────────────────────────── failure vocabulary ─────────────────────────────────── */

/**
 * A preflight refusal: the tool declined to act because a parameter could not be *proved*.
 * `code` is a stable machine string (it is what the eval harness counts), `detail` carries the
 * real candidates/limits so the card can show the user their actual options.
 */
export class PreflightBlock extends Error {
  readonly code: string;
  readonly detail: Record<string, unknown>;
  constructor(code: string, detail: Record<string, unknown> = {}) {
    super(`preflight blocked: ${code}`);
    this.name = 'PreflightBlock';
    this.code = code;
    this.detail = detail;
  }
}

/** Engine error codes that mean "there is no usable token", the same as Slack's auth refusals. */
const AUTH_CODES = new Set(['not_connected', 'expired_or_revoked', 'refresh_failed']);

/**
 * Slack's own word for what went wrong.
 *
 * `SlackError` (toolkit) is the shape in production; the duck-typed fallback exists so a
 * *vendored* copy of that class — the install script copies this folder — still maps to the
 * same surface instead of degrading to "internal fault". It never *invents* a reason: no
 * match returns `null` and the failure is reported as ours, not Slack's.
 */
function slackReason(error: unknown): string | null {
  if (error instanceof SlackError) return error.code;
  if (typeof error !== 'object' || error === null) return null;
  const shaped = error as Record<string, unknown>;
  if (shaped['name'] !== 'SlackError') return null;
  const code = shaped['code'];
  return typeof code === 'string' && /^[a-z][a-z0-9_]*$/.test(code) ? code : null;
}

/** The extra facts a `SlackError` carries — the rate-limit wait and the missing scope. */
function slackErrorFacts(error: unknown): Record<string, unknown> {
  if (!(error instanceof SlackError)) return {};
  return {
    ...(error.retryAfterSec === undefined ? {} : { retry_after_sec: error.retryAfterSec }),
    ...(error.needed === undefined ? {} : { needed_scope: error.needed }),
    ...(error.provided === undefined ? {} : { provided_scopes: error.provided }),
    ...(error.method === '' ? {} : { slack_method: error.method }),
  };
}

/** Engine faults arrive as `EngineError`; duck-typed so a vendored copy still maps correctly. */
function engineCode(error: unknown): string | null {
  if (typeof error !== 'object' || error === null) return null;
  const shaped = error as { name?: unknown; code?: unknown };
  if (shaped.name === 'EngineError' && typeof shaped.code === 'string') return shaped.code;
  return null;
}

/* ─────────────────────────────────── copy + cards access ─────────────────────────────────── */

/**
 * Render a card without ever letting it kill the tool (card-layer rule 3).
 * A throwing or non-string card degrades to `''`; the structured content still ships.
 */
function card(ctx: T2Ctx, name: keyof FrozenCards, data: Record<string, unknown>): string {
  try {
    const fn = ctx.cards?.[name];
    if (typeof fn !== 'function') return '';
    const html = (fn as (value: unknown) => unknown)(data);
    return typeof html === 'string' ? html : '';
  } catch (error) {
    ctx.log?.(`card ${name} failed: ${error instanceof Error ? error.name : typeof error}`);
    return '';
  }
}

/* ─────────────────────────────────── message provenance ───────────────────────────────────
 *
 * `slack_react` and `slack_thread_reply` are the two commands whose risk is *referential*:
 * "that message" has no fixed antecedent, and a mis-resolved `ts` reacts to — or replies
 * under — the wrong person's message. COMMAND-SPEC §5 is explicit: only a `channel`+`ts` the
 * assistant already has in hand may be acted on, never a guessed timestamp.
 *
 * Two layers enforce that:
 *   1. **the session registry** — read tools call `rememberMessage()` for every message they
 *      surface, so a referent that came from a real read is a Map hit with no network cost;
 *   2. **verification** — a pair that is not in the registry is looked up at Slack, and only a
 *      call that returns *that exact message* clears it. A hallucinated `ts` does not exist and
 *      is a hard block.
 *
 * `setProvenancePolicy('session')` drops layer 2 for the strictest possible reading of the
 * spec (registry hit or nothing); `'verify'` (the default) keeps the tools alive when the read
 * that grounded the referent happened before this process started.
 */

/** A reaction chip as the cards render it — Slack emoji name, truthful count, `me` when ours. */
export interface ReactionChip {
  emoji: string;
  count: number;
  me?: boolean;
}

export interface GroundedMessage {
  channel: string;
  ts: string;
  /** Resolved display name (NAME-RULE L3) — never a raw U… id; absent when unresolvable. */
  author?: string;
  /** The raw U… id, machine field only. */
  author_id?: string;
  text?: string;
  thread_ts?: string;
  /** The chips Slack reported on the verified message, for truthful merging (P2-12). */
  reactions?: ReactionChip[];
}

export type ProvenancePolicy = 'session' | 'verify';

const GROUNDING_LIMIT = 500;
const groundedMessages = new Map<string, GroundedMessage>();
let provenancePolicy: ProvenancePolicy = 'verify';

function groundingKey(channel: string, ts: string): string {
  return `${channel}\u0000${ts}`;
}

/** Called by any tool that shows a message to the user — this is what makes "that message" real. */
export function rememberMessage(message: GroundedMessage): void {
  if (message.channel === '' || message.ts === '') return;
  const key = groundingKey(message.channel, message.ts);
  groundedMessages.delete(key);
  groundedMessages.set(key, message);
  while (groundedMessages.size > GROUNDING_LIMIT) {
    const oldest = groundedMessages.keys().next();
    if (oldest.done === true) break;
    groundedMessages.delete(oldest.value);
  }
}

export function rememberMessages(messages: readonly GroundedMessage[]): void {
  for (const message of messages) rememberMessage(message);
}

export function isGrounded(channel: string, ts: string): boolean {
  return groundedMessages.has(groundingKey(channel, ts));
}

/** Test seam / session reset. */
export function forgetGroundedMessages(): void {
  groundedMessages.clear();
}

export function setProvenancePolicy(policy: ProvenancePolicy): void {
  provenancePolicy = policy;
}

export function provenancePolicyNow(): ProvenancePolicy {
  return provenancePolicy;
}

/** `{id: 'C…'}` or `'C…'` → the id. */
function channelIdOf(value: unknown): string | undefined {
  if (typeof value === 'string') return value === '' ? undefined : value;
  return str(asRecord(value)?.['id']);
}

/**
 * THE WIRE (one line, in `server.ts`): hand every tool result to this, and every message the
 * user was just shown becomes a referent "react to that" may act on.
 *
 * ```ts
 * const result = await tool.handler(args, ctx);
 * groundFromToolResult(result.content);        // ← the whole integration
 * ```
 *
 * It reads the three shapes T1 actually returns — `{channel,messages[]}` (read_channel /
 * read_dm), `{conversations[{id,messages[]}]}` (catch_up) and `{results[{channel_id,ts}]}`
 * (search) — and ignores everything else. Never throws: a grounding miss costs a verification
 * round trip, a throw would cost the tool.
 */
export function groundFromToolResult(content: unknown): number {
  try {
    const root = asRecord(content);
    if (root === undefined) return 0;
    let counted = 0;

    const harvest = (channel: string | undefined, list: unknown): void => {
      if (channel === undefined) return;
      for (const entry of asArray(list)) {
        const message = asRecord(entry);
        const ts = str(message?.['ts']);
        if (message === undefined || ts === undefined) continue;
        rememberMessage({
          channel,
          ts,
          ...(str(message['author']) === undefined ? {} : { author: str(message['author']) as string }),
          ...(str(message['text']) === undefined ? {} : { text: str(message['text']) as string }),
        });
        counted += 1;
      }
    };

    // After the Phase-D reshape `channel` is the human label ("#general"); only `channel_id`
    // (or the legacy `{id}` object) may ground a referent. Both shapes are read so grounding
    // keeps working across old and new payloads.
    harvest(str(root['channel_id']) ?? str(asRecord(root['channel'])?.['id']), root['messages']);
    for (const conversation of asArray(root['conversations'])) {
      const shaped = asRecord(conversation);
      harvest(str(shaped?.['channel_id']) ?? channelIdOf(shaped?.['id']), shaped?.['messages']);
    }
    for (const hit of asArray(root['results'])) {
      const shaped = asRecord(hit);
      if (shaped === undefined) continue;
      // `channel` in a search hit is the display string `#general`, never an id — only
      // `channel_id` (or a `{id}` object) may ground a referent.
      harvest(str(shaped['channel_id']) ?? channelIdOf(asRecord(shaped['channel'])), [shaped]);
    }
    return counted;
  } catch {
    return 0;
  }
}

interface Grounding {
  provenance: 'session' | 'verified';
  message: GroundedMessage | undefined;
  reply_count?: number;
}

/**
 * Prove a `channel`+`ts` refers to a message that exists. Throws `ungrounded_message` otherwise.
 * `thread` switches the verification call to `conversations.replies`, which also yields the
 * root's reply count for the card.
 */
async function groundMessage(
  ctx: T2Ctx,
  channel: string,
  ts: string,
  opts: { thread?: boolean } = {},
): Promise<Grounding> {
  const known = groundedMessages.get(groundingKey(channel, ts));
  if (known !== undefined && opts.thread !== true) return { provenance: 'session', message: known };

  if (provenancePolicy === 'session' && known === undefined) {
    throw new PreflightBlock('ungrounded_message', { channel, ts });
  }

  const body = opts.thread === true
    ? await ctx.slackFetch('conversations.replies', { channel, ts, limit: 1 })
    : await ctx.slackFetch('conversations.history', {
        channel,
        latest: ts,
        oldest: ts,
        inclusive: true,
        limit: 1,
      });

  const messages = asArray((body as Record<string, unknown>)['messages']);
  const first = asRecord(messages[0]);
  const foundTs = str(first?.['ts']);
  if (first === undefined || foundTs !== ts) {
    throw new PreflightBlock('ungrounded_message', { channel, ts });
  }

  // NAME-RULE L3: the raw `user` id never becomes a display value. The directory ladder names
  // the author (or nobody), the id rides in `author_id`, and the text is token-decoded once so
  // the react card, thread content and spoken lines all read human. Directory failure only
  // costs the niceties — grounding itself never depends on it.
  const dir = await getDirectory(ctx).catch(() => undefined);
  const authorId = str(first['user']);
  const author = dir === undefined ? undefined : labelForUser(dir, authorId);
  const rawText = str(first['text']);
  const reactions: ReactionChip[] = [];
  for (const entry of asArray(first['reactions'])) {
    const chip = asRecord(entry);
    const emoji = str(chip?.['name']);
    const count = num(chip?.['count']);
    if (emoji === undefined || count === undefined) continue;
    const mine = dir?.me.user_id !== undefined && asArray(chip?.['users']).includes(dir.me.user_id);
    reactions.push({ emoji, count, ...(mine ? { me: true } : {}) });
  }

  const message: GroundedMessage = {
    channel,
    ts,
    ...(author === undefined ? {} : { author }),
    ...(authorId === undefined ? {} : { author_id: authorId }),
    ...(rawText === undefined ? {} : { text: dir === undefined ? rawText : decodeSlackText(dir, rawText) }),
    ...(reactions.length === 0 ? {} : { reactions }),
  };
  rememberMessage(message);
  const replyCount = num(first['reply_count']);
  return {
    provenance: known === undefined ? 'verified' : 'session',
    message,
    ...(replyCount === undefined ? {} : { reply_count: replyCount }),
  };
}

/* ─────────────────────────────────── small typed readers ─────────────────────────────────── */

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : undefined;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

function num(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

/** The one required-string reader: a missing/blank argument is a block, never a default. */
function requiredText(args: Record<string, unknown>, key: string, code: string): string {
  const value = args[key];
  if (typeof value !== 'string' || value.trim() === '') throw new PreflightBlock(code, { field: key });
  return value;
}

function nowMs(ctx: T2Ctx): number {
  return typeof ctx.now === 'function' ? ctx.now() : Date.now();
}

/* ─────────────────────────────────── target resolution ───────────────────────────────────
 *
 * COMMAND-SPEC §5: a spoken channel/person name that resolves to zero or 2+ conversations
 * renders a disambiguation card listing the REAL options. Nothing here picks "the closest
 * string" — the candidate list goes back to the user instead.
 *
 * The resolver itself lives in `resolve.ts` (Phase D): one cached directory, one five-tier
 * ladder shared with T1. T2 only wraps its misses as `PreflightBlock`s.
 */

/** Candidate rows carry the human `name` first; `label` mirrors it for the card renderer. */
function candidateRows(miss: { candidates: CandidateSummary[] }): unknown[] {
  return miss.candidates.map((candidate) => ({ ...candidate, label: candidate.name }));
}

/** One spoken handle → a postable conversation, or a thrown `PreflightBlock` with candidates. */
async function resolveHandle(
  ctx: T2Ctx,
  spoken: string,
  scope: 'any' | 'channel' | 'person',
): Promise<SendTarget> {
  const resolved = await resolveSendTarget(ctx, spoken, scope);
  if (!resolved.ok) {
    throw new PreflightBlock(resolved.code, { query: resolved.query, candidates: candidateRows(resolved) });
  }
  return resolved.target;
}

/**
 * `{channel}` or `{user}` → a conversation. Exactly one must be given: "send it" with no
 * destination is a block, not a default channel.
 */
async function resolveTarget(ctx: T2Ctx, args: Record<string, unknown>): Promise<SendTarget> {
  const channel = str(args['channel']);
  const user = str(args['user']);
  if (channel !== undefined && user !== undefined) {
    throw new PreflightBlock('ambiguous_target', { query: `${channel} / ${user}`, candidates: [channel, user] });
  }
  if (channel !== undefined) return resolveHandle(ctx, channel, 'any');
  if (user !== undefined) return resolveHandle(ctx, user, 'person');
  throw new PreflightBlock('no_target');
}

/**
 * The sender's display name, for the card's avatar row. Never guessed; absent when unknown.
 * NAME-RULE L5: the directory ladder first; the legacy `me.user` handle is the last resort
 * and never outranks a directory hit.
 */
function senderName(directory: Directory): string | undefined {
  return labelForUser(directory, directory.me.user_id) ?? directory.me.user;
}

/** `{author, workspace}` for a writer card — best effort, never the reason a tool fails. */
async function senderCardFields(ctx: T2Ctx): Promise<Record<string, unknown>> {
  try {
    const directory = await getDirectory(ctx);
    const author = senderName(directory);
    return {
      ...(author === undefined ? {} : { author }),
      ...(directory.me.team === undefined ? {} : { workspace: directory.me.team }),
    };
  } catch {
    return {};
  }
}

/* ─────────────────────────────────── time resolution ───────────────────────────────────
 *
 * COMMAND-SPEC §5: the confirm card shows the RESOLVED ABSOLUTE timestamp, never the raw
 * utterance, and an under-specified time blocks rather than defaulting ("at 9" is not AM).
 * So this accepts only two unambiguous forms — a unix instant, or a full ISO-8601 date-time —
 * and refuses everything else. Natural-language parsing lives at Slack (`reminders.add`) or
 * upstream, never in a guess made here.
 */

const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/;

export interface ResolvedTime {
  unix: number;
  iso: string;
}

function resolveInstant(value: unknown): ResolvedTime | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    // Seconds only. A millisecond epoch is a 1000× error waiting to happen, so it is refused.
    if (value > 1e9 && value < 1e11) return { unix: Math.floor(value), iso: new Date(value * 1000).toISOString() };
    return null;
  }
  if (typeof value !== 'string' || value.trim() === '') return null;
  const text = value.trim();
  if (/^\d{10}$/.test(text)) {
    const unix = Number.parseInt(text, 10);
    return { unix, iso: new Date(unix * 1000).toISOString() };
  }
  if (!ISO_INSTANT.test(text)) return null;
  const ms = Date.parse(text.replace(' ', 'T'));
  if (!Number.isFinite(ms)) return null;
  return { unix: Math.floor(ms / 1000), iso: new Date(ms).toISOString() };
}

/* The deterministic time grammar for `when` (DESIGN-SPEC §2 clarification 2): plain words in,
 * an absolute instant out, rule-based, zero LLM. Accepts only unambiguous forms — a phrase
 * like "at 9" (no AM/PM, no minutes) parses to nothing and the caller blocks (`ambiguous_time`)
 * rather than defaulting. Local time zone, deterministic given nowMs. */

const WEEKDAY_NAMES = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'] as const;

/** `5pm` / `5:30 pm` / `17:30` / `noon` / `midnight` → hours+minutes, or null when ambiguous. */
function parseClockPhrase(text: string): { h: number; m: number } | null {
  const t = text.trim();
  if (t === 'noon') return { h: 12, m: 0 };
  if (t === 'midnight') return { h: 0, m: 0 };
  const twelve = /^(\d{1,2})(?::(\d{2}))?\s*(am|pm|a\.m\.|p\.m\.)$/.exec(t);
  if (twelve !== null) {
    let h = Number.parseInt(twelve[1] as string, 10);
    const m = twelve[2] === undefined ? 0 : Number.parseInt(twelve[2], 10);
    if (h < 1 || h > 12 || m > 59) return null;
    const isPm = (twelve[3] as string).startsWith('p');
    if (isPm && h !== 12) h += 12;
    if (!isPm && h === 12) h = 0;
    return { h, m };
  }
  const twentyFour = /^(\d{1,2}):(\d{2})$/.exec(t);
  if (twentyFour !== null) {
    const h = Number.parseInt(twentyFour[1] as string, 10);
    const m = Number.parseInt(twentyFour[2] as string, 10);
    return h <= 23 && m <= 59 ? { h, m } : null;
  }
  return null;
}

/** Midnight-of(nowMs) + dayOffset, at h:m local — unix seconds. */
function atLocalTime(nowMs: number, dayOffset: number, h: number, m: number): number {
  const date = new Date(nowMs);
  date.setHours(0, 0, 0, 0);
  date.setDate(date.getDate() + dayOffset);
  date.setHours(h, m, 0, 0);
  return Math.floor(date.getTime() / 1000);
}

/** Plain-words `when` → unix seconds, or null when the grammar cannot prove an instant. */
function parseWhenPhrase(raw: string, nowMs: number): number | null {
  const text = raw.trim().toLowerCase().replace(/\s+/g, ' ').replace(/^(at|on) /, '');

  const relative = /^in (\d+(?:\.\d+)?) ?(minutes?|mins?|min|hours?|hrs?|hr|h|days?)$/.exec(text);
  if (relative !== null) {
    const amount = Number.parseFloat(relative[1] as string);
    const unit = relative[2] as string;
    const unitMs = unit.startsWith('h') ? 3_600_000 : unit.startsWith('d') ? 86_400_000 : 60_000;
    return Math.floor((nowMs + amount * unitMs) / 1000);
  }

  const dayAndClock = /^(today|tomorrow|sunday|monday|tuesday|wednesday|thursday|friday|saturday)(?: at (.+))?$/.exec(text);
  if (dayAndClock !== null) {
    const clockPart = dayAndClock[2];
    if (clockPart === undefined) return null; // a bare day names no instant
    const clock = parseClockPhrase(clockPart);
    if (clock === null) return null;
    const word = dayAndClock[1] as string;
    if (word === 'today') return atLocalTime(nowMs, 0, clock.h, clock.m);
    if (word === 'tomorrow') return atLocalTime(nowMs, 1, clock.h, clock.m);
    const wanted = WEEKDAY_NAMES.indexOf(word as (typeof WEEKDAY_NAMES)[number]);
    const current = new Date(nowMs).getDay();
    let offset = (wanted - current + 7) % 7;
    if (offset === 0 && atLocalTime(nowMs, 0, clock.h, clock.m) * 1000 <= nowMs) offset = 7;
    return atLocalTime(nowMs, offset, clock.h, clock.m);
  }

  const clockOnly = parseClockPhrase(text);
  if (clockOnly !== null) {
    const today = atLocalTime(nowMs, 0, clockOnly.h, clockOnly.m);
    return today * 1000 > nowMs ? today : atLocalTime(nowMs, 1, clockOnly.h, clockOnly.m);
  }
  return null;
}

/**
 * Schedule's send time. The user-edited `when` re-parses and wins; `post_at` is used only
 * when `when` fails the grammar; nothing parseable at all blocks (`ambiguous_time`).
 */
function resolveSendInstant(args: Record<string, unknown>, whenText: string, nowMsValue: number): ResolvedTime {
  const direct = resolveInstant(whenText);
  const phrase = direct ?? (() => {
    const unix = parseWhenPhrase(whenText, nowMsValue);
    return unix === null ? null : { unix, iso: new Date(unix * 1000).toISOString() };
  })();
  const resolved = phrase ?? resolveInstant(args['post_at']);
  if (resolved === null) throw new PreflightBlock('ambiguous_time', { field: 'when', given: whenText });
  if (resolved.unix <= Math.floor(nowMsValue / 1000)) {
    throw new PreflightBlock('time_in_past', { resolved_at: resolved.iso });
  }
  return resolved;
}

/* ─────────────────────────────────── the failure surface ─────────────────────────────────── */

type ToolReturn = { content: unknown; card: string };

/**
 * The token died mid-call (Slack said `token_revoked`, or the engine could not refresh).
 *
 * This is not a Slack failure to report — it is a reconnect. The consent page opens through
 * the SAME cooldown guard C1/C2 use (so six dead calls are one browser tab, not six), and the
 * deck's `expired_or_revoked` row is spoken only when the tab actually opened: that sentence
 * promises "Reconnecting — one tap on Allow", and a promise the system cannot keep is exactly
 * the thing the copy deck exists to prevent.
 */
async function reconnectSurface(ctx: T2Ctx, tool: string, reason: string | null): Promise<ToolReturn> {
  const opened = await openConsentUnderGuard('first-command').catch(() => ({ opened: false }));
  const content: Record<string, unknown> = {
    ok: false,
    error: 'not_connected',
    provider: 'slack',
    tool,
    consent_opened: opened.opened,
    ...(reason === null ? {} : { provider_message: reason }),
    ...(opened.opened ? { spoken: ctx.copy.DECK.expired_or_revoked } : {}),
  };
  return {
    content,
    card: card(ctx, 'notConnected', {
      state: 'expired_or_revoked',
      tool,
      consentOpened: opened.opened,
      ...(opened.opened ? { spoken: ctx.copy.DECK.expired_or_revoked } : {}),
    }),
  };
}

/**
 * Failure → `{content, card}`. This is the whole error surface of T2 in one table, with no
 * branch that can produce a sentence nobody ratified.
 */
async function toFailure(ctx: T2Ctx, tool: string, error: unknown): Promise<ToolReturn> {
  if (error instanceof PreflightBlock) {
    ctx.log?.(`${tool} blocked: ${error.code}`);
    return {
      content: { ok: false, blocked: true, error: error.code, tool, ...error.detail },
      card: card(ctx, 'errorCard', { kind: 'preflight', tool, error: error.code, ...error.detail }),
    };
  }

  const code = engineCode(error);
  const reason = slackReason(error);
  if ((code !== null && AUTH_CODES.has(code)) || (reason !== null && AUTH_FAILURE_CODES.includes(reason))) {
    return reconnectSurface(ctx, tool, reason);
  }

  if (reason !== null) {
    // A cached id went stale: drop the directory so the next resolution refetches the lists.
    if (reason === 'channel_not_found' || reason === 'user_not_found') invalidateDirectory();
    const facts = slackErrorFacts(error);
    ctx.log?.(`${tool}: slack refused: ${reason}`);
    return {
      // The deck's one quoting row. Slack's own error string goes in verbatim — a paraphrase
      // would be us inventing a fact about their API to a user.
      content: {
        ok: false,
        error: 'provider_error',
        provider_message: reason,
        tool,
        ...facts,
        spoken: ctx.copy.providerErrorLine(reason),
      },
      card: card(ctx, 'errorCard', { kind: 'provider', tool, reason, ...facts }),
    };
  }

  const fault = code ?? 'unavailable';
  ctx.log?.(`${tool}: internal fault: ${fault}`);
  return {
    content: { ok: false, error: 'internal_fault', fault, tool, spoken: ctx.copy.internalFaultLine(fault) },
    card: card(ctx, 'errorCard', { kind: 'fault', tool, fault }),
  };
}

/**
 * Every handler is wrapped: the C2 token gate first (B1's `requireToken` — one helper, one
 * consent tab, one not-connected surface for all fourteen tools), then the body, then the
 * failure table. A T2 tool never throws — a thrown tool is a dead tool.
 */
function guarded(
  name: string,
  body: (args: Record<string, unknown>, ctx: T2Ctx) => Promise<ToolReturn>,
  opts: { token?: boolean } = {},
): ToolDef['handler'] {
  return async function handler(args: any, ctx: T2Ctx): Promise<ToolReturn> {
    const shaped = asRecord(args) ?? {};
    if (opts.token !== false) {
      const gate = await requireToken(ctx);
      if (!gate.ok) return gate.result;
    }
    try {
      return await body(shaped, ctx);
    } catch (error) {
      return toFailure(ctx, name, error);
    }
  };
}

/* ══════════════════════════════════════ the eight ══════════════════════════════════════ */

/* 1 ─ slack_react ───────────────────────────────────────────────────────────────────────── */

const EMOJI_NAME = /^[a-z0-9_+'-]{1,100}(::skin-tone-[2-6])?$/;

/** B2's frozen glyph table (`copy.ts`), read defensively so T2 compiles before it lands. */
function emojiGlyphs(ctx: T2Ctx): Record<string, string> {
  const table = (ctx.copy as { EMOJI_GLYPHS?: Record<string, string> }).EMOJI_GLYPHS;
  return typeof table === 'object' && table !== null ? table : {};
}

/**
 * `👍` / `:thumbsup:` / `thumbsup` → the Slack API name. Glyphs reverse-map through
 * `EMOJI_GLYPHS` (one table, two directions — cards.ts uses it forward); a glyph the table
 * does not know blocks rather than guessing a name.
 */
function emojiName(ctx: T2Ctx, raw: string): string {
  const trimmed = raw.trim();
  for (const [name, glyph] of Object.entries(emojiGlyphs(ctx))) {
    if (glyph === trimmed) return name;
  }
  const name = trimmed.replace(/^:+/, '').replace(/:+$/, '').toLowerCase();
  if (!EMOJI_NAME.test(name)) throw new PreflightBlock('invalid_emoji', { given: raw });
  return name;
}

/** Forward direction, for content the model reads back: name → glyph when the table knows it. */
function emojiDisplay(ctx: T2Ctx, name: string): string {
  return emojiGlyphs(ctx)[name] ?? name;
}

/**
 * Display-arg honesty (DESIGN-SPEC §2): `slack_react.message` / `slack_thread_reply.replying_to`
 * are the model's assertion of what the user saw. When the grounding registry holds the real
 * text, a material mismatch blocks — whitespace-collapsed, case-insensitive, prefix match on
 * the first 140 chars. No grounded entry means pass through; the card never fabricates.
 */
function assertDisplayArgGrounded(claimed: string, message: GroundedMessage | undefined): void {
  const actual = message?.text;
  if (actual === undefined) return;
  const collapse = (value: string): string => value.replace(/\s+/g, ' ').trim().toLowerCase();
  const expected = collapse(actual).slice(0, 140);
  const candidates = [collapse(claimed)];
  const author = message?.author;
  if (author !== undefined && candidates[0]?.startsWith(`${collapse(author)}:`) === true) {
    candidates.push(candidates[0].slice(collapse(author).length + 1).trim());
  }
  // "Author: text" with an author the registry stored under another form still compares on text.
  const generic = /^[^:]{1,80}:\s*(.*)$/.exec(candidates[0] ?? '');
  if (generic !== null && generic[1] !== undefined && generic[1] !== '') candidates.push(generic[1]);
  const matches = candidates.some((candidate) => {
    const clipped = candidate.slice(0, 140);
    return clipped.startsWith(expected) || expected.startsWith(clipped);
  });
  if (!matches) throw new PreflightBlock('ungrounded_message', { given: claimed });
}

const slackReact: ToolDef = {
  name: 'slack_react',
  description:
    'Add an emoji reaction to a specific Slack message. The message must be one already read ' +
    'aloud or shown in this session; a timestamp that cannot be proved blocks instead of reacting.',
  inputSchema: {
    type: 'object',
    properties: {
      channel: { type: 'string', description: 'Channel name, like #general. Also accepts a Slack channel ID.' },
      ts: {
        type: 'string',
        description:
          'The ts value of the target message, copied exactly from a prior read result. Internal reference, never spoken to the user.',
      },
      emoji: {
        type: 'string',
        description: 'The emoji as the character itself, like 👍. Slack emoji names like thumbsup also work.',
      },
      message: {
        type: 'string',
        description:
          'The text of the message being reacted to, copied word for word from the read result. Shown to the user on the confirmation card.',
      },
    },
    required: ['channel', 'ts', 'emoji'],
    additionalProperties: false,
  },
  confirm: true,
  handler: guarded('slack_react', async (args, ctx) => {
    const ts = requiredText(args, 'ts', 'ungrounded_message');
    const emoji = emojiName(ctx, requiredText(args, 'emoji', 'invalid_emoji'));
    const target = await resolveTarget(ctx, args);
    const grounding = await groundMessage(ctx, target.channel_id, ts);

    // The display arg is the model's assertion; the grounding registry is the gate.
    const claimed = str(args['message']);
    if (claimed !== undefined) assertDisplayArgGrounded(claimed, grounding.message);

    await ctx.slackFetch(
      'reactions.add',
      { channel: target.channel_id, timestamp: ts, name: emoji },
      { httpMethod: 'POST' },
    );

    const message = grounding.message;
    // P2-12, react truth: merge OUR reaction into the chips Slack reported, never a hardcoded
    // lone `count: 1` when the grounding captured real chips. Ours bumps or appends.
    const existing = message?.reactions ?? [];
    const reactions: ReactionChip[] = existing.some((chip) => chip.emoji === emoji)
      ? existing.map((chip) => (chip.emoji === emoji ? { ...chip, count: chip.count + 1, me: true } : chip))
      : [...existing, { emoji, count: 1, me: true }];

    return {
      content: {
        ok: true,
        action: 'reaction_added',
        emoji: emojiDisplay(ctx, emoji),
        in: target.label,
        ...(message?.author === undefined ? {} : { message_author: message.author }),
        ...(message?.text === undefined ? {} : { message_text: message.text }),
        channel_id: target.channel_id,
        ts,
        provenance: grounding.provenance,
      },
      card: card(ctx, 'messageRow', {
        channel: target.label,
        ts,
        ...(message?.text === undefined ? {} : { text: message.text }),
        ...(message?.author === undefined ? {} : { author: message.author }),
        reactions,
      }),
    };
  }),
};

/* 2 ─ slack_schedule_message ────────────────────────────────────────────────────────────── */

const slackScheduleMessage: ToolDef = {
  name: 'slack_schedule_message',
  description:
    'Schedule a message to post later in a Slack channel or DM. The text is sent word-for-word ' +
    'as dictated and the send time must be an absolute instant; the scheduled id comes back so the send can be cancelled.',
  inputSchema: {
    type: 'object',
    properties: {
      channel: { type: 'string', description: 'Channel name, like #general. Also accepts a Slack channel ID.' },
      user: {
        type: 'string',
        description: "Person's name, like Maya, to send a direct message instead. Also accepts a Slack user ID.",
      },
      text: { type: 'string', description: 'The literal message text, verbatim as dictated.' },
      post_at: { type: 'number', description: 'Internal alternative to when: unix seconds for the send. Prefer when.' },
      when: {
        type: 'string',
        description: 'When to send, in plain words, like tomorrow at 9:00 AM. Also accepts an ISO date-time.',
      },
    },
    required: ['text', 'when'],
    additionalProperties: false,
  },
  confirm: true,
  handler: guarded('slack_schedule_message', async (args, ctx) => {
    const text = requiredText(args, 'text', 'empty_text');
    const whenText = requiredText(args, 'when', 'ambiguous_time');
    // The user-edited `when` re-parses and wins over any model-supplied post_at (§2 rule).
    const when = resolveSendInstant(args, whenText, nowMs(ctx));
    const target = await resolveTarget(ctx, args);

    const body = asRecord(
      await ctx.slackFetch(
        'chat.scheduleMessage',
        { channel: target.channel_id, text, post_at: when.unix },
        { httpMethod: 'POST' },
      ),
    );
    const scheduledId = str(body?.['scheduled_message_id']);
    const sendTime = humanTime(String(when.unix), nowMs(ctx));

    return {
      content: {
        ok: true,
        action: 'message_scheduled',
        to: target.label,
        text,
        ...(sendTime === '' ? {} : { time: sendTime }),
        target_kind: target.kind,
        channel_id: str(body?.['channel']) ?? target.channel_id,
        post_at: when.unix,
        post_at_iso: when.iso,
        // The undo handle. `slack_undo_scheduled` (T3) needs exactly this string.
        ...(scheduledId === undefined ? {} : { scheduled_message_id: scheduledId }),
      },
      card: card(ctx, 'sendConfirm', {
        kind: 'schedule',
        destination: target.label,
        destination_kind: target.kind,
        ...(await senderCardFields(ctx)),
        text,
        scheduled_ts: when.unix,
        scheduled_iso: when.iso,
      }),
    };
  }),
};

/* 3 ─ slack_set_reminder ────────────────────────────────────────────────────────────────── */

const slackSetReminder: ToolDef = {
  name: 'slack_set_reminder',
  description:
    'Set a Slack reminder for yourself. The reminder text is stored word-for-word and the time ' +
    'Slack resolved is returned as an absolute timestamp so it can be shown back rather than assumed.',
  inputSchema: {
    type: 'object',
    properties: {
      text: { type: 'string', description: 'What to be reminded about, verbatim as dictated.' },
      time: {
        type: 'string',
        description: 'When to be reminded, in plain words Slack understands, like in 20 minutes or tomorrow at 9am.',
      },
    },
    required: ['text', 'time'],
    additionalProperties: false,
  },
  confirm: true,
  handler: guarded('slack_set_reminder', async (args, ctx) => {
    const text = requiredText(args, 'text', 'empty_text');
    const rawTime = args['time'];
    if (rawTime === undefined || rawTime === null || String(rawTime).trim() === '') {
      throw new PreflightBlock('ambiguous_time', { field: 'time' });
    }
    // An absolute instant is used as-is; anything else is handed to Slack VERBATIM. Slack is the
    // parser — we never reinterpret the phrase — and what comes back is the resolved instant.
    const resolved = resolveInstant(rawTime);
    const timeParam = resolved === null ? String(rawTime) : String(resolved.unix);

    const body = asRecord(
      await ctx.slackFetch('reminders.add', { text, time: timeParam }, { httpMethod: 'POST' }),
    );
    const reminder = asRecord(body?.['reminder']);
    const at = num(reminder?.['time']) ?? resolved?.unix;
    // Slack accepted it but named no instant: the card cannot show a resolved time, so per
    // COMMAND-SPEC §11 that is a block, not a shrug with a guessed time.
    if (at === undefined) throw new PreflightBlock('ambiguous_time', { field: 'time', given: String(rawTime) });

    return {
      content: {
        ok: true,
        action: 'reminder_set',
        text,
        remind_at: at,
        remind_at_iso: new Date(at * 1000).toISOString(),
        ...(str(reminder?.['id']) === undefined ? {} : { reminder_id: str(reminder?.['id']) }),
        time_source: resolved === null ? 'slack_parsed' : 'absolute',
      },
      card: card(ctx, 'statusSet', {
        kind: 'reminder',
        text,
        expires_at: at,
        expires_at_iso: new Date(at * 1000).toISOString(),
      }),
    };
  }),
};

/* 4 ─ slack_upload_file ─────────────────────────────────────────────────────────────────── */

/** Slack's documented ceiling for the external-upload flow is 1 GB. */
const MAX_UPLOAD_BYTES = 1_000_000_000;

const slackUploadFile: ToolDef = {
  name: 'slack_upload_file',
  description:
    'Upload a file that already exists on this Mac to a Slack channel or DM, using the current ' +
    'getUploadURLExternal/completeUploadExternal flow. A path that does not exist is a hard block, never a near match.',
  inputSchema: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'Absolute path of the file on this machine.' },
      filename: {
        type: 'string',
        description:
          "The file's name with extension, like report.pdf, taken from the end of path. Shown to the user on the confirmation card.",
      },
      channel: { type: 'string', description: 'Channel name, like #general. Also accepts a Slack channel ID.' },
      user: {
        type: 'string',
        description: "Person's name, like Maya, to send the file as a direct message instead. Also accepts a Slack user ID.",
      },
      title: { type: 'string', description: 'Optional title shown in Slack.' },
      initial_comment: { type: 'string', description: 'Optional message posted with the file.' },
    },
    required: ['path'],
    additionalProperties: false,
  },
  confirm: true,
  handler: guarded('slack_upload_file', async (args, ctx) => {
    const path = requiredText(args, 'path', 'file_not_found');

    // Size check BEFORE anything is reserved at Slack: a 0-byte or oversized file should never
    // consume an upload URL, and `length` in the reservation must be the real byte count.
    let size = 0;
    try {
      const stat = statSync(path);
      if (!stat.isFile()) throw new PreflightBlock('file_not_found', { path });
      size = stat.size;
    } catch (error) {
      if (error instanceof PreflightBlock) throw error;
      throw new PreflightBlock('file_not_found', { path });
    }
    if (size === 0) throw new PreflightBlock('file_empty', { path });
    if (size > MAX_UPLOAD_BYTES) throw new PreflightBlock('file_too_large', { path, bytes: size, limit: MAX_UPLOAD_BYTES });

    // `filename` is a display arg for the confirmation card; the tool always executes from
    // `path`, and when the two disagree, `path` wins silently (DESIGN-SPEC §3).
    const filename = basename(path);
    const target = await resolveTarget(ctx, args);

    const reserved = asRecord(
      await ctx.slackFetch('files.getUploadURLExternal', { filename, length: size }, { httpMethod: 'POST' }),
    );
    const uploadUrl = str(reserved?.['upload_url']);
    const fileId = str(reserved?.['file_id']);
    if (uploadUrl === undefined || fileId === undefined) throw new PreflightBlock('upload_unavailable', { filename });

    const bytes = readFileSync(path);
    const push = ctx.fetch ?? (globalThis.fetch as unknown as UploadFetch);
    const response = await push(uploadUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream' },
      body: bytes,
    });
    if (response.ok !== true) throw new PreflightBlock('upload_failed', { filename, status: response.status });

    const title = str(args['title']) ?? filename;
    const comment = str(args['initial_comment']);
    const completed = asRecord(
      await ctx.slackFetch(
        'files.completeUploadExternal',
        {
          files: JSON.stringify([{ id: fileId, title }]),
          channel_id: target.channel_id,
          ...(comment === undefined ? {} : { initial_comment: comment }),
        },
        { httpMethod: 'POST' },
      ),
    );
    const file = asRecord(asArray(completed?.['files'])[0]);

    return {
      content: {
        ok: true,
        action: 'file_uploaded',
        to: target.label,
        filename,
        title,
        bytes: size,
        ...(comment === undefined ? {} : { initial_comment: comment }),
        target_kind: target.kind,
        channel_id: target.channel_id,
        file_id: fileId,
        ...(str(file?.['permalink']) === undefined ? {} : { permalink: str(file?.['permalink']) }),
      },
      card: card(ctx, 'sendConfirm', {
        kind: 'file',
        destination: target.label,
        destination_kind: target.kind,
        ...(await senderCardFields(ctx)),
        filename,
        bytes: size,
        ...(comment === undefined ? {} : { text: comment }),
      }),
    };
  }),
};

/* 5 ─ slack_thread_reply ────────────────────────────────────────────────────────────────── */

const slackThreadReply: ToolDef = {
  name: 'slack_thread_reply',
  description:
    'Reply inside a Slack thread. The thread root must be one already read or shown in this ' +
    'session, and the reply text posts word-for-word as dictated.',
  inputSchema: {
    type: 'object',
    properties: {
      channel: { type: 'string', description: 'Channel name, like #general. Also accepts a Slack channel ID.' },
      thread_ts: {
        type: 'string',
        description:
          "The ts value of the thread's first message, copied exactly from a prior read result. Internal reference, never spoken to the user.",
      },
      text: { type: 'string', description: 'The literal reply text, verbatim as dictated.' },
      broadcast: { type: 'boolean', description: 'Also send the reply to the channel.' },
      replying_to: {
        type: 'string',
        description:
          "The thread's first message as Author: text, copied from the read result. Shown to the user on the confirmation card.",
      },
    },
    required: ['channel', 'thread_ts', 'text'],
    additionalProperties: false,
  },
  confirm: true,
  handler: guarded('slack_thread_reply', async (args, ctx) => {
    const threadTs = requiredText(args, 'thread_ts', 'ungrounded_message');
    const text = requiredText(args, 'text', 'empty_text');
    const target = await resolveTarget(ctx, args);
    // The read half grounds the write half: the root is fetched (or already in hand) before a
    // single character is posted under it.
    const grounding = await groundMessage(ctx, target.channel_id, threadTs, { thread: true });
    const broadcast = args['broadcast'] === true;

    // The display arg is the model's assertion; the grounding registry is the gate.
    const claimed = str(args['replying_to']);
    if (claimed !== undefined) assertDisplayArgGrounded(claimed, grounding.message);

    const body = asRecord(
      await ctx.slackFetch(
        'chat.postMessage',
        {
          channel: target.channel_id,
          text,
          thread_ts: threadTs,
          ...(broadcast ? { reply_broadcast: true } : {}),
        },
        { httpMethod: 'POST' },
      ),
    );
    const posted = str(body?.['ts']);
    const postedTime = posted === undefined ? '' : humanTime(posted, nowMs(ctx));
    const root = grounding.message;

    const content: Record<string, unknown> = {
      ok: true,
      action: 'thread_replied',
      to: target.label,
      text,
      broadcast,
      ...(root?.author === undefined ? {} : { thread_root_author: root.author }),
      ...(root?.text === undefined ? {} : { thread_root_text: root.text }),
      ...(postedTime === '' ? {} : { time: postedTime }),
      channel_id: target.channel_id,
      thread_ts: threadTs,
      ...(posted === undefined ? {} : { ts: posted }),
      provenance: grounding.provenance,
      ...(grounding.reply_count === undefined ? {} : { thread_reply_count: grounding.reply_count }),
    };
    if (posted !== undefined) rememberMessage({ channel: target.channel_id, ts: posted, text, thread_ts: threadTs });

    return {
      content,
      card: card(ctx, 'sendConfirm', {
        kind: 'thread_reply',
        destination: target.label,
        destination_kind: target.kind,
        ...(await senderCardFields(ctx)),
        text,
        ...(posted === undefined ? {} : { ts: posted }),
        thread_ts: threadTs,
        ...(root?.text === undefined ? {} : { thread_root_text: root.text }),
        ...(root?.author === undefined ? {} : { thread_root_author: root.author }),
      }),
    };
  }),
};

/* 6 ─ slack_set_status ──────────────────────────────────────────────────────────────────── */

const slackSetStatus: ToolDef = {
  name: 'slack_set_status',
  description:
    'Set your Slack status, and snooze notifications with it when a duration was spoken. ' +
    'A duration with no number blocks and asks for one rather than choosing a default.',
  inputSchema: {
    type: 'object',
    properties: {
      text: { type: 'string', description: 'Status text, verbatim as dictated.' },
      emoji: { type: 'string', description: 'Status emoji as the character itself, like 🌴. Slack emoji names also work.' },
      duration_minutes: { type: 'number', description: 'How long the status lasts, in minutes.' },
      snooze: { type: 'boolean', description: 'Also snooze notifications for the same duration.' },
    },
    required: ['text'],
    additionalProperties: false,
  },
  confirm: true,
  handler: guarded('slack_set_status', async (args, ctx) => {
    const text = requiredText(args, 'text', 'empty_text');
    const emojiRaw = str(args['emoji']);
    const emoji = emojiRaw === undefined ? undefined : `:${emojiName(ctx, emojiRaw)}:`;
    const wantsSnooze = args['snooze'] === true;

    const rawDuration = args['duration_minutes'];
    let duration: number | undefined;
    if (rawDuration !== undefined && rawDuration !== null) {
      const parsed = typeof rawDuration === 'number' ? rawDuration : Number.parseFloat(String(rawDuration));
      if (!Number.isFinite(parsed) || parsed <= 0 || parsed > 1440 || !Number.isInteger(parsed)) {
        throw new PreflightBlock('invalid_duration', { given: String(rawDuration) });
      }
      duration = parsed;
    }
    // "Snooze me for a bit" carries no number: block instead of inventing one (COMMAND-SPEC §14).
    if (wantsSnooze && duration === undefined) throw new PreflightBlock('missing_duration');

    const nowSeconds = Math.floor(nowMs(ctx) / 1000);
    const expiration = duration === undefined ? 0 : nowSeconds + duration * 60;

    await ctx.slackFetch(
      'users.profile.set',
      {
        profile: JSON.stringify({
          status_text: text,
          status_emoji: emoji ?? '',
          status_expiration: expiration,
        }),
      },
      { httpMethod: 'POST' },
    );

    let snoozeUntil: number | undefined;
    if (wantsSnooze && duration !== undefined) {
      const dnd = asRecord(
        await ctx.slackFetch('dnd.setSnooze', { num_minutes: duration }, { httpMethod: 'POST' }),
      );
      snoozeUntil = num(dnd?.['snooze_endtime']) ?? nowSeconds + duration * 60;
    }

    return {
      content: {
        ok: true,
        action: 'status_set',
        status_text: text,
        ...(emoji === undefined ? {} : { status_emoji: emoji }),
        ...(duration === undefined ? {} : { duration_minutes: duration }),
        ...(expiration === 0 ? {} : { expires_at: expiration, expires_at_iso: new Date(expiration * 1000).toISOString() }),
        dnd_snoozed: snoozeUntil !== undefined,
        ...(snoozeUntil === undefined
          ? {}
          : { snooze_until: snoozeUntil, snooze_until_iso: new Date(snoozeUntil * 1000).toISOString() }),
      },
      card: card(ctx, 'statusSet', {
        kind: 'status',
        text,
        ...(emoji === undefined ? {} : { emoji }),
        ...(expiration === 0 ? {} : { expires_at: expiration, expires_at_iso: new Date(expiration * 1000).toISOString() }),
        dnd_snoozed: snoozeUntil !== undefined,
        ...(snoozeUntil === undefined || duration === undefined ? {} : { snooze_minutes: duration }),
        ...(snoozeUntil === undefined ? {} : { snooze_until: snoozeUntil }),
      }),
    };
  }),
};

/* 7 ─ slack_disconnect ──────────────────────────────────────────────────────────────────── */

const slackDisconnect: ToolDef = {
  name: 'slack_disconnect',
  description:
    'Disconnect Slack on this Mac: the token is deleted from the Keychain vault. ' +
    'Toggle-grade and ungated, like the official apps; reconnecting later is one spoken command.',
  inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  confirm: false,
  // No token gate: disconnecting a connection that is already gone must still succeed cleanly.
  handler: guarded(
    'slack_disconnect',
    async (_args, ctx) => {
      // Best effort, before the token is destroyed: name the workspace being signed out of.
      // A failure here is not a failure to disconnect — it just means the card says less.
      let workspace: string | undefined;
      let handle: string | undefined;
      try {
        const identity = asRecord(await ctx.slackFetch('auth.test', {}, { httpMethod: 'POST' }));
        workspace = str(identity?.['team']);
        // NAME-RULE L4: `user` is the LEGACY handle. The directory ladder names the account
        // ("Rithvik"); the legacy handle survives only as the ladder's own last resort.
        const legacy = str(identity?.['user']);
        let display: string | undefined;
        try {
          display = labelForUser(await getDirectory(ctx), str(identity?.['user_id']));
        } catch {
          /* directory unavailable: fall through to the legacy last resort */
        }
        handle = display ?? legacy;
      } catch {
        /* already signed out, offline, or scope-less — the vault delete below is what matters */
      }

      const drop = ctx.disconnect ?? engineDisconnect;
      await drop('slack');
      forgetGroundedMessages();
      invalidateDirectory();

      // §4.4 payload contract: `handle` is the resolved display name, plain — the card layer
      // owns any `@` glyph styling; content reads naturally when spoken.
      return {
        content: {
          ok: true,
          action: 'disconnected',
          provider: 'slack',
          vault_cleared: true,
          ...(workspace === undefined ? {} : { workspace }),
          ...(handle === undefined ? {} : { handle }),
        },
        card: card(ctx, 'disconnected', {
          ...(workspace === undefined ? {} : { workspace }),
          ...(handle === undefined ? {} : { handle }),
        }),
      };
    },
    { token: false },
  ),
};

/* 8 ─ slack_health ──────────────────────────────────────────────────────────────────────── */

const slackHealth: ToolDef = {
  name: 'slack_health',
  description:
    'Report whether Slack is connected on this Mac, and as whom in which workspace, by asking ' +
    'Slack itself rather than by trusting a stored token. Read-only.',
  inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  confirm: false,
  handler: guarded('slack_health', async (_args, ctx) => {
    // Only a probe that returns an identity is allowed to produce the word "connected" — never
    // the mere presence of a vaulted token (Phase-1 rule, kept).
    const identity = asRecord(await ctx.slackFetch('auth.test', {}, { httpMethod: 'POST' }));
    const user = str(identity?.['user']);
    const userId = str(identity?.['user_id']);
    if (user === undefined && userId === undefined) throw new PreflightBlock('identity_unavailable');
    const workspace = str(identity?.['team']);

    // NAME-RULE L4: `auth.test`'s `user` is the LEGACY handle ("icynd2777"). Resolve the real
    // display name through the directory ladder before anything user-visible or spoken is
    // produced; the legacy handle is the ladder's own last resort, never outranking a hit.
    let display: string | undefined;
    try {
      display = labelForUser(await getDirectory(ctx), userId);
    } catch {
      /* directory unavailable: the legacy fallback below is the ladder's last resort */
    }
    const handle = display ?? user;
    if (handle === undefined) throw new PreflightBlock('identity_unavailable');

    return {
      content: {
        ok: true,
        connected: true,
        handle,
        ...(workspace === undefined ? {} : { workspace }),
        ...(userId === undefined ? {} : { user_id: userId }),
        ...(str(identity?.['team_id']) === undefined ? {} : { team_id: str(identity?.['team_id']) }),
        ...(str(identity?.['url']) === undefined ? {} : { workspace_url: str(identity?.['url']) }),
      },
      // No `presence` field: auth.test proves the token, not Slack presence, and the green dot
      // renders only when presence is actually known to be 'active' (P1-11 honesty gate).
      card: card(ctx, 'connectedSuccess', {
        handle,
        ...(workspace === undefined ? {} : { workspace }),
      }),
    };
  }),
};

/* ─────────────────────────────────────── the registry ─────────────────────────────────────── */

/** The eight, in COMMAND-SPEC §2 T2 order. B5 spreads this into the single tool registry. */
export const T2_TOOLS: ToolDef[] = [
  slackReact,
  slackScheduleMessage,
  slackSetReminder,
  slackUploadFile,
  slackThreadReply,
  slackSetStatus,
  slackDisconnect,
  slackHealth,
];

export const T2_TOOL_NAMES = T2_TOOLS.map((tool) => tool.name);

/** Exactly the T2 tools the manifest must list under `confirmTools`. */
export const T2_CONFIRM_TOOLS = T2_TOOLS.filter((tool) => tool.confirm).map((tool) => tool.name);
