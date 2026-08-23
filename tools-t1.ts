/**
 * T1 — THE CORE SIX.
 *
 * `slack_catch_up` · `slack_read_channel` · `slack_read_dm` · `slack_send_message` ·
 * `slack_search` · `slack_find` — implemented exactly per `docs/design/SLACK-COMMAND-SPEC.md`
 * §2 T1 (plus §5's voice-pitfall table, which is the reason half this file is name
 * resolution rather than API calls).
 *
 * Four rules hold this file honest, and every one of them is testable:
 *
 *  1. **No prose is minted here.** A handler returns structured JSON facts and the *name* of
 *     a card; sentences live in the copy deck (`copy.ts`, B4) and pixels live in `cards.ts`
 *     (B4). This file never writes a sentence the user hears and never hand-writes HTML.
 *  2. **Nothing is guessed.** Every spoken channel/person name is resolved against a list
 *     Slack actually returned. Zero matches or two-plus matches produce a disambiguation
 *     card — never "the closest string". `slack_send_message` therefore cannot post to a
 *     channel the user did not name, which is the single worst failure this integration has.
 *  3. **Extractive, never generative.** The catch-up digest carries verbatim message text
 *     (`clip()`-ing is the card layer's job, not ours). There is no summarizer anywhere in
 *     this path — see `docs/CONTEXT.md`; the digest's ranking is arithmetic (mention count,
 *     then recency), so the same inbox always produces the same digest.
 *  4. **A card can never break a tool.** Card composition runs inside `safeCard()`; if the
 *     card layer is missing or throws, the tool still returns its content with an empty card
 *     string. A missing card is a worse demo; a thrown card is a dead tool.
 *
 * Auth appears nowhere below: `ctx.slackFetch` already carries a fresh Bearer token from the
 * engine vault (toolkit.ts, B1). That absence is the whole design: an integration built on this engine contains zero auth code.
 */

import { SCARD } from './copy.ts';
import {
  candidateSummary,
  decodeSlackText,
  getDirectory,
  humanTime,
  labelForChannel,
  labelForUser,
  resolveConversation,
  resolveSendTarget,
} from './resolve.ts';
import type { CandidateSummary, Conversation, Directory, Person, ResolveMiss, ResolveScope } from './resolve.ts';
import { AUTH_FAILURE_CODES } from './toolkit.ts';
import type { FrozenCards, TokenGate, ToolCtx, ToolDef } from './toolkit.ts';

/* ── the resolver lives in resolve.ts now (Phase D) — T1 re-exports the pool API for its callers ── */
export { resolveTarget } from './resolve.ts';
export type { Conversation, Person, Resolution, Target } from './resolve.ts';

/* ───────────────────────── the frozen contract, imported not re-declared ─────────────────────────
 *
 * `ToolCtx` / `ToolDef` / `TokenGate` come from `toolkit.ts` (B1) — the single canonical home
 * of the contract in `build-system/briefs/phaseS-common.md`. Nothing in this file re-states
 * them, so T1 cannot drift from what B3's T2 tools and B5's registry compile against.
 */

/** What every handler returns: structured content + a rendered card. Plain text is an audit fail. */
export interface ToolOutput {
  content: unknown;
  card: string;
}

export type { ToolCtx, ToolDef };

/* ─────────────────────────────────────── seams ─────────────────────────────────────── */

/**
 * The not-connected gate (COMMAND-SPEC C2). B1's `toolkit.requireToken` is the production
 * implementation; this default is the same contract expressed against the frozen `ToolCtx`,
 * so T1 is correct on its own and gets *more* correct (consent auto-open) once B5 injects.
 */
export type T1TokenGate = (ctx: ToolCtx) => Promise<TokenGate>;

/**
 * The default is deliberately side-effect-free (it opens no browser tab), so T1 is testable
 * and correct on its own. **B5 wires the production one in a single line at assembly:**
 *
 * ```ts
 * import { requireToken } from './toolkit.ts';
 * useTokenGate(requireToken);   // adds C2's consent auto-open, under B1's cooldown guard
 * ```
 */
async function defaultTokenGate(ctx: ToolCtx): Promise<TokenGate> {
  try {
    const token = await ctx.getToken();
    if (typeof token === 'string' && token !== '') return { ok: true, token };
  } catch (error) {
    const code = slackErrorCode(error);
    // A dead token is the same user-visible situation as no token: reconnect, don't error.
    if (code !== null && !AUTH_FAILURES.has(code) && code !== 'not_connected') throw error;
  }
  return { ok: false, result: notConnectedOutput(ctx) };
}

let tokenGate: T1TokenGate = defaultTokenGate;

/** B5 injects B1's `requireToken` here at assembly; tests use it to drive the blocked path. */
export function useTokenGate(gate: T1TokenGate): void {
  tokenGate = gate;
}

export function resetTokenGate(): void {
  tokenGate = defaultTokenGate;
}

/** Wall clock, in ms. A seam so the catch-up lookback and the send stamp are testable. */
let clock: () => number = () => Date.now();

export function useClock(fn: () => number): void {
  clock = fn;
}

export function resetClock(): void {
  clock = () => Date.now();
}

/* ────────────────────────────────── narrowing helpers ────────────────────────────────── */

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

function intInRange(value: unknown, fallback: number, low: number, high: number): number {
  const parsed = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(high, Math.max(low, Math.trunc(parsed)));
}

/* ─────────────────────────────── provider failure mapping ─────────────────────────────── */

/**
 * Slack refusals that mean "this token is done" rather than "that request was wrong" —
 * B1's list, not a second copy of it, plus the engine's own two codes for the same state.
 */
const AUTH_FAILURES = new Set([...AUTH_FAILURE_CODES, 'expired_or_revoked', 'refresh_failed']);

/**
 * Slack's own error string out of whatever the toolkit threw. B1's `SlackError` is the
 * expected shape; the field sweep keeps this correct against a vendored/renamed copy, and
 * the message fallback keeps it correct against a plain `Error`. Never a paraphrase — the
 * string that comes out is the string Slack sent.
 */
export function slackErrorCode(error: unknown): string | null {
  const shaped = asRecord(error);
  for (const key of ['slackError', 'error', 'reason', 'code']) {
    const value = shaped[key];
    if (typeof value === 'string' && value !== '') return value;
  }
  const message = typeof shaped['message'] === 'string' ? shaped['message'] : '';
  const match = /(?:slack (?:refused|error)|not_connected)[:\s]*([a-z_]+)?/i.exec(message);
  if (match !== null) return match[1] ?? 'not_connected';
  return null;
}

function retryAfterOf(error: unknown): number | undefined {
  const shaped = asRecord(error);
  const value = shaped['retryAfterSec'] ?? shaped['retryAfter'] ?? shaped['retry_after'];
  const parsed = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

/* ────────────────────────────────────── card seam ────────────────────────────────────── */

/**
 * Compose a card, or degrade to no card. `cards.ts` is B4's file and may not exist yet in a
 * parallel build; a T1 handler must still answer with its facts either way.
 */
function safeCard(ctx: ToolCtx, name: keyof FrozenCards, data: unknown): string {
  try {
    const fn = ctx.cards?.[name] as ((payload: unknown) => unknown) | undefined;
    if (typeof fn !== 'function') return '';
    const rendered = fn(data);
    return typeof rendered === 'string' ? rendered : '';
  } catch {
    return '';
  }
}

function notConnectedOutput(ctx: ToolCtx): ToolOutput {
  return {
    content: { error: 'not_connected' },
    card: safeCard(ctx, 'notConnected', { reason: 'not_connected' }),
  };
}

function errorOutput(ctx: ToolCtx, data: Record<string, unknown>): ToolOutput {
  return { content: { error: data['kind'], ...data }, card: safeCard(ctx, 'errorCard', data) };
}

function failureOutput(ctx: ToolCtx, error: unknown): ToolOutput {
  const code = slackErrorCode(error);
  if (code !== null && (AUTH_FAILURES.has(code) || code === 'not_connected')) return notConnectedOutput(ctx);
  if (code === 'ratelimited' || code === 'rate_limited') {
    const retryAfter = retryAfterOf(error);
    return errorOutput(ctx, {
      kind: 'rate_limited',
      ...(retryAfter === undefined ? {} : { retry_after: retryAfter }),
    });
  }
  // Slack's own word, verbatim (deck row `provider_error` quotes it) — never our paraphrase.
  return errorOutput(ctx, { kind: 'provider_error', reason: code ?? 'unknown_error' });
}

/* ─────────────────────────────────── Slack primitives ─────────────────────────────────── */

const CATCH_UP_LOOKBACK_DEFAULT_MINUTES = 240;
const CATCH_UP_MAX_CONVERSATIONS = 20;
const CATCH_UP_MESSAGES_PER_CONVERSATION = 5;
const CATCH_UP_CONVERSATIONS_IN_CONTENT = 5;
/** UI-SPEC §3.3 digest budget: 2 channel groups × 3 messages, everything else is `+N more`. */
const DIGEST_GROUPS = 2;
const DIGEST_MESSAGES_PER_GROUP = 3;
const SEARCH_RESULTS_SHOWN = 5;

/** Slack's join/leave/topic housekeeping. Real content only, deterministically filtered. */
const NOISE_SUBTYPES = new Set([
  'channel_join',
  'channel_leave',
  'group_join',
  'group_leave',
  'channel_topic',
  'channel_purpose',
  'channel_name',
  'channel_archive',
  'channel_unarchive',
]);

export interface CatchUpMessage {
  author?: string;
  author_id?: string;
  text: string;
  ts: string;
}

async function history(ctx: ToolCtx, channel: string, params: Record<string, unknown>): Promise<CatchUpMessage[]> {
  const body = asRecord(await ctx.slackFetch('conversations.history', { channel, ...params }));
  const messages: CatchUpMessage[] = [];
  for (const entry of asArray(body['messages'])) {
    const message = asRecord(entry);
    const subtype = str(message['subtype']);
    if (subtype !== undefined && NOISE_SUBTYPES.has(subtype)) continue;
    const text = typeof message['text'] === 'string' ? message['text'] : '';
    if (text.trim() === '') continue;
    const ts = str(message['ts']);
    const authorId = str(message['user']) ?? str(message['bot_id']);
    messages.push({
      // Verbatim. The card clips; nothing here rewrites a word of what someone said.
      text,
      ts: ts ?? '',
      ...(authorId === undefined ? {} : { author_id: authorId }),
    });
  }
  return messages;
}

/* ────────────────────────────── deterministic name resolution ──────────────────────────────
 *
 * Lives in `resolve.ts` (Phase D): one directory cache, one five-tier ladder, shared with T2.
 * What stays here is only the miss surface — the disambiguation card data.
 */

/** Candidate rows carry the human `name` first; `label` mirrors it for the card renderer. */
function candidateRow(candidate: CandidateSummary): Record<string, unknown> {
  return { ...candidate, label: candidate.name };
}

/**
 * The block card. Two distinct facts, kept distinct: "several of these exist, which one?"
 * and "no such thing — here are the real names near it." Neither one acts.
 */
function missOutput(ctx: ToolCtx, miss: ResolveMiss): ToolOutput {
  return errorOutput(ctx, {
    kind: miss.code,
    query: miss.query,
    candidates: miss.candidates.map(candidateRow),
  });
}

/* ──────────────────────────────────── message shaping ──────────────────────────────────── */

function withAuthors(messages: CatchUpMessage[], people: Map<string, Person>): CatchUpMessage[] {
  return messages.map((message) => {
    const person = message.author_id === undefined ? undefined : people.get(message.author_id);
    // No author on file ⇒ no author field. A card must never print a name Slack didn't give.
    return person === undefined ? message : { ...message, author: person.display };
  });
}

/**
 * Human label for a listed conversation. NAME-RULE P2-15: a DM whose peer the directory
 * cannot name falls back to the NEUTRAL word, never `conversation.user` / `conversation.id` —
 * an id is not a display value anywhere.
 */
function conversationLabel(conversation: Conversation, people: Map<string, Person>): string {
  if (conversation.kind === 'dm') {
    const person = conversation.user === undefined ? undefined : people.get(conversation.user);
    return person?.display ?? SCARD.kind_dm;
  }
  const name = conversation.name;
  if (name === undefined) return conversation.kind === 'channel' ? SCARD.neutral_channel : SCARD.kind_group_dm;
  return conversation.kind === 'channel' ? `#${name}` : name;
}

/**
 * One message, human-first: `author` and `text` and `time` lead (the model quotes what comes
 * first), `ts` and `author_id` ride at the machine tail. `ts` keeps its exact key — the
 * grounding registry and the react/reply args key on it. `text` is decoded at this seam
 * (CARDS-SPEC-R2 §4.3): Slack's `<@U…>`/`<#C…|name>`/`<url|label>` tokens and entities become
 * human words once, so cards and spoken content never see a machine token.
 */
function messagePayload(message: CatchUpMessage, directory: Directory): Record<string, unknown> {
  const time = message.ts === '' ? '' : humanTime(message.ts, clock());
  return {
    ...(message.author === undefined ? {} : { author: message.author }),
    text: decodeSlackText(directory, message.text),
    ...(time === '' ? {} : { time }),
    ...(message.ts === '' ? {} : { ts: message.ts }),
    ...(message.author_id === undefined ? {} : { author_id: message.author_id }),
  };
}

/* ──────────────────────────────────────── handlers ──────────────────────────────────────── */

/**
 * "What did I miss?" — the differentiator (COMMAND-SPEC §2 T1 #3).
 *
 * One `conversations.list`, one `users.list`, one `conversations.history` per conversation the
 * user is in, then arithmetic: rank by mentions of you, then by recency. Nothing is summarized;
 * the digest carries the messages themselves.
 */
async function catchUp(args: any, ctx: ToolCtx): Promise<ToolOutput> {
  const options = asRecord(args);
  const lookbackMinutes = intInRange(options['lookback_minutes'], CATCH_UP_LOOKBACK_DEFAULT_MINUTES, 5, 24 * 60);
  const oldest = ((clock() - lookbackMinutes * 60_000) / 1000).toFixed(6);

  const directory = await getDirectory(ctx);
  const { me, conversations, people } = directory;

  const active = conversations
    .filter((conversation) => conversation.is_member)
    .slice(0, CATCH_UP_MAX_CONVERSATIONS);

  const groups: {
    conversation: Conversation;
    label: string;
    mentions: number;
    messages: CatchUpMessage[];
    latest: number;
  }[] = [];

  let skippedUnreadable = 0;
  for (const conversation of active) {
    // Slackbot's DM refuses conversations.history for user tokens (channel_not_found),
    // and any single unreadable conversation must cost the digest one group, not the
    // whole answer — a catch-up that dies on Slackbot is worse than an incomplete one.
    let raw: CatchUpMessage[];
    try {
      raw = await history(ctx, conversation.id, {
        oldest,
        limit: CATCH_UP_MESSAGES_PER_CONVERSATION * 2,
      });
    } catch {
      skippedUnreadable += 1;
      continue;
    }
    // Your own messages are not something you missed.
    const fromOthers = raw.filter((message) => message.author_id !== me.user_id);
    if (fromOthers.length === 0) continue;
    const named = withAuthors(fromOthers.slice(0, CATCH_UP_MESSAGES_PER_CONVERSATION), people);
    const mentionToken = me.user_id === undefined ? null : `<@${me.user_id}>`;
    const mentions =
      mentionToken === null
        ? 0
        : fromOthers.reduce((total, message) => total + message.text.split(mentionToken).length - 1, 0);
    groups.push({
      conversation,
      label: conversationLabel(conversation, people),
      mentions,
      // Slack returns newest-first; a channel reads oldest→newest, like the real client.
      messages: [...named].reverse(),
      latest: Number.parseFloat(fromOthers[0]?.ts ?? '0') || 0,
    });
  }

  groups.sort((a, b) => (b.mentions - a.mentions !== 0 ? b.mentions - a.mentions : b.latest - a.latest));

  const shown = groups.slice(0, DIGEST_GROUPS);
  const hiddenMessages =
    groups.reduce((total, group) => total + group.messages.length, 0) -
    shown.reduce((total, group) => total + Math.min(group.messages.length, DIGEST_MESSAGES_PER_GROUP), 0);

  const card = safeCard(ctx, 'digest', {
    ...(me.team === undefined ? {} : { workspace: me.team }),
    groups: shown.map((group) => ({
      channel: group.label,
      kind: group.conversation.kind,
      count: group.messages.length,
      mentions: group.mentions,
      messages: group.messages.slice(-DIGEST_MESSAGES_PER_GROUP).map((message) => messagePayload(message, directory)),
    })),
    more: {
      messages: Math.max(0, hiddenMessages),
      conversations: Math.max(0, groups.length - shown.length),
    },
  });

  return {
    content: {
      lookback_minutes: lookbackMinutes,
      conversations: groups.slice(0, CATCH_UP_CONVERSATIONS_IN_CONTENT).map((group) => ({
        channel: group.label,
        kind: group.conversation.kind,
        mentions: group.mentions,
        message_count: group.messages.length,
        messages: group.messages.map((message) => messagePayload(message, directory)),
        channel_id: group.conversation.id,
      })),
      total_conversations_with_activity: groups.length,
      total_messages: groups.reduce((total, group) => total + group.messages.length, 0),
      ...(skippedUnreadable === 0 ? {} : { skipped_unreadable_conversations: skippedUnreadable }),
      ...(me.team === undefined ? {} : { workspace: me.team }),
    },
    card,
  };
}

/** Read any conversation by spoken name — channels, private channels, group DMs, open DMs. */
async function readConversation(
  ctx: ToolCtx,
  spoken: string,
  limit: number,
  scope: ResolveScope,
): Promise<ToolOutput> {
  const resolved = await resolveSendTarget(ctx, spoken, scope);
  if (!resolved.ok) return missOutput(ctx, resolved);
  const target = resolved.target;

  const directory = await getDirectory(ctx);
  const me = directory.me;
  const messages = withAuthors(await history(ctx, target.channel_id, { limit }), directory.people);
  const latest = messages[0];

  // Names lead; ids ride at the machine tail (RESOLVER-DESIGN §5). The model quotes the
  // label back into send/reply args, which is what puts "#general" on the confirmation card.
  const base = {
    channel: target.label,
    ...(me.team === undefined ? {} : { workspace: me.team }),
  };
  const machine = { channel_id: target.channel_id, channel_kind: target.kind };

  if (latest === undefined) {
    return {
      content: { ...base, messages: [], empty: true, ...machine },
      card: safeCard(ctx, 'emptyChannel', { channel: target.label, ...(me.team === undefined ? {} : { workspace: me.team }) }),
    };
  }

  return {
    content: { ...base, messages: messages.map((message) => messagePayload(message, directory)), ...machine },
    card: safeCard(ctx, 'messageRow', {
      channel: target.label,
      ...(me.team === undefined ? {} : { workspace: me.team }),
      ...messagePayload(latest, directory),
    }),
  };
}

async function readChannel(args: any, ctx: ToolCtx): Promise<ToolOutput> {
  const options = asRecord(args);
  const spoken = str(options['channel']) ?? str(options['name']) ?? '';
  if (spoken === '') return errorOutput(ctx, { kind: 'missing_parameter', parameter: 'channel' });
  return readConversation(ctx, spoken, intInRange(options['limit'], 1, 1, 20), 'any');
}

async function readDm(args: any, ctx: ToolCtx): Promise<ToolOutput> {
  const options = asRecord(args);
  const spoken = str(options['person']) ?? str(options['user']) ?? '';
  if (spoken === '') return errorOutput(ctx, { kind: 'missing_parameter', parameter: 'person' });
  return readConversation(ctx, spoken, intInRange(options['limit'], 1, 1, 20), 'person');
}

/**
 * The gated one (COMMAND-SPEC §2 T1 #5). Two preflight facts, both provable on the card:
 * the destination is a conversation Slack listed, and the text is the literal dictated string.
 */
async function sendMessage(args: any, ctx: ToolCtx): Promise<ToolOutput> {
  const options = asRecord(args);
  const spoken = str(options['target']) ?? str(options['channel']) ?? '';
  // NOT `str()`: a message of "0" is a real message. Only a non-string or empty text blocks.
  const text = typeof options['text'] === 'string' ? options['text'] : '';
  if (spoken === '') return errorOutput(ctx, { kind: 'missing_parameter', parameter: 'target' });
  if (text.trim() === '') return errorOutput(ctx, { kind: 'missing_parameter', parameter: 'text' });

  const resolved = await resolveSendTarget(ctx, spoken, 'any');
  if (!resolved.ok) return missOutput(ctx, resolved);
  const target = resolved.target;

  const directory = await getDirectory(ctx);
  const me = directory.me;
  const posted = asRecord(
    // Verbatim text, one hop from the argument to Slack. No cleanup, no paraphrase step exists.
    await ctx.slackFetch('chat.postMessage', { channel: target.channel_id, text }, { httpMethod: 'POST' }),
  );
  // Slack's own ts or none: a fabricated timestamp would violate the no-fabrication invariant.
  const ts = str(posted['ts']);
  const time = ts === undefined ? '' : humanTime(ts, clock());
  // NAME-RULE L5: the directory ladder first; the legacy handle only as the last resort.
  const sender = labelForUser(directory, me.user_id) ?? me.user;

  return {
    content: {
      sent: true,
      action: 'message_sent',
      to: target.label,
      text,
      ...(time === '' ? {} : { time }),
      ...(me.team === undefined ? {} : { workspace: me.team }),
      kind: target.kind,
      channel_id: target.channel_id,
      ...(ts === undefined ? {} : { ts }),
    },
    card: safeCard(ctx, 'sendConfirm', {
      destination: target.label,
      kind: target.kind,
      ...(me.team === undefined ? {} : { workspace: me.team }),
      ...(sender === undefined ? {} : { author: sender }),
      text,
      ...(ts === undefined ? {} : { ts }),
    }),
  };
}

/** `search.messages` — user-token-only, which is the architecture proof point (COMMAND-SPEC §3). */
async function search(args: any, ctx: ToolCtx): Promise<ToolOutput> {
  const options = asRecord(args);
  const query = typeof options['query'] === 'string' ? options['query'] : '';
  if (query.trim() === '') return errorOutput(ctx, { kind: 'missing_parameter', parameter: 'query' });
  const count = intInRange(options['count'], SEARCH_RESULTS_SHOWN, 1, 20);

  // The query goes over the wire exactly as spoken — the card shows it back for the same reason.
  const body = asRecord(await ctx.slackFetch('search.messages', { query, count }));
  const matches = asArray(asRecord(body['messages'])['matches']);
  const total = Number.parseInt(String(asRecord(body['messages'])['total'] ?? matches.length), 10);

  // NAME-RULE L1 (the "icynd2777" bug): the hit's `username` is Slack's LEGACY handle and is
  // never read. The author is `match.user` resolved through the directory ladder, or absent.
  const directory = await getDirectory(ctx);
  const results = matches.map((entry) => {
    const match = asRecord(entry);
    const channel = asRecord(match['channel']);
    const channelId = str(channel['id']);
    const channelName = str(channel['name']);
    // L2: prefer the directory label (right for private/DM hits); `#name` from the payload
    // is the fallback when the id is unknown to the directory. Never the raw id.
    const channelLabel =
      (channelId === undefined ? undefined : labelForChannel(directory, channelId)) ??
      (channelName === undefined ? undefined : `#${channelName}`);
    const authorId = str(match['user']);
    const author = labelForUser(directory, authorId);
    const ts = str(match['ts']);
    const time = ts === undefined ? '' : humanTime(ts, clock());
    return {
      ...(author === undefined ? {} : { author }),
      ...(channelLabel === undefined ? {} : { channel: channelLabel }),
      text: decodeSlackText(directory, typeof match['text'] === 'string' ? match['text'] : ''),
      ...(time === '' ? {} : { time }),
      ...(ts === undefined ? {} : { ts }),
      ...(authorId === undefined ? {} : { author_id: authorId }),
      ...(channelId === undefined ? {} : { channel_id: channelId }),
      ...(str(match['permalink']) === undefined ? {} : { permalink: str(match['permalink']) as string }),
    };
  });

  return {
    content: { query, total: Number.isFinite(total) ? total : results.length, results },
    card: safeCard(ctx, 'searchResults', {
      query,
      ...(directory.me.team === undefined ? {} : { workspace: directory.me.team }),
      results: results.slice(0, SEARCH_RESULTS_SHOWN),
      more: Math.max(0, (Number.isFinite(total) ? total : results.length) - Math.min(results.length, SEARCH_RESULTS_SHOWN)),
    }),
  };
}

/** Lookup, not action: shows every plausible match instead of choosing one (COMMAND-SPEC §2 #7). */
async function find(args: any, ctx: ToolCtx): Promise<ToolOutput> {
  const options = asRecord(args);
  const query = str(options['query']) ?? str(options['name']) ?? '';
  if (query === '') return errorOutput(ctx, { kind: 'missing_parameter', parameter: 'query' });
  const kindArg = str(options['kind']);
  const scope: ResolveScope = kindArg === 'channel' || kindArg === 'person' ? kindArg : 'any';

  const resolved = await resolveConversation(ctx, query, scope);
  const matches: CandidateSummary[] = resolved.ok ? [candidateSummary(resolved.target)] : resolved.candidates;
  const workspace = (await getDirectory(ctx)).me.team; // cached: resolveConversation just walked it

  return {
    content: { query, kind: scope, matches, match_count: matches.length },
    card: safeCard(ctx, 'searchResults', {
      query,
      ...(workspace === undefined ? {} : { workspace }),
      results: matches.slice(0, SEARCH_RESULTS_SHOWN).map((candidate) => ({
        author: candidate.name,
        kind: candidate.kind,
        text: '',
      })),
      more: Math.max(0, matches.length - SEARCH_RESULTS_SHOWN),
    }),
  };
}

/* ─────────────────────────────────────── the table ─────────────────────────────────────── */

/** Gate + failure mapping, applied identically to every T1 tool. A handler never throws. */
function guard(run: (args: any, ctx: ToolCtx) => Promise<ToolOutput>) {
  return async function handler(args: any, ctx: ToolCtx): Promise<ToolOutput> {
    try {
      const gate = await tokenGate(ctx);
      if (!gate.ok) return gate.result;
      return await run(args, ctx);
    } catch (error) {
      return failureOutput(ctx, error);
    }
  };
}

export const T1_TOOLS: ToolDef[] = [
  {
    name: 'slack_catch_up',
    description:
      'Cross-channel Slack digest of what arrived recently, grouped by channel or DM and ranked by mentions of you then recency. Quotes the messages verbatim, no summary is generated. Use when the user asks "what did I miss", "catch me up on Slack", or "anything new". Read-only.',
    inputSchema: {
      type: 'object',
      properties: {
        lookback_minutes: {
          type: 'integer',
          minimum: 5,
          maximum: 1440,
          description: 'How far back to look. Defaults to 240 (4 hours).',
        },
      },
    },
    confirm: false,
    handler: guard(catchUp),
  },
  {
    name: 'slack_read_channel',
    description:
      'Read the most recent message(s) in a Slack channel, private channel, group DM or DM, named by the user. Resolves the spoken name against the real conversation list and asks which one when the name is ambiguous. Use when the user asks what is in a channel or what someone said there. Read-only.',
    inputSchema: {
      type: 'object',
      properties: {
        channel: {
          type: 'string',
          minLength: 1,
          description: "Channel name, like #general, or a person's name for a DM. Also accepts a Slack channel ID.",
        },
        limit: { type: 'integer', minimum: 1, maximum: 20, description: 'How many recent messages. Default 1.' },
      },
      required: ['channel'],
    },
    confirm: false,
    handler: guard(readChannel),
  },
  {
    name: 'slack_read_dm',
    description:
      'Read the most recent message(s) in the direct message conversation with one person, opening the DM if it does not exist yet. Use when the user asks about their DM with someone by name. Read-only.',
    inputSchema: {
      type: 'object',
      properties: {
        person: { type: 'string', minLength: 1, description: "Person's name, like Maya. Also accepts a Slack user ID." },
        limit: { type: 'integer', minimum: 1, maximum: 20, description: 'How many recent messages. Default 1.' },
      },
      required: ['person'],
    },
    confirm: false,
    handler: guard(readDm),
  },
  {
    name: 'slack_send_message',
    description:
      'Send a Slack message to a channel or person. The destination must resolve to exactly one real conversation and the text is posted exactly as dictated, nothing is rewritten. Use when the user says to tell, message or send something to a channel or person.',
    inputSchema: {
      type: 'object',
      properties: {
        target: {
          type: 'string',
          minLength: 1,
          description: "Channel name, like #general, or a person's name, like Maya. Also accepts a Slack channel or user ID.",
        },
        text: { type: 'string', minLength: 1, description: 'The literal message text the user dictated.' },
      },
      required: ['target', 'text'],
    },
    confirm: true,
    handler: guard(sendMessage),
  },
  {
    name: 'slack_search',
    description:
      'Search Slack messages with Slack’s own search (search.messages, which only a user token can call), passing the query verbatim. Use when the user asks to search Slack or find what someone said about something. Read-only.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', minLength: 1, description: 'The search query, word for word as the user said it.' },
        count: { type: 'integer', minimum: 1, maximum: 20, description: 'How many results to fetch. Default 5.' },
      },
      required: ['query'],
    },
    confirm: false,
    handler: guard(search),
  },
  {
    name: 'slack_find',
    description:
      'Find Slack channels and people by name and list every plausible match rather than picking one. Use when the user asks whether a channel exists, who someone is, or what channels they are in. Read-only.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', minLength: 1, description: 'Name or fragment of a channel or person.' },
        kind: {
          type: 'string',
          enum: ['any', 'channel', 'person'],
          description: 'Restrict the lookup to channels or people. Default any.',
        },
      },
      required: ['query'],
    },
    confirm: false,
    handler: guard(find),
  },
];

export const T1_TOOL_NAMES = T1_TOOLS.map((tool) => tool.name);
