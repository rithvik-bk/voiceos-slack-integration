/**
 * RESOLVE — one name-resolution layer for every Slack tool (Phase D, builder B1).
 *
 * Single owner of name→ID and ID→name for the whole integration, per
 * `docs/design/rehaul/RESOLVER-DESIGN.md` (adopted as final by DESIGN-SPEC §2).
 * `tools-t1.ts` and `tools-t2.ts` import this file and carry no private resolver.
 *
 * Four properties, all testable:
 *
 *  1. **One directory, cached.** `conversations.list` + `users.list` + `auth.test` are walked
 *     once per 60 s (`DIRECTORY_TTL_MS`), shared across concurrent callers via one in-flight
 *     promise. A voice burst costs one walk of each list, not six.
 *  2. **Five-tier ladder, never a coin flip.** id passthrough → exact → normalized →
 *     substring → miss-with-nearest-names. Two-plus hits in a tier is an ambiguity returned
 *     as data; nothing here ever picks "the closest string" silently.
 *  3. **Human labels are the only user-visible strings.** `Target.label` is `#general` or
 *     `Maya`; raw ids ride in machine fields (`channel_id`/`user_id`) no card renders.
 *  4. **Zero LLM, zero runtime deps.** node builtins and `ToolCtx` only.
 */

import type { ToolCtx } from './toolkit.ts';

/* ─────────────────────────────────────── entities ─────────────────────────────────────── */

export type EntityKind = 'channel' | 'group_dm' | 'dm' | 'person';
export type ResolveScope = 'any' | 'channel' | 'person';

export interface Conversation {
  id: string; // C…/G…/D…
  name?: string;
  kind: 'channel' | 'dm' | 'group_dm';
  is_member: boolean;
  user?: string; // DM peer's U… id
}

export interface Person {
  id: string; // U…/W…
  handle: string; // slack @name
  display: string; // what cards show
  aliases: string[]; // matched, never shown
}

export interface Target {
  id: string; // conversation id, or U… when kind === 'person' (DM not open yet)
  label: string; // '#general' | 'Maya' — the ONLY string a user-visible surface may show
  kind: EntityKind;
  user_id?: string;
  aliases?: string[];
}

/* ─────────────────────────────────── the directory cache ─────────────────────────────────── */

export interface Directory {
  fetchedAt: number; // ms epoch, from the injected clock
  conversations: Conversation[];
  people: Map<string, Person>; // by user id
  pool: Target[]; // prebuilt match pool (channels + open DMs + people)
  channelsById: Map<string, Target>; // C…/G…/D… → Target (reverse lookup for read reshape)
  me: { user_id?: string; user?: string; team?: string }; // auth.test, cached with the lists
}

export const DIRECTORY_TTL_MS = 60_000;

/** A `target_not_found` older than this triggers one refetch before the miss is returned. */
const MISS_RETRY_MS = 10_000;

const PAGE_LIMIT = 200;
const MAX_PAGES = 5;
const CANDIDATES_SHOWN = 5;
const ALL_CONVERSATION_TYPES = 'public_channel,private_channel,mpim,im';

let clock: () => number = () => Date.now();
let cache: Directory | null = null;
let inFlight: Promise<Directory> | null = null;

export function useDirectoryClock(fn: () => number): void {
  clock = fn;
}

export function resetDirectoryClock(): void {
  clock = () => Date.now();
}

/** Clears cache + in-flight promise between tests. */
export function resetDirectory(): void {
  cache = null;
  inFlight = null;
}

/** Drop the cache. Called by slack_disconnect and after a write fails with channel_not_found/user_not_found. */
export function invalidateDirectory(): void {
  cache = null;
}

/* ─────────────────────────────── typed readers (local only) ─────────────────────────────── */

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/* ─────────────────────────────────── the Slack walks ─────────────────────────────────── */

/** One paginated `conversations.list` walk. Cursor exhaustion, not an unbounded loop. */
async function listConversations(ctx: ToolCtx): Promise<Conversation[]> {
  const found: Conversation[] = [];
  let cursor = '';
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const params: Record<string, unknown> = {
      types: ALL_CONVERSATION_TYPES,
      exclude_archived: true,
      limit: PAGE_LIMIT,
    };
    if (cursor !== '') params['cursor'] = cursor;
    const body = asRecord(await ctx.slackFetch('conversations.list', params));
    for (const entry of asArray(body['channels'])) {
      const channel = asRecord(entry);
      const id = str(channel['id']);
      if (id === undefined) continue;
      const isIm = channel['is_im'] === true;
      const isMpim = channel['is_mpim'] === true;
      const name = str(channel['name']);
      found.push({
        id,
        ...(name === undefined ? {} : { name }),
        kind: isIm ? 'dm' : isMpim ? 'group_dm' : 'channel',
        // DMs have no membership flag; a DM that is listed is one you are in.
        is_member: isIm || isMpim ? true : channel['is_member'] === true,
        ...(str(channel['user']) === undefined ? {} : { user: str(channel['user']) as string }),
      });
    }
    const next = str(asRecord(body['response_metadata'])['next_cursor']);
    if (next === undefined) break;
    cursor = next;
  }
  return found;
}

/**
 * One paginated `users.list` walk, indexed by id — one call feeds every author name on a card.
 *
 * THE DISPLAY LADDER (NAME-RULE §1, the single owner — no other file may rank name fields):
 * `display_name_normalized` → `real_name_normalized` → `display_name` → `real_name` →
 * top-level `real_name` → legacy `name` (absolute last resort) → NOTHING. A member with no
 * resolvable name is skipped entirely: no name to match on, no name a surface may show, and
 * an id is NEVER a display value.
 */
async function listUsers(ctx: ToolCtx): Promise<Map<string, Person>> {
  const people = new Map<string, Person>();
  let cursor = '';
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const params: Record<string, unknown> = { limit: PAGE_LIMIT };
    if (cursor !== '') params['cursor'] = cursor;
    const body = asRecord(await ctx.slackFetch('users.list', params));
    for (const entry of asArray(body['members'])) {
      const member = asRecord(entry);
      const id = str(member['id']);
      if (id === undefined || member['deleted'] === true) continue;
      const profile = asRecord(member['profile']);
      const display =
        str(profile['display_name_normalized']) ??
        str(profile['real_name_normalized']) ??
        str(profile['display_name']) ??
        str(profile['real_name']) ??
        str(member['real_name']) ??
        str(member['name']);
      if (display === undefined) continue;
      const aliases = [str(member['name']), str(profile['display_name']), str(profile['real_name']), str(member['real_name'])].filter(
        (alias): alias is string => alias !== undefined && alias !== display,
      );
      people.set(id, { id, handle: str(member['name']) ?? id, display, aliases: [...new Set(aliases)] });
    }
    const next = str(asRecord(body['response_metadata'])['next_cursor']);
    if (next === undefined) break;
    cursor = next;
  }
  return people;
}

/** `auth.test` — who this token is. No scope required; the only source of the sender identity. */
async function whoAmI(ctx: ToolCtx): Promise<Directory['me']> {
  const body = asRecord(await ctx.slackFetch('auth.test'));
  const userId = str(body['user_id']);
  const user = str(body['user']);
  const team = str(body['team']);
  return {
    ...(userId === undefined ? {} : { user_id: userId }),
    ...(user === undefined ? {} : { user }),
    ...(team === undefined ? {} : { team }),
  };
}

/* ─────────────────────────────────── pool construction ─────────────────────────────────── */

function channelTarget(conversation: Conversation): Target {
  const name = conversation.name ?? conversation.id;
  return {
    id: conversation.id,
    label: conversation.kind === 'channel' ? `#${name}` : name,
    kind: conversation.kind,
  };
}

function personTarget(person: Person): Target {
  return {
    id: person.id,
    label: person.display,
    kind: 'person',
    user_id: person.id,
    ...(person.aliases.length === 0 ? {} : { aliases: person.aliases }),
  };
}

function buildDirectory(
  conversations: Conversation[],
  people: Map<string, Person>,
  me: Directory['me'],
  fetchedAt: number,
): Directory {
  const pool: Target[] = [];
  const channelsById = new Map<string, Target>();
  const openDmUsers = new Set<string>();

  for (const conversation of conversations) {
    if (conversation.kind === 'dm') {
      const person = conversation.user === undefined ? undefined : people.get(conversation.user);
      if (person === undefined) continue;
      const target: Target = {
        id: conversation.id,
        label: person.display,
        kind: 'dm',
        user_id: person.id,
        ...(person.aliases.length === 0 ? {} : { aliases: person.aliases }),
      };
      channelsById.set(conversation.id, target);
      openDmUsers.add(person.id);
      pool.push(target);
      continue;
    }
    const target = channelTarget(conversation);
    // Reverse lookup covers every conversation Slack listed; the MATCH pool only carries
    // channels you are a member of (you cannot read or post the rest by name anyway).
    channelsById.set(conversation.id, target);
    if (conversation.kind === 'channel' && !conversation.is_member) continue;
    pool.push(target);
  }

  for (const person of people.values()) {
    if (openDmUsers.has(person.id)) continue;
    pool.push(personTarget(person));
  }

  return { fetchedAt, conversations, people, pool, channelsById, me };
}

/** Serve from cache when younger than DIRECTORY_TTL_MS, else refetch. Concurrent callers share one in-flight fetch. */
export function getDirectory(ctx: ToolCtx, opts: { maxAgeMs?: number } = {}): Promise<Directory> {
  const maxAge = opts.maxAgeMs ?? DIRECTORY_TTL_MS;
  const now = clock();
  if (cache !== null && now - cache.fetchedAt < maxAge) return Promise.resolve(cache);
  if (inFlight !== null) return inFlight;

  inFlight = (async () => {
    const [conversations, people, me] = await Promise.all([
      listConversations(ctx),
      listUsers(ctx),
      whoAmI(ctx),
    ]);
    const built = buildDirectory(conversations, people, me, clock());
    cache = built;
    inFlight = null;
    return built;
  })();
  // A rejected fetch clears the in-flight slot so the next call retries. No negative caching.
  inFlight = inFlight.catch((error: unknown) => {
    inFlight = null;
    throw error;
  });
  return inFlight;
}

/* ─────────────────────────────────── the match ladder ─────────────────────────────────── */

const CONVERSATION_ID = /^[CGD][A-Z0-9]{4,}$/;
const PERSON_ID = /^[UW][A-Z0-9]{4,}$/;

function normalizeLoose(value: string): string {
  return value.trim().toLowerCase().replace(/^[#@]/, '');
}

function normalizeTight(value: string): string {
  return normalizeLoose(value).replace(/[^a-z0-9]/g, '');
}

/** Levenshtein, bounded — used ONLY to order suggestions, never to auto-pick a target. */
function editDistance(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length > 40 || b.length > 40) return Math.abs(a.length - b.length);
  let previous = Array.from({ length: b.length + 1 }, (_unused, index) => index);
  for (let i = 1; i <= a.length; i += 1) {
    const current = [i];
    for (let j = 1; j <= b.length; j += 1) {
      const substitution = (previous[j - 1] ?? 0) + (a[i - 1] === b[j - 1] ? 0 : 1);
      const deletion = (previous[j] ?? 0) + 1;
      const insertion = (current[j - 1] ?? 0) + 1;
      current.push(Math.min(substitution, deletion, insertion));
    }
    previous = current;
  }
  return previous[b.length] ?? Math.max(a.length, b.length);
}

function namesOf(target: Target): string[] {
  return [target.label, ...(target.aliases ?? [])];
}

function dedupeTargets(targets: Target[]): Target[] {
  const seen = new Set<string>();
  const unique: Target[] = [];
  for (const target of targets) {
    const key = `${target.kind}:${target.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(target);
  }
  return unique;
}

type LadderHit = { tier: 'exact' | 'normalized' | 'substring'; matches: Target[] } | null;

function runLadder(spoken: string, pool: Target[]): LadderHit {
  const loose = normalizeLoose(spoken);
  const tight = normalizeTight(spoken);
  if (loose === '') return null;

  const tiers: Array<{ tier: 'exact' | 'normalized' | 'substring'; matches: Target[] }> = [
    {
      tier: 'exact',
      matches: pool.filter((target) => namesOf(target).some((name) => normalizeLoose(name) === loose)),
    },
    {
      tier: 'normalized',
      matches: pool.filter((target) => namesOf(target).some((name) => normalizeTight(name) === tight)),
    },
    {
      tier: 'substring',
      matches: pool.filter((target) => namesOf(target).some((name) => normalizeTight(name).includes(tight))),
    },
  ];
  for (const entry of tiers) {
    const unique = dedupeTargets(entry.matches);
    if (unique.length > 0) return { tier: entry.tier, matches: unique };
  }
  return null;
}

/** Nearest real names by bounded Levenshtein — suggestions on a card, never acted on. */
function nearestTargets(spoken: string, pool: Target[]): Target[] {
  const tight = normalizeTight(spoken);
  if (tight === '') return [];
  return dedupeTargets(
    [...pool]
      .map((target) => ({
        target,
        distance: Math.min(...namesOf(target).map((name) => editDistance(normalizeTight(name), tight))),
      }))
      .filter((entry) => entry.distance <= Math.max(2, Math.round(tight.length / 3)))
      .sort((a, b) => a.distance - b.distance)
      .map((entry) => entry.target),
  ).slice(0, CANDIDATES_SHOWN);
}

/* ────────────────────────── the pool-level API (compat, sync) ────────────────────────── */

export interface Resolution {
  match?: Target;
  candidates: Target[];
  /** `match` = one answer · `ambiguous` = several real ones · `not_found` = none, candidates are near names. */
  reason: 'match' | 'ambiguous' | 'not_found';
}

/**
 * Spoken name → exactly one target out of a prebuilt pool, or a disambiguation list.
 * Tiered and strictly ordered per DESIGN-SPEC §2 / RESOLVER-DESIGN §4: raw-ID passthrough →
 * exact → normalized → substring → nearest-names miss. A tier with 2+ matches is an
 * ambiguity, never a coin flip.
 */
export function resolveTarget(spoken: string, pool: Target[]): Resolution {
  const raw = spoken.trim();
  if (raw === '') return { candidates: [], reason: 'not_found' };

  if (CONVERSATION_ID.test(raw) || PERSON_ID.test(raw)) {
    const known = pool.find((target) => target.id === raw || target.user_id === raw);
    const passthrough: Target =
      known ??
      (PERSON_ID.test(raw)
        ? { id: raw, label: raw, kind: 'person', user_id: raw }
        : { id: raw, label: raw, kind: raw.startsWith('D') ? 'dm' : raw.startsWith('G') ? 'group_dm' : 'channel' });
    return { match: passthrough, candidates: [passthrough], reason: 'match' };
  }

  const hit = runLadder(raw, pool);
  if (hit !== null) {
    if (hit.matches.length === 1) {
      return { match: hit.matches[0] as Target, candidates: hit.matches, reason: 'match' };
    }
    return { candidates: hit.matches.slice(0, CANDIDATES_SHOWN), reason: 'ambiguous' };
  }
  return { candidates: nearestTargets(raw, pool), reason: 'not_found' };
}

/* ─────────────────────────────────── the resolution API ─────────────────────────────────── */

export interface CandidateSummary {
  name: string; // '#general' | 'Maya' — human, card-safe
  kind: EntityKind;
  channel_id?: string; // machine fields, never rendered
  user_id?: string;
}

export interface ResolveOk {
  ok: true;
  target: Target;
  via: 'id' | 'exact' | 'normalized' | 'substring';
}

export interface ResolveMiss {
  ok: false;
  code: 'ambiguous_target' | 'target_not_found';
  query: string; // the spoken string, verbatim
  candidates: CandidateSummary[]; // ≤ 5; ambiguous → the real matches; not_found → nearest names
}

export type ResolveResult = ResolveOk | ResolveMiss;

export function candidateSummary(target: Target): CandidateSummary {
  return {
    name: target.label,
    kind: target.kind,
    ...(target.kind === 'person' ? {} : { channel_id: target.id }),
    ...(target.user_id === undefined ? {} : { user_id: target.user_id }),
  };
}

/** The pool a spoken name may mean, narrowed by scope and by a leading `#`/`@`. */
function scopedPool(directory: Directory, spoken: string, scope: ResolveScope): Target[] {
  const wantsChannel = spoken.trim().startsWith('#') || scope === 'channel';
  const wantsPerson = spoken.trim().startsWith('@') || scope === 'person';
  return directory.pool.filter((target) => {
    if (wantsChannel) return target.kind === 'channel' || target.kind === 'group_dm';
    if (wantsPerson) return target.kind === 'dm' || target.kind === 'person';
    return true;
  });
}

function directoryAge(directory: Directory): number {
  return clock() - directory.fetchedAt;
}

/** Spoken name or raw ID → one conversation/person Target. Never throws a resolution; never picks a coin flip. */
export async function resolveConversation(
  ctx: ToolCtx,
  spoken: string,
  scope: ResolveScope = 'any',
): Promise<ResolveResult> {
  const raw = spoken.trim();
  if (raw === '') return { ok: false, code: 'target_not_found', query: spoken, candidates: [] };

  // Tier 0: raw-ID passthrough, with label backfill from the directory so the Target still
  // carries the human name. An id the directory has never seen passes through untouched.
  if (CONVERSATION_ID.test(raw)) {
    const directory = await getDirectory(ctx);
    const known = directory.channelsById.get(raw);
    const target: Target =
      known ??
      { id: raw, label: raw, kind: raw.startsWith('D') ? 'dm' : raw.startsWith('G') ? 'group_dm' : 'channel' };
    return { ok: true, target, via: 'id' };
  }
  if (PERSON_ID.test(raw)) {
    const directory = await getDirectory(ctx);
    const person = directory.people.get(raw);
    const target: Target = person === undefined ? { id: raw, label: raw, kind: 'person', user_id: raw } : personTarget(person);
    return { ok: true, target, via: 'id' };
  }

  let directory = await getDirectory(ctx);
  let hit = runLadder(raw, scopedPool(directory, raw, scope));
  if (hit === null && directoryAge(directory) > MISS_RETRY_MS) {
    // Miss-retry: a just-created channel costs one extra walk, not a failed command.
    directory = await getDirectory(ctx, { maxAgeMs: 0 });
    hit = runLadder(raw, scopedPool(directory, raw, scope));
  }

  if (hit !== null) {
    if (hit.matches.length === 1) {
      return { ok: true, target: hit.matches[0] as Target, via: hit.tier };
    }
    return {
      ok: false,
      code: 'ambiguous_target',
      query: spoken,
      candidates: hit.matches.slice(0, CANDIDATES_SHOWN).map(candidateSummary),
    };
  }
  return {
    ok: false,
    code: 'target_not_found',
    query: spoken,
    candidates: nearestTargets(raw, scopedPool(directory, raw, scope)).map(candidateSummary),
  };
}

/** Person only (slack_read_dm, {user} args). Raw U…/W… passes through. */
export function resolveUser(ctx: ToolCtx, spoken: string): Promise<ResolveResult> {
  return resolveConversation(ctx, spoken, 'person');
}

/** Resolution + conversations.open for kind 'person' → a postable channel id, always. */
export interface SendTarget {
  channel_id: string; // guaranteed C…/G…/D…
  label: string;
  kind: 'channel' | 'group_dm' | 'dm';
  user_id?: string;
}

export async function resolveSendTarget(
  ctx: ToolCtx,
  spoken: string,
  scope: ResolveScope = 'any',
): Promise<{ ok: true; target: SendTarget } | ResolveMiss> {
  const resolved = await resolveConversation(ctx, spoken, scope);
  if (!resolved.ok) return resolved;
  const target = resolved.target;

  if (target.kind !== 'person') {
    return {
      ok: true,
      target: {
        channel_id: target.id,
        label: target.label,
        kind: target.kind,
        ...(target.user_id === undefined ? {} : { user_id: target.user_id }),
      },
    };
  }

  const userId = target.user_id ?? target.id;
  const opened = asRecord(await ctx.slackFetch('conversations.open', { users: userId }, { httpMethod: 'POST' }));
  const channelId = str(asRecord(opened['channel'])['id']);
  if (channelId === undefined) {
    return { ok: false, code: 'target_not_found', query: spoken, candidates: [candidateSummary(target)] };
  }
  return { ok: true, target: { channel_id: channelId, label: target.label, kind: 'dm', user_id: userId } };
}

/* ─────────────────── reverse lookup + presentation (read-tool reshape) ─────────────────── */

/**
 * '#general' / 'Maya' / group-dm name for a conversation id. `undefined` when the directory
 * has never seen the id — NEVER the raw id (NAME-RULE §1): a caller with no label omits the
 * field or uses the neutral word; `guardChannel` stays the render-layer net.
 */
export function labelForChannel(dir: Directory, channelId: string): string | undefined {
  const label = dir.channelsById.get(channelId)?.label;
  // Belt-and-braces: a directory entry whose label degenerated to the id is no label at all.
  if (label === undefined || label === channelId || label === `#${channelId}`) return undefined;
  return label;
}

/** Display name for a user id. `undefined` when unresolvable — NEVER the id (NAME-RULE §1). */
export function labelForUser(dir: Directory, userId: string | undefined): string | undefined {
  return userId === undefined ? undefined : dir.people.get(userId)?.display;
}

/* ───────────────────────────── Slack mrkdwn token decode ─────────────────────────────
 *
 * Slack message text arrives with machine tokens (`<@U…>`, `<#C…|name>`, `<url|label>`) and
 * HTML entities (`&amp; &lt; &gt;`). One decode, at the source, so cards AND spoken content
 * get human text and no downstream layer ever needs id knowledge (CARDS-SPEC-R2 §4.3).
 */

const SLACK_TOKEN = /<([^<>]*)>/g;
const URL_SCHEME = /^[a-z][a-z0-9+.-]*:/i;

function decodeToken(dir: Directory, whole: string, inner: string): string {
  if (inner.startsWith('@')) {
    // `<@U…>` / `<@U…|legacy>`: the |part is the LEGACY handle — the directory ladder wins,
    // and the fallback is a neutral word, never the id and never the legacy handle.
    const id = (inner.slice(1).split('|')[0] ?? '').trim();
    return `@${labelForUser(dir, id) ?? 'member'}`;
  }
  if (inner.startsWith('#')) {
    const [id = '', name] = inner.slice(1).split('|');
    if (name !== undefined && name !== '') return `#${name}`;
    return labelForChannel(dir, id.trim()) ?? '#channel';
  }
  if (inner.startsWith('!')) {
    const [command = '', label] = inner.slice(1).split('|');
    if (command === 'here') return '@here';
    if (command === 'channel') return '@channel';
    if (command === 'everyone') return '@everyone';
    return label !== undefined && label !== '' ? label : whole;
  }
  if (URL_SCHEME.test(inner)) {
    const barAt = inner.indexOf('|');
    if (barAt === -1) return inner;
    const label = inner.slice(barAt + 1);
    return label === '' ? inner.slice(0, barAt) : label;
  }
  // Not a token this rule knows — leave the bytes alone (extractive by default).
  return whole;
}

/**
 * Slack raw message text → human text: entities decoded exactly once, `<@U…>` → `@DisplayName`
 * (never the id), `<#C…|name>` → `#name`, `<url|label>` → label, `<!here>` → `@here`.
 * Deterministic, zero LLM; unknown constructs pass through verbatim.
 */
export function decodeSlackText(dir: Directory, raw: string): string {
  const decoded = raw.replace(SLACK_TOKEN, (whole, inner: string) => decodeToken(dir, whole, inner));
  // Ampersand LAST, so `&amp;lt;` decodes once to `&lt;` rather than twice to `<`.
  return decoded.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'] as const;
const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'] as const;

function clockString(date: Date): string {
  const hours24 = date.getHours();
  const hours12 = hours24 % 12 === 0 ? 12 : hours24 % 12;
  const minutes = String(date.getMinutes()).padStart(2, '0');
  return `${hours12}:${minutes} ${hours24 < 12 ? 'AM' : 'PM'}`;
}

/**
 * Slack ts → human clock string: '5:31 PM' same day, 'Mon 5:31 PM' this week, 'Aug 16' older.
 * Locale-stable (English tables above, local time zone), deterministic given nowMs.
 * An unparseable ts yields '' — callers omit the field rather than fabricate a time.
 */
export function humanTime(ts: string, nowMs: number): string {
  const seconds = Number.parseFloat(ts);
  if (!Number.isFinite(seconds)) return '';
  const date = new Date(seconds * 1000);
  const now = new Date(nowMs);
  const startOfDay = (d: Date): number => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  const dayDiff = Math.round((startOfDay(date) - startOfDay(now)) / 86_400_000);
  if (dayDiff === 0) return clockString(date);
  if (Math.abs(dayDiff) < 7) return `${DAYS[date.getDay()] as string} ${clockString(date)}`;
  return `${MONTHS[date.getMonth()] as string} ${date.getDate()}`;
}
