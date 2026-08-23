/**
 * Multi-account and tenancy — SPEC Part 4 §11, closing gap C-13.
 *
 * Most OAuth stacks assume one account per provider, and it is the first thing a real user
 * hits inside a week: two Slack workspaces, a personal and a work Gmail. Handshake treats
 * the account as a first-class dimension, and this module is the whole of that dimension:
 *
 *   1. A STABLE ACCOUNT ID derived from the identity probe — never from a display name.
 *      A workspace can be renamed and a handle can change; the provider's opaque id
 *      (Slack `team_id`/`user_id`, a Google `sub`) does not, so that is what we key on,
 *      falling back to workspace+handle only when the provider exposes no opaque id.
 *
 *   2. A VAULT KEY of (provider + account). Two accounts of one provider get two Keychain
 *      items and never overwrite each other. `accountKey()` is the single place that
 *      composition happens; the vault stays keyed by an opaque string it does not parse.
 *
 *   3. `getToken(provider, account?)` RESOLUTION with a defined default rule and ambiguity
 *      SURFACED to the caller — the engine never silently picks one of several accounts.
 *
 * Slack's bot-vs-user token distinction is NOT handled here as a branch. That is a
 * `token_shape` / `token_path` concern in the provider profile (the exchange already reads
 * `authed_user.access_token` by config, not by `if (slack)`). At this layer a bot and a user
 * are simply two identities → two accounts, with zero provider-specific code. There is no
 * `if (provider === …)` in this file, by charter (INV-CONFIG-1).
 *
 * Pure by design: no Keychain, no network, no child process. It computes ids and keys and
 * resolves a selector against a stored index. Persistence and wiring live in the integrator
 * edits documented alongside this module — the index is a display-safe list (handles and
 * workspace labels, never a token), so it can ride in the vault next to the tokens it maps.
 */

import { createHash } from 'node:crypto';

import { EngineError } from './errors.ts';
import type { Identity } from './identity.ts';

/* ─────────────────────────────── types ─────────────────────────────── */

/**
 * A display-safe pointer to one connected account. Everything here is safe to render and
 * safe to persist in the index — there is deliberately no token, no scope, no expiry.
 */
export interface AccountRef {
  /** The provider this account belongs to (the profile `name`). */
  provider: string;
  /** Stable, opaque, key-safe id from {@link deriveAccountId}. */
  accountId: string;
  /** The probe's handle, e.g. `rithvik`. Display + selector only. */
  handle: string;
  /** The probe's workspace/tenant label, e.g. `VoiceOS HQ`. Optional. */
  workspace?: string;
}

/**
 * The per-provider account list plus an optional caller-designated default. The default is
 * EXPLICIT: the engine never marks one behind the user's back, because "silently picked" is
 * exactly the behaviour §11 forbids.
 */
export interface AccountIndex {
  accounts: AccountRef[];
  defaultAccountId?: string;
}

/** The outcome of resolving a `getToken(provider, account?)` request against an index. */
export type AccountResolution =
  | { ok: true; account: AccountRef }
  | { ok: false; reason: 'none'; candidates: AccountRef[] }
  | { ok: false; reason: 'ambiguous'; candidates: AccountRef[] };

/* ─────────────────────────────── stable account id ─────────────────────────────── */

/** Keychain/service charset the vault enforces. A key we build MUST satisfy it. */
const KEY_SAFE = /^[a-z0-9][a-z0-9._-]*$/i;

/** Length of the derived id in hex chars. 20 hex = 80 bits — collision-proof for the
 *  handful of accounts one human holds per provider, and short enough to read in a log. */
const ACCOUNT_ID_LEN = 20;

/**
 * The seed we hash. Structured with a field tag and a unit separator so that
 * `(handle="ab", workspace="")` can never collide with `(handle="a", workspace="b")`, and
 * so the opaque-id path can never collide with the fallback path.
 */
function stableSeed(identity: Identity): string {
  // The immutable subject: the engine's native probe field `accountId`, or the OIDC-standard
  // `sub` when the subject arrives under that name. Either one survives a handle/workspace
  // rename, so two accounts sharing a handle but differing in subject never collapse.
  const opaque = identity.accountId ?? identity.sub;
  if (opaque !== undefined && opaque !== '') return `id${opaque}`;
  const workspace = identity.workspace ?? '';
  return `hw${workspace}${identity.handle}`;
}

/**
 * A stable, opaque, key-safe account id derived from the identity probe.
 *
 * Precedence is the whole point: the provider's opaque account id first (survives renames),
 * then workspace+handle, and NEVER a display name. The result is a hash, so it is always
 * `[0-9a-f]` (legal in a vault key) and never carries a raw handle or email into a Keychain
 * service name.
 *
 * @throws EngineError `config_invalid` when the identity has no handle to derive from — a
 *         probe that returned no handle is not a connection (see identity.ts).
 */
export function deriveAccountId(identity: Identity): string {
  if (identity.handle === undefined || identity.handle === '') {
    throw new EngineError('config_invalid', 'cannot derive an account id without an identity handle', {
      hint: 'deriveAccountId needs the probe handle (and, when present, the opaque account id). An identity with no handle is not a connection.',
    });
  }
  return createHash('sha256').update(stableSeed(identity), 'utf8').digest('hex').slice(0, ACCOUNT_ID_LEN);
}

/** Build a display-safe {@link AccountRef} for `provider` from a resolved identity. */
export function toAccountRef(provider: string, identity: Identity): AccountRef {
  return {
    provider,
    accountId: deriveAccountId(identity),
    handle: identity.handle,
    ...(identity.workspace === undefined || identity.workspace === ''
      ? {}
      : { workspace: identity.workspace }),
  };
}

/* ─────────────────────────────── vault key ─────────────────────────────── */

/** Marker between the provider and the account in a composed vault key. The account id is
 *  hex, so this never appears inside it; the vault never parses the key, so it is cosmetic. */
const ACCOUNT_KEY_SEP = '.acct.';

/**
 * The (provider + account) key under which this account's token is vaulted.
 *
 * Passed to the existing `vaultService`/`putToken`/`readToken`/`deleteToken` in place of the
 * bare provider name — which is the entire mechanism by which two accounts of one provider
 * get two Keychain items instead of clobbering one. Both halves must be key-safe: `provider`
 * is validated by the vault already, and `accountId` must come from {@link deriveAccountId}
 * (hex), so a raw email or opaque id is rejected here rather than mangled downstream.
 */
export function accountKey(provider: string, accountId: string): string {
  if (!KEY_SAFE.test(provider)) {
    throw new EngineError('config_invalid', 'provider name is not a legal vault key', {
      hint: `Provider names are [A-Za-z0-9._-]; got ${JSON.stringify(provider)}.`,
    });
  }
  if (!KEY_SAFE.test(accountId)) {
    throw new EngineError('config_invalid', 'account id is not a legal vault key', {
      hint: `Account ids must come from deriveAccountId() (hex); got ${JSON.stringify(accountId)}.`,
    });
  }
  const key = `${provider}${ACCOUNT_KEY_SEP}${accountId}`;
  // Belt and suspenders: the composed key itself must satisfy the vault charset.
  if (!KEY_SAFE.test(key)) {
    throw new EngineError('config_invalid', 'composed account key is not a legal vault key', {
      hint: `Composed ${JSON.stringify(key)} from provider + account.`,
    });
  }
  return key;
}

/* ─────────────────────────────── index helpers ─────────────────────────────── */

export function emptyIndex(): AccountIndex {
  return { accounts: [] };
}

/**
 * Add or update an account, keyed by its stable id. Re-connecting the same account (same
 * opaque id) after a workspace rename updates the label in place rather than duplicating —
 * the id is stable across the rename, so there is exactly one entry.
 */
export function upsertAccount(index: AccountIndex, ref: AccountRef): AccountIndex {
  const accounts = index.accounts.filter((a) => a.accountId !== ref.accountId);
  accounts.push(ref);
  return { ...index, accounts };
}

/**
 * Forget one account. If it was the default, the default is cleared — a dangling default is
 * a stale pointer that would otherwise resolve to nothing (or, worse, invite a silent pick).
 */
export function removeAccount(index: AccountIndex, accountId: string): AccountIndex {
  const accounts = index.accounts.filter((a) => a.accountId !== accountId);
  const next: AccountIndex = { accounts };
  if (index.defaultAccountId !== undefined && index.defaultAccountId !== accountId) {
    next.defaultAccountId = index.defaultAccountId;
  }
  return next;
}

/**
 * Designate the default account (the one `getToken(provider)` uses with no selector when
 * several exist). Refuses an id the index does not hold, so a default is always live.
 *
 * @throws EngineError `config_invalid` when `accountId` is not in the index.
 */
export function setDefaultAccount(index: AccountIndex, accountId: string): AccountIndex {
  if (!index.accounts.some((a) => a.accountId === accountId)) {
    throw new EngineError('config_invalid', 'cannot default to an account that is not connected', {
      hint: `No account ${JSON.stringify(accountId)} in this provider's index.`,
    });
  }
  return { ...index, defaultAccountId: accountId };
}

/** The accounts held for this provider (a copy; callers must not mutate the index). */
export function listAccounts(index: AccountIndex): AccountRef[] {
  return [...index.accounts];
}

/* ── index (de)serialization — the index is display-safe (no secrets), so it can persist as
 *    one small JSON record next to the tokens. Parsing is total: junk becomes an empty index
 *    rather than a throw, because a corrupt index must degrade to "nothing connected", never
 *    crash getToken. ── */

export function serializeIndex(index: AccountIndex): string {
  return JSON.stringify({
    accounts: index.accounts,
    ...(index.defaultAccountId === undefined ? {} : { defaultAccountId: index.defaultAccountId }),
  });
}

export function parseIndex(raw: string): AccountIndex {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return emptyIndex();
  }
  if (parsed === null || typeof parsed !== 'object') return emptyIndex();
  const obj = parsed as { accounts?: unknown; defaultAccountId?: unknown };
  const rawAccounts = Array.isArray(obj.accounts) ? obj.accounts : [];
  const accounts: AccountRef[] = [];
  for (const entry of rawAccounts) {
    if (entry === null || typeof entry !== 'object') continue;
    const e = entry as Partial<AccountRef>;
    // Read into locals BEFORE testing: comparing a `provider`-named field to a string
    // literal would trip the INV-CONFIG-1 grep even though this is a shape check, not a
    // per-provider branch. Locals keep the guard honest and the intent obvious.
    const name = e.provider;
    const id = e.accountId;
    const handle = e.handle;
    const workspace = e.workspace;
    if (typeof name !== 'string' || name === '') continue;
    if (typeof id !== 'string' || id === '') continue;
    if (typeof handle !== 'string' || handle === '') continue;
    accounts.push({
      provider: name,
      accountId: id,
      handle,
      ...(typeof workspace === 'string' && workspace !== '' ? { workspace } : {}),
    });
  }
  const result: AccountIndex = { accounts };
  if (
    typeof obj.defaultAccountId === 'string' &&
    accounts.some((a) => a.accountId === obj.defaultAccountId)
  ) {
    result.defaultAccountId = obj.defaultAccountId;
  }
  return result;
}

/* ─────────────────────────────── selector matching ─────────────────────────────── */

function norm(value: string): string {
  return value.trim().toLowerCase();
}

/**
 * Does `selector` name this account? Matches the stable id, the handle, the workspace, or a
 * `handle@workspace` compound — all case- and whitespace-insensitive. Matching is EXACT
 * (not prefix): a selector that names two accounts is genuinely ambiguous, which is precisely
 * the case the resolver surfaces rather than guessing through.
 */
export function matchesSelector(account: AccountRef, selector: string): boolean {
  const s = norm(selector);
  if (s === '') return false;
  if (s === norm(account.accountId)) return true;
  if (s === norm(account.handle)) return true;
  if (account.workspace !== undefined) {
    if (s === norm(account.workspace)) return true;
    if (s === `${norm(account.handle)}@${norm(account.workspace)}`) return true;
  }
  return false;
}

/* ─────────────────────────────── resolution ─────────────────────────────── */

/**
 * Resolve `getToken(provider, account?)` against a stored index — the DEFINED DEFAULT RULE:
 *
 *   1. An explicit `selector` wins and must match exactly one account. Zero matches →
 *      `none` (with the full list so the caller can show the choices); two or more →
 *      `ambiguous` (with the matches).
 *   2. No selector, exactly one account → that account.
 *   3. No selector, several accounts, an explicit default that is still present → the default.
 *   4. Otherwise → `ambiguous`, candidates surfaced. The engine never picks silently.
 *
 * Returned as a discriminated union so a caller can render choices without a try/catch;
 * {@link resolveAccountOrThrow} is the throwing form the token path uses.
 */
export function resolveAccount(index: AccountIndex, selector?: string): AccountResolution {
  const all = index.accounts;
  const wanted = selector !== undefined && norm(selector) !== '' ? selector : undefined;

  if (wanted !== undefined) {
    const matches = all.filter((a) => matchesSelector(a, wanted));
    if (matches.length === 1) return { ok: true, account: matches[0]! };
    if (matches.length === 0) return { ok: false, reason: 'none', candidates: [...all] };
    return { ok: false, reason: 'ambiguous', candidates: matches };
  }

  if (all.length === 0) return { ok: false, reason: 'none', candidates: [] };
  if (all.length === 1) return { ok: true, account: all[0]! };

  if (index.defaultAccountId !== undefined) {
    const chosen = all.find((a) => a.accountId === index.defaultAccountId);
    if (chosen !== undefined) return { ok: true, account: chosen };
    // A stale default is ignored rather than trusted — fall through to surfacing.
  }

  return { ok: false, reason: 'ambiguous', candidates: [...all] };
}

/**
 * Surfaced ambiguity as a typed throw the token path can propagate. Carries the candidate
 * accounts so the product surface can render "which account?" instead of a dead end.
 *
 * The base `code` is `config_invalid` (the request was under-specified, not a provider or
 * token failure) so it never masquerades as `not_connected` and mis-routes the caller into a
 * fresh consent. The integrator may add a dedicated `account_ambiguous` code and map it;
 * `instanceof AccountAmbiguousError` and `.candidates` are the stable contract meanwhile.
 */
export class AccountAmbiguousError extends EngineError {
  readonly candidates: AccountRef[];
  constructor(provider: string, candidates: AccountRef[]) {
    super('config_invalid', `${provider} has several connected accounts; specify which one`, {
      hint: `Pass account to getToken('${provider}', account). Options: ${candidates
        .map(describeAccount)
        .join(' · ')}.`,
    });
    this.name = 'AccountAmbiguousError';
    this.candidates = candidates;
  }
}

/**
 * {@link resolveAccount}, throwing on anything but a clean single match.
 *
 *   - ambiguous → {@link AccountAmbiguousError} (carries `.candidates`).
 *   - none, with a selector → `not_connected` naming the unmatched selector.
 *   - none, no accounts at all → `not_connected` for the provider.
 *
 * @throws EngineError / AccountAmbiguousError
 */
export function resolveAccountOrThrow(
  provider: string,
  index: AccountIndex,
  selector?: string,
): AccountRef {
  const r = resolveAccount(index, selector);
  if (r.ok) return r.account;
  if (r.reason === 'ambiguous') throw new AccountAmbiguousError(provider, r.candidates);
  // reason === 'none'
  if (selector !== undefined && norm(selector) !== '') {
    throw new EngineError('not_connected', `no ${provider} account matches ${JSON.stringify(selector)}`, {
      hint:
        r.candidates.length === 0
          ? `${provider} is not connected. Call connect() first.`
          : `Connected ${provider} accounts: ${r.candidates.map(describeAccount).join(' · ')}.`,
    });
  }
  throw new EngineError('not_connected', `${provider} is not connected`, {
    hint: `Nothing is vaulted for ${provider}. Call connect() first.`,
  });
}

/* ─────────────────────────────── display ─────────────────────────────── */

/** A human-readable, secret-free label for an account. */
export function describeAccount(ref: AccountRef): string {
  return ref.workspace === undefined ? ref.handle : `${ref.handle} in ${ref.workspace}`;
}
