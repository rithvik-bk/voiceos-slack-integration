/**
 * P1-I6 — silent refresh. The file that decides whether the demo still works tomorrow.
 *
 * Slack's access token lives 12 hours and its refresh token is SINGLE-USE under rotation.
 * That combination has one catastrophic failure mode, and it is not "the token expired":
 * it is five MCP processes each holding the same refresh token, all refreshing at once,
 * four of them getting `invalid_refresh_token`, and the vault ending up holding a refresh
 * token the provider has already retired. Auth is then permanently bricked and the only
 * repair is a human clicking Allow — mid-demo. So:
 *
 *   - refresh is EDGE-TRIGGERED (§A1): inside REFRESH_SKEW_MS of expiry, or after a real
 *     401. Never a poll loop, never a timer. Nothing happens while nothing is being asked.
 *   - refreshes are serialised by an O_EXCL lockfile in os.tmpdir(), which is cross-process
 *     (five MCP servers, one lock) as well as cross-async. The lock file holds a pid and a
 *     timestamp and NEVER token bytes.
 *   - the loser of the race does NOT refresh. It re-reads the vault and finds the winner's
 *     fresh token there — which is why the winner persists the new pair BEFORE releasing.
 *   - a stale lock (holder crashed) is taken over after STALE_LOCK_MS. A lock that can
 *     deadlock the demo is worse than the race it prevents.
 */

import { constants as FS, open, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { REFRESH_SKEW_MS } from './config.ts';
import { EngineError } from './errors.ts';
import { refreshGrant, satisfiesPredicate } from './exchange.ts';
import type { HttpOptions } from './exchange.ts';
import * as obs from './observability.ts';
import { readFirstString } from './paths.ts';
import {
  assertRefreshUnconsumed,
  familyRevocationReauth,
  isFamilyRevocation,
  markRefreshConsumed,
} from './reuse.ts';
import { putToken, readToken } from './vault.ts';
import type { ProviderProfile, TokenRecord } from './types.ts';

/** A lock older than this belonged to a process that died holding it. */
export const STALE_LOCK_MS = 30_000;
/** How long we are willing to wait for another process's refresh before taking over. */
const LOCK_WAIT_MS = 20_000;
const LOCK_POLL_MS = 50;

function lockPath(provider: string, accountId?: string): string {
  // Provider names are validated by vault.vaultService() before they ever reach a path;
  // this second pass is here so a bad name can never escape into os.tmpdir() either.
  // C-13: the lock is per (provider, account). Two accounts hold two different refresh tokens,
  // so serialising them under one lock would be needless contention; keying the lock by account
  // keeps the single-use-rotation guarantee per grant. A bare-provider call keeps the legacy
  // path byte-for-byte, so an existing single-slot lock is unaffected.
  const base = accountId === undefined || accountId === '' ? provider : `${provider}.acct.${accountId}`;
  const safe = base.replace(/[^A-Za-z0-9._-]/g, '_');
  return join(tmpdir(), `voiceos-connect-${safe}.refresh.lock`);
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Acquire the per-provider refresh lock, or throw.
 *
 * `wx` is the whole mechanism: O_CREAT|O_EXCL is atomic on every filesystem we care about,
 * so exactly one process wins even if it is not this one.
 */
async function acquireLock(provider: string, accountId?: string): Promise<() => Promise<void>> {
  const path = lockPath(provider, accountId);
  const deadline = Date.now() + LOCK_WAIT_MS;

  for (;;) {
    try {
      const handle = await open(path, FS.O_CREAT | FS.O_EXCL | FS.O_WRONLY);
      // Contents are diagnostic ONLY. A token byte in a world-readable tmp file would
      // undo the entire point of the Keychain.
      await handle.writeFile(JSON.stringify({ pid: process.pid, at: Date.now() }));
      await handle.close();
      let released = false;
      return async () => {
        if (released) return;
        released = true;
        await rm(path, { force: true });
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
        throw new EngineError('refresh_failed', 'could not take the refresh lock', {
          hint: `Lock path ${path} is not creatable. Refreshes must be serialised: a rotating refresh token used twice is permanently dead.`,
          cause: error,
        });
      }
      if (await isStale(path)) {
        await rm(path, { force: true });
        continue;
      }
      if (Date.now() >= deadline) {
        // Take over rather than fail: the holder is alive but wedged, and a stuck lock
        // would turn a slow refresh into a dead integration.
        await rm(path, { force: true });
        continue;
      }
      await sleep(LOCK_POLL_MS);
    }
  }
}

async function isStale(path: string): Promise<boolean> {
  try {
    const info = await stat(path);
    if (Date.now() - info.mtimeMs > STALE_LOCK_MS) return true;
    // A lock whose owner is gone is stale immediately, whatever its age says.
    const body = await readFile(path, 'utf8').catch(() => '');
    const pid = Number((JSON.parse(body || '{}') as { pid?: number }).pid);
    if (Number.isInteger(pid) && pid > 0 && pid !== process.pid) {
      try {
        process.kill(pid, 0);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ESRCH') return true;
      }
    }
    return false;
  } catch {
    // It vanished between the EEXIST and the stat: not stale, just gone. Retry the create.
    return false;
  }
}

/* ──────────────────────────────────── freshness ──────────────────────────────────── */

/** A record with no expiry is treated as fresh: the provider never promised otherwise. */
export function isFresh(record: TokenRecord, now = Date.now(), skewMs = REFRESH_SKEW_MS): boolean {
  if (record.expires_at === undefined) return true;
  return record.expires_at - now > skewMs;
}

/* ───────────────────────────────────── the verb ───────────────────────────────────── */

export interface RefreshOptions extends HttpOptions {
  /** Refresh even if the vaulted token still looks fresh — the on-401 path. */
  force?: boolean;
  /**
   * C-13 — which account's token to read, refresh and re-vault. Omitted = the legacy single
   * slot (bare provider key). `getToken(provider, account)` resolves the selector to a stable
   * accountId and passes it here, so refresh reads and rewrites the RIGHT account's record.
   */
  accountId?: string;
}

/**
 * A token that is valid *right now* for `profile`.
 *
 * @throws EngineError `not_connected` when nothing is vaulted.
 * @throws EngineError `expired_or_revoked` when the grant is dead and only a human can fix it.
 */
export async function getFreshToken(
  profile: ProviderProfile,
  options: RefreshOptions = {},
): Promise<string> {
  // C-23: every serve is recorded credential-free so silent-refresh rate is a measured number.
  // `fresh`/`refreshed` are served without user interaction; `reauth_required` is a serve that
  // needs a human — the "bug with a user attached" the metric counts against (SPEC §29).
  const served = (
    outcome: 'fresh' | 'refreshed' | 'reauth_required',
    errorCode?: string,
  ): void =>
    obs.recordTokenServed(profile.name, outcome, {
      ...(options.accountId === undefined ? {} : { accountId: options.accountId }),
      ...(errorCode === undefined ? {} : { errorCode }),
    });

  const existing = await readToken(profile.name, options.accountId);
  if (existing === null) {
    // Not a serve failure — nothing was ever connected. Not counted against silent-refresh rate.
    throw new EngineError('not_connected', `${profile.name} is not connected`, {
      hint: `Call connect() for ${profile.display_name} — nothing is vaulted for it.`,
    });
  }
  if (!options.force && isFresh(existing)) {
    served('fresh');
    return existing.access_token;
  }

  if (existing.refresh_token === undefined) {
    served('reauth_required', 'expired_or_revoked');
    throw new EngineError('expired_or_revoked', `${profile.name} has no refresh token`, {
      hint: `${profile.display_name} issued no refresh token (or the profile disables rotation). Reconnect to get a new one.`,
    });
  }

  const release = await acquireLock(profile.name, options.accountId);
  try {
    // The loser of the race lands here AFTER the winner has already persisted. Re-reading
    // is what turns a would-be double refresh into a cache hit — and it is why the winner
    // writes the vault before it releases.
    const current = await readToken(profile.name, options.accountId);
    if (current === null) {
      throw new EngineError('not_connected', `${profile.name} was disconnected mid-refresh`, {
        hint: 'The vault entry disappeared while waiting for the refresh lock.',
      });
    }
    if (!options.force && isFresh(current)) {
      served('fresh');
      return current.access_token;
    }
    // `force` must not re-refresh a token another process just rotated for us: if the
    // vaulted refresh token changed while we waited, the rotation already happened.
    if (options.force && current.refresh_token !== existing.refresh_token) {
      served('fresh');
      return current.access_token;
    }

    const refreshToken = current.refresh_token;
    if (refreshToken === undefined) {
      served('reauth_required', 'expired_or_revoked');
      throw new EngineError('expired_or_revoked', `${profile.name} has no refresh token`, {
        hint: `Reconnect ${profile.display_name}.`,
      });
    }

    // C-10: never send a rotating refresh token we have already spent this process. After a
    // crash lost the persist, the force/on-401 path can re-read a vault still holding the OLD
    // token and try it a second time — the exact move that trips family revocation (RFC 6819
    // §5.2.2.3). Refuse it locally, as a clean re-auth, before it leaves the machine.
    try {
      assertRefreshUnconsumed(refreshToken, profile);
    } catch (error) {
      served('reauth_required', 'expired_or_revoked');
      throw error;
    }

    let next: TokenRecord;
    try {
      next = await refreshGrant(profile, refreshToken, options);
    } catch (error) {
      // The provider declared the grant dead: the token IS proven spent. Record it so it is
      // never replayed, and surface a clean reconnect instead of a cryptic failure.
      if (isFamilyRevocation(error)) {
        markRefreshConsumed(refreshToken);
        served('reauth_required', 'expired_or_revoked');
        throw familyRevocationReauth(profile, error);
      }
      // A transient/transport failure does NOT prove the token was spent — leave it unmarked
      // so the caller's backoff retry stays free to try it again.
      throw error;
    }

    // A real rotation happened (the provider handed back a DIFFERENT refresh token): the old
    // one is now retired on the provider's side and must never be sent again.
    if (next.refresh_token !== undefined && next.refresh_token !== refreshToken) {
      markRefreshConsumed(refreshToken);
    }

    // Merge, do not replace: the identity was resolved at connect time and the refresh
    // response does not carry it, but the product surface speaks it on every status.
    const merged: TokenRecord = {
      ...next,
      // A provider that omits a new refresh token means "keep using the old one."
      refresh_token: next.refresh_token ?? refreshToken,
      ...(current.identity === undefined ? {} : { identity: current.identity }),
      scopes: next.scopes.length > 0 ? next.scopes : current.scopes,
    };

    // BEFORE the release, and before the return: a rotated pair that is not durably stored
    // is a pair the provider has already invalidated on its side.
    await putToken(profile.name, merged, options.accountId);
    served('refreshed');
    return merged.access_token;
  } finally {
    await release();
  }
}

/**
 * Provider error codes that mean "this token is dead," as opposed to "this request was bad."
 * Only these trigger the one retry: retrying a `missing_scope` would burn a rotation for
 * nothing, and rotations are the scarce resource here.
 */
const DEAD_TOKEN = new Set([
  'invalid_auth',
  'not_authed',
  'token_expired',
  'token_revoked',
  'invalid_token',
  'expired_token',
  'account_inactive',
]);

/**
 * Was that response an auth failure?
 *
 * A 401 is the easy half. The half that matters for THIS demo is the other one: Slack
 * answers a revoked or expired token with **HTTP 200 and `{"ok": false, "error":
 * "invalid_auth"}`** [C-SL-20]. An engine that only watches for 401 would therefore never
 * refresh Slack at all — it would surface "not connected" twelve hours after the last
 * consent, which is precisely the moment this project exists to survive. The profile's
 * `success_predicate` is already the one encoding of "did this 200 succeed", so the body
 * check is free and provider-agnostic: no `if (slack)`.
 */
export async function isAuthFailure(profile: ProviderProfile, response: Response): Promise<boolean> {
  if (response.status === 401) return true;
  if (!response.ok) return false;
  if (profile.success_predicate === undefined || profile.success_predicate === null) return false;
  try {
    // `clone()` so the caller still gets an unread body.
    const payload: unknown = await response.clone().json();
    if (satisfiesPredicate(profile.success_predicate, payload)) return false;
    const error = (readFirstString(payload, ['error']) ?? '').toLowerCase();
    return DEAD_TOKEN.has(error);
  } catch {
    return false;
  }
}

/**
 * A `fetch` that carries a fresh token and survives exactly one auth failure.
 *
 * This is the "on-401 retry ONCE" half of §A1, and it lives here rather than in every
 * integration because it must share the lock: an auth-failure storm across five tools is
 * the same bricking scenario as an expiry storm. `Authorization` is attached here and
 * nowhere else, so no integration ever holds a token long enough to log it.
 */
export async function authorizedFetch(
  profile: ProviderProfile,
  url: string,
  init: RequestInit = {},
  options: RefreshOptions = {},
): Promise<Response> {
  const doFetch = options.fetchImpl ?? fetch;

  const send = async (token: string): Promise<Response> =>
    doFetch(url, {
      ...init,
      headers: {
        ...(profile.static_headers ?? {}),
        ...(init.headers as Record<string, string> | undefined),
        authorization: `Bearer ${token}`,
      },
    });

  const first = await send(await getFreshToken(profile, options));
  if (!(await isAuthFailure(profile, first))) return first;

  // Exactly ONE retry, and only on the edge — never a loop, never a poll.
  return send(await getFreshToken(profile, { ...options, force: true }));
}
