/**
 * Dotted-path reads over a parsed JSON body (work item W4).
 *
 * Every place the engine has to reach into a provider response — `authed_user.access_token`,
 * `ok`, `team`, `expires_in` — goes through here. Two rules make this boring on purpose:
 *
 *  1. No `eval`, no expression language. A path is a list of literal keys. Anything a
 *     provider.json can say, this can evaluate, and `provider.schema.json` catches the rest.
 *  2. A missing link is `undefined`, never a throw. "Slack's refresh response has no
 *     `authed_user`" is a normal, expected fact (D-2026-08-16-1), not an exception.
 */

/** Read `a.b.c` out of a parsed JSON value. `undefined` for any missing or non-object link. */
export function readPath(source: unknown, path: string | undefined): unknown {
  if (path === undefined || path === '') return undefined;
  let cursor: unknown = source;
  for (const key of path.split('.')) {
    if (cursor === null || typeof cursor !== 'object') return undefined;
    cursor = (cursor as Record<string, unknown>)[key];
    if (cursor === undefined) return undefined;
  }
  return cursor;
}

/**
 * First path that yields a non-empty string.
 *
 * This is the data-shaped answer to D-2026-08-16-1 (Slack's token endpoint returns the
 * exchange nested under `authed_user` and the refresh at the TOP LEVEL). The engine tries
 * the profile's path first and falls back to the top-level spelling — a candidate LIST, so
 * a second two-shaped provider costs zero engine lines and there is no `if (slack)`.
 */
export function readFirstString(source: unknown, paths: ReadonlyArray<string | undefined>): string | undefined {
  for (const path of paths) {
    const value = readPath(source, path);
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return undefined;
}

/** First path that yields a finite number. Providers send `expires_in` as a number. */
export function readFirstNumber(source: unknown, paths: ReadonlyArray<string | undefined>): number | undefined {
  for (const path of paths) {
    const value = readPath(source, path);
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    // Some providers stringify it. A numeric string is still a number here.
    if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) {
      return Number(value);
    }
  }
  return undefined;
}
