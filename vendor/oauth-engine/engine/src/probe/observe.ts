/**
 * Connect-time observations (C-1, SPEC §2 fifth bullet).
 *
 *   "On a successful connect, record the token response shape, expiry representation,
 *    granted-versus-requested scopes, and whether the refresh token differs from the original
 *    on first refresh."
 *
 * These are the only fields the probe cannot learn without a real token in hand, so they are
 * measured from a CAPTURED response the caller supplies (the probe never completes an
 * interactive consent itself). Everything here is pure and offline.
 *
 * The one scar this file must respect is C-SL-07 / D-2026-08-16-1: Slack's exchange response
 * carries TWO `access_token`s — a top-level BOT token and the real user token nested under
 * `authed_user`. A shape-finder that blindly grabs the top-level one records a plausible,
 * working, WRONG path. So when more than one candidate exists the probe prefers the NESTED
 * path and flags the ambiguity for human confirmation rather than silently picking.
 */

import type { MeasuredProfile, Receipt, ScopeGrant } from './types.ts';

/** Every dotted path at which `key` holds a value of the wanted primitive type. */
function findPaths(
  source: unknown,
  key: string,
  want: 'string' | 'number',
  prefix = '',
): string[] {
  if (source === null || typeof source !== 'object' || Array.isArray(source)) return [];
  const out: string[] = [];
  for (const [k, v] of Object.entries(source as Record<string, unknown>)) {
    const path = prefix === '' ? k : `${prefix}.${k}`;
    if (k === key && typeof v === want) out.push(path);
    if (v !== null && typeof v === 'object') out.push(...findPaths(v, key, want, path));
  }
  return out;
}

/** Prefer a nested path over a top-level one (the C-SL-07 rule). */
function preferNested(paths: string[]): string {
  const nested = paths.filter((p) => p.includes('.'));
  return (nested.length > 0 ? nested : paths)[0] as string;
}

function scopesFrom(source: unknown, tokenPath: string): { scopes: string[]; from: string } | undefined {
  // Scope may sit exactly where the token sits (Slack: authed_user.scope), else top-level.
  const nestedScopeKey = tokenPath.includes('.')
    ? `${tokenPath.slice(0, tokenPath.lastIndexOf('.'))}.scope`
    : undefined;
  const readDotted = (path: string): unknown => {
    let cur: unknown = source;
    for (const part of path.split('.')) {
      if (cur === null || typeof cur !== 'object') return undefined;
      cur = (cur as Record<string, unknown>)[part];
    }
    return cur;
  };
  for (const [path, raw] of [
    [nestedScopeKey, nestedScopeKey ? readDotted(nestedScopeKey) : undefined],
    ['scope', readDotted('scope')],
    ['scopes', readDotted('scopes')],
  ] as const) {
    if (typeof raw === 'string' && raw.trim() !== '') {
      return { scopes: raw.split(/[,\s]+/).filter((s) => s.length > 0), from: String(path) };
    }
    if (Array.isArray(raw)) {
      const arr = raw.filter((s): s is string => typeof s === 'string');
      if (arr.length > 0) return { scopes: arr, from: String(path) };
    }
  }
  return undefined;
}

export interface TokenShapeObservation {
  fields: Partial<MeasuredProfile>;
  /** Granted scopes parsed from the response, when present. */
  granted_scopes?: string[];
  receipts: Receipt[];
}

/**
 * Observe a token response's shape. `requestedScopes` lets the probe classify `scope_grant`
 * as `exact` vs `downgradeable`; without them it reports the granted set but leaves the grant
 * mode `unknown`.
 */
export function observeTokenResponse(
  response: unknown,
  requestedScopes?: string[],
): TokenShapeObservation {
  const fields: Partial<MeasuredProfile> = {};
  const receipts: Receipt[] = [];

  const accessPaths = findPaths(response, 'access_token', 'string');
  if (accessPaths.length === 0) {
    receipts.push({
      field: 'token_path',
      value: 'unknown',
      method: 'token-response-shape',
      note: 'no access_token string anywhere in the response',
    });
    return { fields, receipts };
  }
  const tokenPath = preferNested(accessPaths);
  fields.token_path = tokenPath;
  receipts.push({
    field: 'token_path',
    value: tokenPath,
    method: 'token-response-shape',
    note:
      accessPaths.length > 1
        ? `AMBIGUOUS: candidates [${accessPaths.join(', ')}]; selected the nested one (C-SL-07) — confirm against granted scopes`
        : 'single access_token location',
  });

  const refreshPaths = findPaths(response, 'refresh_token', 'string');
  if (refreshPaths.length > 0) {
    // Keep the refresh path in the same object as the chosen token when possible.
    const tokenParent = tokenPath.includes('.') ? tokenPath.slice(0, tokenPath.lastIndexOf('.')) : '';
    const sameParent = refreshPaths.find((p) =>
      tokenParent === '' ? !p.includes('.') : p.startsWith(`${tokenParent}.`),
    );
    const chosen = sameParent ?? preferNested(refreshPaths);
    fields.refresh_token_path = chosen;
    receipts.push({
      field: 'refresh_token_path',
      value: chosen,
      method: 'token-response-shape',
      note: refreshPaths.length > 1 ? `candidates [${refreshPaths.join(', ')}]` : 'single refresh_token location',
    });
  }

  // Expiry representation.
  const expiresInPaths = findPaths(response, 'expires_in', 'number');
  const expiresAtPaths = findPaths(response, 'expires_at', 'number');
  if (expiresInPaths.length > 0) {
    const p = preferNested(expiresInPaths);
    fields.expires_in_path = p;
    receipts.push({ field: 'expiry', value: 'expires_in', method: 'token-response-shape', note: `expires_in at ${p}` });
  } else if (expiresAtPaths.length > 0) {
    receipts.push({
      field: 'expiry',
      value: 'expires_at',
      method: 'token-response-shape',
      note: `absolute expires_at at ${expiresAtPaths[0]} — pre-emptive refresh keyed off it`,
    });
  } else {
    receipts.push({
      field: 'expiry',
      value: 'none',
      method: 'token-response-shape',
      note: 'no expiry in the response — the engine must probe-on-401 rather than pre-empt',
    });
  }

  // Granted vs requested scopes.
  const granted = scopesFrom(response, tokenPath);
  const result: TokenShapeObservation = { fields, receipts };
  if (granted !== undefined) {
    result.granted_scopes = granted.scopes;
    if (requestedScopes !== undefined && requestedScopes.length > 0) {
      const req = new Set(requestedScopes);
      const got = new Set(granted.scopes);
      const missing = [...req].filter((s) => !got.has(s));
      const extra = [...got].filter((s) => !req.has(s));
      let grant: ScopeGrant;
      let note: string;
      if (missing.length === 0 && extra.length === 0) {
        grant = 'exact';
        note = `granted set equals requested (from ${granted.from})`;
      } else if (missing.length > 0 && extra.length === 0) {
        grant = 'downgradeable';
        note = `provider granted fewer than requested — missing [${missing.join(', ')}] (from ${granted.from})`;
      } else {
        grant = 'unknown';
        note = `granted differs: missing [${missing.join(', ')}], extra [${extra.join(', ')}] (from ${granted.from})`;
      }
      fields.scope_grant = grant;
      receipts.push({ field: 'scope_grant', value: grant, method: 'token-response-shape', note });
    } else {
      receipts.push({
        field: 'scope_grant',
        value: 'unknown',
        method: 'token-response-shape',
        note: `granted [${granted.scopes.join(', ')}] but no requested set to compare — grant mode undetermined`,
      });
    }
  } else {
    receipts.push({
      field: 'scope_grant',
      value: 'unknown',
      method: 'token-response-shape',
      note: 'no scope field in the response',
    });
  }

  return result;
}

export interface RotationObservation {
  fields: Partial<MeasuredProfile>;
  receipt: Receipt;
}

/**
 * Observe whether the refresh token rotates. Compares the refresh token returned by the FIRST
 * refresh against the one originally issued: a different value means single-use rotation
 * (reuse-detection territory); an identical or absent value means a long-lived/static token.
 */
export function observeFirstRefresh(
  originalRefreshToken: string | undefined,
  firstRefreshResponse: unknown,
): RotationObservation {
  if (originalRefreshToken === undefined || originalRefreshToken === '') {
    return {
      fields: { refresh: 'none' },
      receipt: {
        field: 'refresh',
        value: 'none',
        method: 'first-refresh-rotation',
        note: 'no refresh token was issued — refresh path does not apply',
      },
    };
  }
  const refreshPaths = findPaths(firstRefreshResponse, 'refresh_token', 'string');
  if (refreshPaths.length === 0) {
    return {
      fields: { refresh: 'long_lived' },
      receipt: {
        field: 'refresh',
        value: 'long_lived',
        method: 'first-refresh-rotation',
        note: 'first refresh returned no new refresh token — original stays valid (long-lived/static)',
      },
    };
  }
  // Read the first candidate's value.
  const readDotted = (path: string): unknown => {
    let cur: unknown = firstRefreshResponse;
    for (const part of path.split('.')) {
      if (cur === null || typeof cur !== 'object') return undefined;
      cur = (cur as Record<string, unknown>)[part];
    }
    return cur;
  };
  const returned = readDotted(refreshPaths[0] as string);
  const rotated = typeof returned === 'string' && returned !== originalRefreshToken;
  if (rotated) {
    return {
      fields: { refresh: 'rotation', rotation: 'forced' },
      receipt: {
        field: 'refresh',
        value: 'rotation',
        method: 'first-refresh-rotation',
        note: 'first refresh returned a DIFFERENT refresh token ⇒ rotation (single-use, reuse-detection applies)',
      },
    };
  }
  return {
    fields: { refresh: 'long_lived' },
    receipt: {
      field: 'refresh',
      value: 'long_lived',
      method: 'first-refresh-rotation',
      note: 'first refresh returned the SAME refresh token ⇒ long-lived/static',
    },
  };
}
