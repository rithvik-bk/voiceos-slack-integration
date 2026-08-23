/**
 * C-14 taxonomy tests — the closed nine, and the precedence that keeps normalization honest.
 *
 * INV-ERR-1: every engine failure normalizes to the closed taxonomy, each carrying the raw
 * provider error and a recommended action.
 */

import { describe, expect, it } from 'vitest';

import type { EngineErrorCode } from '../src/types.ts';
import {
  TAXONOMY_CODES,
  fromEngineCode,
  fromHttpStatus,
  fromOAuthError,
  normalize,
  normalizeEngineError,
  recommendedAction,
} from '../src/taxonomy.ts';
import type { TaxonomyCode } from '../src/taxonomy.ts';

describe('the closed set', () => {
  it('is exactly the nine SPEC §15 codes, no duplicates', () => {
    expect([...TAXONOMY_CODES].sort()).toEqual(
      [
        'CONFIG_INVALID',
        'CONSENT_DENIED',
        'NOT_CONNECTED',
        'PROVIDER_UNAVAILABLE',
        'RATE_LIMITED',
        'REFRESH_FAILED',
        'REVOKED',
        'SCOPE_INSUFFICIENT',
        'TOKEN_EXPIRED',
      ].sort(),
    );
    expect(new Set(TAXONOMY_CODES).size).toBe(9);
  });

  it('gives every code a non-empty recommended action', () => {
    for (const code of TAXONOMY_CODES) {
      expect(recommendedAction(code).length).toBeGreaterThan(0);
    }
  });
});

describe('fromEngineCode — every internal code lands in the nine', () => {
  const cases: ReadonlyArray<readonly [EngineErrorCode, TaxonomyCode]> = [
    ['not_connected', 'NOT_CONNECTED'],
    ['denied_by_user', 'CONSENT_DENIED'],
    ['expired_or_revoked', 'REVOKED'],
    ['refresh_failed', 'REFRESH_FAILED'],
    ['timeout', 'PROVIDER_UNAVAILABLE'],
    ['provider_error', 'PROVIDER_UNAVAILABLE'],
    ['port_blocked', 'CONFIG_INVALID'],
    ['state_mismatch', 'CONFIG_INVALID'],
    ['vault_unavailable', 'CONFIG_INVALID'],
    ['not_implemented', 'CONFIG_INVALID'],
    ['config_invalid', 'CONFIG_INVALID'],
  ];

  it.each(cases)('%s → %s', (engine, expected) => {
    expect(fromEngineCode(engine)).toBe(expected);
  });

  it('always returns a member of the closed set', () => {
    for (const [engine] of cases) {
      expect(TAXONOMY_CODES).toContain(fromEngineCode(engine));
    }
  });
});

describe('fromOAuthError — provider vocabulary → the nine', () => {
  const cases: ReadonlyArray<readonly [string, TaxonomyCode]> = [
    ['invalid_scope', 'SCOPE_INSUFFICIENT'],
    ['insufficient_scope', 'SCOPE_INSUFFICIENT'],
    ['missing_scope', 'SCOPE_INSUFFICIENT'],
    ['token_revoked', 'REVOKED'],
    ['account_inactive', 'REVOKED'],
    ['invalid_auth', 'REVOKED'],
    ['token_expired', 'TOKEN_EXPIRED'],
    ['expired_token', 'TOKEN_EXPIRED'],
    ['invalid_token', 'TOKEN_EXPIRED'],
    ['invalid_grant', 'REFRESH_FAILED'],
    ['access_denied', 'CONSENT_DENIED'],
    ['not_authed', 'NOT_CONNECTED'],
    ['slow_down', 'RATE_LIMITED'],
    ['ratelimited', 'RATE_LIMITED'],
    ['too_many_requests', 'RATE_LIMITED'],
    ['temporarily_unavailable', 'PROVIDER_UNAVAILABLE'],
    ['server_error', 'PROVIDER_UNAVAILABLE'],
    ['invalid_client', 'CONFIG_INVALID'],
    ['unsupported_grant_type', 'CONFIG_INVALID'],
  ];

  it.each(cases)('%s → %s', (token, expected) => {
    expect(fromOAuthError(token)).toBe(expected);
  });

  it('finds a token embedded in a full sentence', () => {
    expect(fromOAuthError('The refresh token is invalid: invalid_grant (expired).')).toBe('REFRESH_FAILED');
  });

  it('matches case-insensitively', () => {
    expect(fromOAuthError('INVALID_SCOPE')).toBe('SCOPE_INSUFFICIENT');
  });

  it('returns undefined for an opaque string', () => {
    expect(fromOAuthError('something went wrong')).toBeUndefined();
    expect(fromOAuthError('')).toBeUndefined();
  });

  it('does not false-match a substring inside a larger word', () => {
    // "reinvalid_scoped" must not read as invalid_scope.
    expect(fromOAuthError('reinvalid_scoped')).toBeUndefined();
  });
});

describe('fromHttpStatus', () => {
  it('maps only the unambiguous statuses', () => {
    expect(fromHttpStatus(429)).toBe('RATE_LIMITED');
    expect(fromHttpStatus(500)).toBe('PROVIDER_UNAVAILABLE');
    expect(fromHttpStatus(503)).toBe('PROVIDER_UNAVAILABLE');
    expect(fromHttpStatus(401)).toBe('TOKEN_EXPIRED');
    expect(fromHttpStatus(403)).toBe('SCOPE_INSUFFICIENT');
  });

  it('returns undefined for a status it will not guess', () => {
    expect(fromHttpStatus(200)).toBeUndefined();
    expect(fromHttpStatus(400)).toBeUndefined();
    expect(fromHttpStatus(404)).toBeUndefined();
  });
});

describe('normalize — precedence and payload', () => {
  it('an explicit revoked flag outranks everything', () => {
    const n = normalize({ revoked: true, status: 429, providerError: 'invalid_scope', engineCode: 'timeout' });
    expect(n.code).toBe('REVOKED');
  });

  it('a provider error token outranks the HTTP status', () => {
    // A 403 alone is SCOPE_INSUFFICIENT, but the body says the token was revoked.
    const n = normalize({ status: 403, providerError: 'token_revoked' });
    expect(n.code).toBe('REVOKED');
  });

  it('the HTTP status outranks the engine code', () => {
    const n = normalize({ status: 429, engineCode: 'provider_error' });
    expect(n.code).toBe('RATE_LIMITED');
  });

  it('falls back to the engine code when nothing more specific is present', () => {
    expect(normalize({ engineCode: 'not_connected' }).code).toBe('NOT_CONNECTED');
  });

  it('falls back to PROVIDER_UNAVAILABLE for a wholly unattributed failure', () => {
    expect(normalize({}).code).toBe('PROVIDER_UNAVAILABLE');
  });

  it('an opaque provider string does not override a good engine code', () => {
    const n = normalize({ engineCode: 'refresh_failed', providerError: 'kaboom' });
    expect(n.code).toBe('REFRESH_FAILED');
  });

  it('carries the raw provider error verbatim when present', () => {
    const n = normalize({ status: 500, providerError: 'upstream exploded' });
    expect(n.rawProviderError).toBe('upstream exploded');
    expect(n.action).toBe(recommendedAction('PROVIDER_UNAVAILABLE'));
  });

  it('omits rawProviderError when there is none or it is empty', () => {
    expect(normalize({ engineCode: 'timeout' })).not.toHaveProperty('rawProviderError');
    expect(normalize({ engineCode: 'timeout', providerError: '' })).not.toHaveProperty('rawProviderError');
  });

  it('always emits a member of the closed set', () => {
    const samples = [
      normalize({}),
      normalize({ status: 418 }),
      normalize({ providerError: 'gibberish' }),
      normalize({ engineCode: 'config_invalid' }),
    ];
    for (const s of samples) expect(TAXONOMY_CODES).toContain(s.code);
  });
});

describe('normalizeEngineError — the EngineError duck', () => {
  it('maps code and forwards providerMessage as the raw error', () => {
    const n = normalizeEngineError({ code: 'provider_error', providerMessage: 'invalid_grant' });
    // The provider's word (invalid_grant) is more specific than the generic provider_error.
    expect(n.code).toBe('REFRESH_FAILED');
    expect(n.rawProviderError).toBe('invalid_grant');
  });

  it('works with no providerMessage', () => {
    const n = normalizeEngineError({ code: 'not_connected' });
    expect(n.code).toBe('NOT_CONNECTED');
    expect(n).not.toHaveProperty('rawProviderError');
  });
});
