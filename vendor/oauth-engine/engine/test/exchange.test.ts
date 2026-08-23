/**
 * P1-I4 — token endpoint behaviour, against the asserting mock AS.
 *
 * The tests that matter here are not "a token comes back." They are the four provider
 * truths that were bought with live probes in Phase 0, each of which would otherwise be
 * re-litigated by the next person to touch this file:
 *
 *   1. Slack's exchange is NESTED and its refresh is TOP-LEVEL (D-2026-08-16-1)
 *   2. Slack's top-level exchange `access_token` is the BOT token — parsing it is a
 *      silent, plausible, WRONG success [C-SL-07]
 *   3. Slack fails with HTTP 200 + {"ok": false} [C-SL-20]
 *   4. Zoom's public PKCE client sends client_id in the body and NO Authorization header
 */

import { afterEach, describe, expect, it } from 'vitest';

import { exchangeCode, refreshGrant } from '../src/exchange.ts';
import { EngineError } from '../src/index.ts';
import type { ProviderProfile } from '../src/index.ts';
import { REDIRECT_URIS } from '../src/config.ts';
import { startMockAs } from './mock-as.ts';
import type { MockAs, MockAsOptions } from './mock-as.ts';

const BOUND_REDIRECT = REDIRECT_URIS[0] as string;

const SLACK_SHAPE: Omit<ProviderProfile, 'token_url' | 'authorize_url'> = {
  name: 'slack-test',
  display_name: 'Slack',
  client_id: 'mock.client.id',
  client_type: 'public',
  pkce: 'S256',
  redirect_strategy: 'loopback',
  redirect_host: 'localhost',
  redirect_ports: [33418],
  scopes: ['channels:read', 'channels:history', 'users:read'],
  scope_param: 'user_scope',
  scope_delimiter: ',',
  token_auth: 'none',
  refresh_auth: 'client_id_body',
  token_path: 'authed_user.access_token',
  refresh_token_path: 'authed_user.refresh_token',
  expires_in_path: 'authed_user.expires_in',
  success_predicate: { path: 'ok', equals: true },
  refresh: 'rotation',
  rotation: 'optional-enabled',
  access_token_ttl: 43_200,
  identity_probe: { url: 'https://example.invalid/probe', handle_path: 'user' },
};

const ZOOM_SHAPE: Omit<ProviderProfile, 'token_url' | 'authorize_url'> = {
  name: 'zoom-test',
  display_name: 'Zoom',
  client_id: 'mockZoomPublicId',
  client_type: 'public',
  pkce: 'S256',
  redirect_strategy: 'loopback',
  redirect_host: '127.0.0.1',
  redirect_ports: [33418],
  scopes: ['user:read:user'],
  scope_param: 'scope',
  token_auth: 'none',
  refresh_auth: 'unknown',
  token_path: 'access_token',
  success_predicate: null,
  refresh: 'rotation',
  rotation: 'forced',
  access_token_ttl: 3600,
  identity_probe: { url: 'https://example.invalid/probe', handle_path: 'display_name' },
};

let mock: MockAs | undefined;
afterEach(async () => {
  await mock?.close();
  mock = undefined;
});

async function slack(options: Partial<MockAsOptions> = {}): Promise<ProviderProfile> {
  mock = await startMockAs({ mode: 'slack', expectedRedirectUri: BOUND_REDIRECT, ...options });
  return { ...SLACK_SHAPE, token_url: mock.tokenUrl, authorize_url: mock.authorizeUrl };
}

describe('exchangeCode — the authorization_code grant', () => {
  it('parses the NESTED Slack shape and never the top-level bot token', async () => {
    const profile = await slack();
    const record = await exchangeCode(profile, {
      code: 'mock-auth-code',
      verifier: 'v'.repeat(43),
      redirectUri: BOUND_REDIRECT,
    });

    expect(record.access_token).toBe(mock?.current().access);
    // The single most dangerous near-miss in this whole engine.
    expect(record.access_token).not.toBe('mock-bot-token-do-not-use');
    expect(record.refresh_token).toBe(mock?.current().refresh);
    expect(record.provider).toBe('slack-test');
    expect(record.scopes).toEqual(['channels:read', 'channels:history', 'users:read']);
    expect(record.expires_at).toBeGreaterThan(Date.now() + 43_000_000);
    expect(mock?.violations).toEqual([]);
  });

  it('sends the bound redirect_uri byte-identically, and no client_secret (§A8, D6)', async () => {
    const profile = await slack();
    await exchangeCode(profile, {
      code: 'mock-auth-code',
      verifier: 'v'.repeat(43),
      redirectUri: BOUND_REDIRECT,
    });
    const sent = mock?.requests[0];
    expect(sent?.params.redirect_uri).toBe(BOUND_REDIRECT);
    expect(sent?.params.client_secret).toBeUndefined();
    expect(sent?.params.client_id).toBe('mock.client.id');
    expect(sent?.params.code_verifier).toBe('v'.repeat(43));
    expect(sent?.authorization).toBeUndefined();
    expect(mock?.violations).toEqual([]);
  });

  it('treats a mismatched redirect_uri as the failure it is, not a shrug', async () => {
    mock = await startMockAs({ mode: 'slack', expectedRedirectUri: BOUND_REDIRECT });
    const profile: ProviderProfile = {
      ...SLACK_SHAPE,
      token_url: mock.tokenUrl,
      authorize_url: mock.authorizeUrl,
    };
    const error = await exchangeCode(profile, {
      code: 'mock-auth-code',
      verifier: 'v'.repeat(43),
      redirectUri: REDIRECT_URIS[1] as string,
    }).catch((e: unknown) => e as EngineError);

    expect(error).toBeInstanceOf(EngineError);
    expect((error as EngineError).providerMessage).toContain('bad_redirect_uri');
    // The mock recorded WHY, so this failure is diagnosable from the test output alone.
    expect(mock.violations.join(' ')).toContain('byte-identical');
    mock.violations.length = 0; // asserted; do not let afterEach's cleanup imply a pass
  });

  it('honours the body-level success predicate: HTTP 200 + {"ok": false} is a FAILURE', async () => {
    const profile = await slack();
    const error = await exchangeCode(profile, {
      code: 'not-the-code',
      verifier: 'v'.repeat(43),
      redirectUri: BOUND_REDIRECT,
    }).catch((e: unknown) => e as EngineError);

    expect(error).toBeInstanceOf(EngineError);
    expect((error as EngineError).code).toBe('expired_or_revoked');
    expect((error as EngineError).providerMessage).toContain('invalid_code');
    expect(mock?.violations).toEqual([]);
  });

  it('refuses a PKCE exchange with no verifier at the provider, not silently', async () => {
    const profile = await slack();
    const error = await exchangeCode(
      { ...profile, pkce: 'none' },
      { code: 'mock-auth-code', verifier: 'unused', redirectUri: BOUND_REDIRECT },
    ).catch((e: unknown) => e as EngineError);
    expect(error).toBeInstanceOf(EngineError);
    expect(mock?.violations.join(' ')).toContain('code_verifier missing');
    mock!.violations.length = 0;
  });

  it('never lets a code, verifier or token reach an error string', async () => {
    const profile = await slack();
    const code = 'super-secret-authorization-code';
    const verifier = 'super-secret-pkce-verifier-value-0123456789';
    const error = await exchangeCode(profile, {
      code,
      verifier,
      redirectUri: BOUND_REDIRECT,
    }).catch((e: unknown) => e as EngineError);

    const serialized = JSON.stringify({
      message: (error as EngineError).message,
      hint: (error as EngineError).hint,
      providerMessage: (error as EngineError).providerMessage,
      stack: (error as EngineError).stack,
    });
    expect(serialized).not.toContain(code);
    expect(serialized).not.toContain(verifier);
  });
});

describe('exchangeCode — Zoom, as measured live 2026-08-16', () => {
  it('puts client_id in the body and sends NO Authorization header', async () => {
    mock = await startMockAs({ mode: 'zoom', expectedRedirectUri: BOUND_REDIRECT });
    const profile: ProviderProfile = {
      ...ZOOM_SHAPE,
      token_url: mock.tokenUrl,
      authorize_url: mock.authorizeUrl,
    };
    const record = await exchangeCode(profile, {
      code: 'mock-auth-code',
      verifier: 'v'.repeat(43),
      redirectUri: BOUND_REDIRECT,
    });
    expect(record.access_token).toBe(mock.current().access);
    expect(record.refresh_token).toBe(mock.current().refresh);
    expect(mock.requests[0]?.params.client_id).toBe('mockZoomPublicId');
    expect(mock.requests[0]?.authorization).toBeUndefined();
    expect(mock.violations).toEqual([]);
  });

  it('uses the HTTP status as the whole verdict when there is no predicate', async () => {
    mock = await startMockAs({ mode: 'zoom' });
    const profile: ProviderProfile = {
      ...ZOOM_SHAPE,
      token_url: mock.tokenUrl,
      authorize_url: mock.authorizeUrl,
    };
    const error = await exchangeCode(profile, {
      code: 'wrong',
      verifier: 'v'.repeat(43),
      redirectUri: BOUND_REDIRECT,
    }).catch((e: unknown) => e as EngineError);
    expect((error as EngineError).code).toBe('expired_or_revoked');
    expect((error as EngineError).providerMessage).toContain('invalid code');
  });
});

describe('refreshGrant — the shape that changes underneath you', () => {
  it('parses Slack’s TOP-LEVEL refresh response (D-2026-08-16-1)', async () => {
    const profile = await slack();
    const first = await exchangeCode(profile, {
      code: 'mock-auth-code',
      verifier: 'v'.repeat(43),
      redirectUri: BOUND_REDIRECT,
    });

    const refreshed = await refreshGrant(profile, first.refresh_token as string);

    // The profile's token_path (`authed_user.access_token`) does not exist in this body.
    // Falling through to the top level is the entire point.
    expect(refreshed.access_token).toBe(mock?.current().access);
    expect(refreshed.access_token).not.toBe(first.access_token);
    expect(refreshed.refresh_token).toBe(mock?.current().refresh);
    expect(refreshed.scopes).toContain('identify');
    expect(mock?.violations).toEqual([]);
  });

  it('authenticates the refresh with client_id in the body and no secret (U1, closed live)', async () => {
    const profile = await slack();
    const first = await exchangeCode(profile, {
      code: 'mock-auth-code',
      verifier: 'v'.repeat(43),
      redirectUri: BOUND_REDIRECT,
    });
    await refreshGrant(profile, first.refresh_token as string);

    const sent = mock?.requests.at(-1);
    expect(sent?.grant).toBe('refresh_token');
    expect(sent?.params.client_id).toBe('mock.client.id');
    expect(sent?.params.client_secret).toBeUndefined();
    expect(sent?.authorization).toBeUndefined();
  });

  it('treats a replayed (rotated-away) refresh token as expired_or_revoked', async () => {
    const profile = await slack();
    const first = await exchangeCode(profile, {
      code: 'mock-auth-code',
      verifier: 'v'.repeat(43),
      redirectUri: BOUND_REDIRECT,
    });
    await refreshGrant(profile, first.refresh_token as string);

    const error = await refreshGrant(profile, first.refresh_token as string).catch(
      (e: unknown) => e as EngineError,
    );
    expect((error as EngineError).code).toBe('expired_or_revoked');
    expect(mock?.violations).toEqual([]);
  });

  it('refuses to invent a refresh for a provider that has none', async () => {
    const profile = await slack();
    const error = await refreshGrant({ ...profile, refresh: 'none' }, 'anything').catch(
      (e: unknown) => e as EngineError,
    );
    expect((error as EngineError).code).toBe('config_invalid');
  });

  it('rejects confidential-client Basic auth instead of pretending to hold a secret', async () => {
    const profile = await slack();
    const error = await refreshGrant({ ...profile, refresh_auth: 'basic' }, 'anything').catch(
      (e: unknown) => e as EngineError,
    );
    expect((error as EngineError).code).toBe('config_invalid');
    expect((error as EngineError).hint).toContain('client secret');
  });

  it('supports the basic_empty_password axis without a branch (Reddit’s shape)', async () => {
    mock = await startMockAs({ mode: 'generic' });
    const profile: ProviderProfile = {
      ...ZOOM_SHAPE,
      name: 'reddit-shape',
      token_url: mock.tokenUrl,
      authorize_url: mock.authorizeUrl,
      refresh_auth: 'basic_empty_password',
    };
    await exchangeCode(profile, {
      code: 'mock-auth-code',
      verifier: 'v'.repeat(43),
      redirectUri: BOUND_REDIRECT,
    });
    await refreshGrant(profile, mock.current().refresh);

    const sent = mock.requests.at(-1);
    expect(sent?.authorization).toBe(`Basic ${Buffer.from('mockZoomPublicId:').toString('base64')}`);
    expect(sent?.params.client_secret).toBeUndefined();
    expect(mock.violations).toEqual([]);
  });
});
