/**
 * C-21 / SPEC §18 — the falsifiable claim: "lines of authorization code in a new integration
 * equals zero." That is worth saying only because it can be proven false, so this test tries to.
 *
 * `test/fixtures/newapp-tools.ts` is a complete tool file for a brand-new provider. Two proofs:
 *
 *  1. COUNT — strip its comments, then grep the live code for every authorization construct a
 *     hand-rolled integration would contain (a token variable, a Bearer/Authorization header, a
 *     refresh, PKCE, an exchange, a client secret, the lower-level auth accessors). The count
 *     must be zero. `auth.client(...)` is the one allowed line and is explicitly not a match.
 *
 *  2. IT ACTUALLY WORKS — run those same auth-free tools against the live mock provider and get
 *     real, authenticated data back. Zero auth code that also fails to authenticate would be a
 *     cheat; this proves the file is genuinely auth-free AND genuinely authenticated.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import { registerProvider } from '../src/index.ts';
import { deleteToken, putToken } from '../src/vault.ts';
import type { ProviderProfile, TokenRecord } from '../src/types.ts';
import { startMockAs } from './mock-as.ts';
import type { MockAs } from './mock-as.ts';
import { whoAmI, createThing } from './fixtures/newapp-tools.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(HERE, 'fixtures', 'newapp-tools.ts');
const PROVIDER = 'newapp';
const LOCK = join(tmpdir(), `voiceos-connect-${PROVIDER}.refresh.lock`);

/** Blank comments (line + block), preserving newlines so a hit still points at real code. */
function stripComments(src: string): string {
  let out = '';
  let mode: 'code' | 'line' | 'block' = 'code';
  for (let i = 0; i < src.length; i++) {
    const c = src[i]!;
    const c2 = src[i + 1];
    if (mode === 'code') {
      if (c === '/' && c2 === '/') { mode = 'line'; i++; continue; }
      if (c === '/' && c2 === '*') { mode = 'block'; i++; continue; }
      out += c;
      continue;
    }
    if (mode === 'line') {
      if (c === '\n') { mode = 'code'; out += '\n'; }
      continue;
    }
    if (c === '*' && c2 === '/') { mode = 'code'; i++; continue; }
    if (c === '\n') out += '\n';
  }
  return out;
}

/** The auth constructs a from-scratch integration would carry — every one is banned in a tool file. */
const AUTH_CONSTRUCTS: ReadonlyArray<readonly [string, RegExp]> = [
  ['access/refresh token variable', /\b(?:access_token|refresh_token|accessToken|refreshToken)\b/i],
  ['a bearer/authorization header', /\b(?:bearer|authorization)\b/i],
  ['a DPoP proof', /\bdpop\b/i],
  ['a refresh call', /\brefresh\w*\s*\(/i],
  ['PKCE', /\bpkce|code_verifier|code_challenge\b/i],
  ['a client secret', /\bclient_secret\b/i],
  ['an OAuth token exchange', /\b(?:grant_type|exchangeCode|token_url|oauth)\b/i],
  ['the lower-level token accessors', /\b(?:getToken|getFreshToken|authorizedFetch|auth\.token)\b/],
];

function genericProfile(as: MockAs): ProviderProfile {
  return {
    name: PROVIDER,
    display_name: 'New App',
    client_id: 'mock.client.id',
    client_type: 'public',
    pkce: 'S256',
    redirect_strategy: 'loopback',
    redirect_host: 'localhost',
    redirect_ports: [33420],
    authorize_url: as.authorizeUrl,
    token_url: as.tokenUrl,
    api_base: as.origin,
    scopes: ['read'],
    scope_param: 'scope',
    token_auth: 'none',
    refresh_auth: 'client_id_body',
    token_path: 'access_token',
    refresh: 'rotation',
    rotation: 'optional-enabled',
    access_token_ttl: 3600,
    identity_probe: { url: as.identityUrl, handle_path: 'display_name' },
  };
}

let mock: MockAs;

beforeEach(async () => {
  mock = await startMockAs({ mode: 'generic' });
  await rm(LOCK, { force: true });
});

afterEach(async () => {
  await deleteToken(PROVIDER).catch(() => undefined);
  await rm(LOCK, { force: true });
  await mock.close();
});

describe('C-21 — auth lines in a new integration = 0', () => {
  it('the fixture tool file contains zero authorization constructs', () => {
    const code = stripComments(readFileSync(FIXTURE, 'utf8'));
    const hits: string[] = [];
    for (const [label, re] of AUTH_CONSTRUCTS) {
      if (re.test(code)) hits.push(label);
    }
    expect(hits, `authorization code found in a tool file: ${hits.join(', ')}`).toEqual([]);
  });

  it('the detector actually fires (a hand-rolled auth line would be caught)', () => {
    const handRolled = `const token = await getToken('x'); fetch(u, { headers: { Authorization: 'Bearer ' + token } });`;
    const hits = AUTH_CONSTRUCTS.filter(([, re]) => re.test(handRolled)).map(([l]) => l);
    expect(hits.length).toBeGreaterThan(0);
  });

  it('the same auth-free tools authenticate for real against a live provider', async () => {
    registerProvider(genericProfile(mock));
    const record: TokenRecord = {
      provider: PROVIDER,
      access_token: mock.current().access,
      refresh_token: mock.current().refresh,
      expires_at: Date.now() + 3_600_000,
      scopes: ['read'],
      obtained_at: Date.now(),
    };
    await putToken(PROVIDER, record);

    const me = await whoAmI();
    expect(me.display_name).toBe('Rithvik');

    // A 404 from the mock's unknown route is returned, not thrown — the tool file never sees auth.
    const created = await createThing('widget');
    expect(created.status).toBe(404);
    expect(mock.violations).toEqual([]);
  });
});
