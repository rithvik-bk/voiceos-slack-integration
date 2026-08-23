/**
 * Tests for the push gate (tools/scan-secrets.mjs).
 *
 * Every token-shaped literal here is assembled at runtime from fragments. Writing one as a
 * literal would plant a real finding in a real repo file — the scanner would be correct to
 * fail, and the honest fix would be a second allowlist entry, which is exactly the erosion
 * the one-entry rule exists to prevent.
 */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCANNER = join(REPO, 'tools', 'scan-secrets.mjs');

/** Assembled, never a literal — see the file header. */
const SLACK = `xox${'p'}-A1b2C3d4E5f6G7h8i9J0kLmN`;
const CANARY = `xox${'p'}-do-not-log-me`;
const STRIPE = `sk_${'test'}_51QwErTyUiOpAsDfGhJkLzXc`;

const roots: string[] = [];

function sandbox(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'scan-secrets-'));
  roots.push(root);
  for (const [name, body] of Object.entries(files)) {
    const full = join(root, name);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, body);
  }
  return root;
}

function scan(root: string) {
  const run = spawnSync(process.execPath, [SCANNER, root], { encoding: 'utf8' });
  return { status: run.status, out: `${run.stdout}${run.stderr}` };
}

afterEach(() => {
  roots.length = 0; // mkdtemp dirs live under the OS temp dir; the OS reaps them
});

describe('scan-secrets', () => {
  it('catches a planted Slack token and fails the build', () => {
    const { status, out } = scan(sandbox({ 'notes/leak.md': `token: ${SLACK}\n` }));
    expect(status).toBe(1);
    expect(out).toContain('notes/leak.md:1');
    expect(out).toContain('slack_token');
  });

  it('catches every Slack token prefix, not just the user token', () => {
    // xoxb bot, xoxe rotating refresh, xoxd browser cookie — all leak the same way.
    for (const kind of ['b', 'e', 'd', 'c', 'r', 's']) {
      const planted = `xox${kind}-2345678901-2345678901234-AbCdEfGhIjKlMnOp`;
      const { status } = scan(sandbox({ 'leak.txt': planted }));
      expect(status, `xox${kind}- must be caught`).toBe(1);
    }
  });

  it('never prints the secret it found', () => {
    const { out } = scan(sandbox({ 'leak.txt': `${SLACK}\n` }));
    expect(out).not.toContain(SLACK);
    expect(out).toContain(`${SLACK.slice(0, 5)}…`); // redacted preview only
  });

  it('catches every rule class the contract names', () => {
    const root = sandbox({
      'a.env': `STRIPE=${STRIPE}\n`,
      'b.json': `{"${'client'}_secret": "9f3c1b7ad2e64f88ba51"}\n`,
      'c.txt': `enc:${'v1'}:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n`,
      'd.pem': `-----BEGIN RSA ${'PRIVATE'} KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n`,
      'e.ts': `const h = { Authorization: 'Bearer ${'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}' };\n`,
    });
    const { status, out } = scan(root);
    expect(status).toBe(1);
    for (const rule of ['stripe_key', 'client_secret_value', 'vault_blob', 'pem_private_key', 'bearer_header']) {
      expect(out, `${rule} must fire`).toContain(rule);
    }
  });

  it('does not fire on the words themselves, or on placeholders', () => {
    // Every one of these shapes is real, and present in this repo's docs today.
    const { status, out } = scan(
      sandbox({
        'docs.md': [
          'Public clients send no `client_secret` at refresh.',
          'The vault stores an enc:v1-style blob, never a token.',
          'Slack samples an access token as "xoxp-1234" and a refresh as "xoxe-1-abcd".',
        ].join('\n'),
        'template.json': '{ "client_secret": "__SLACK_CLIENT_SECRET__" }',
        'shell.sh': 'curl -d client_secret=$SLACK_CLIENT_SECRET https://example.com',
        'schema.test.ts': "expect(validate({ client_secret: 'shhh' })).toMatch(/client_secret/);",
        'paths.ts': "const p = { token_path: 'authed_user.access_token' };",
        'mock-as.ts': "access_token: 'mock-bot-token-do-not-use',",
      }),
    );
    expect(out).toContain('clean');
    expect(status).toBe(0);
  });

  it('does not let a stand-in vocabulary launder a provider-prefixed token', () => {
    // `mock-…` as a bare value is a stand-in; `xoxp-mock-…` has a real token's shape and a
    // real token's blast radius, so the value vocabulary must not reach it.
    const { status } = scan(sandbox({ 'mock-as.ts': `access_token: '${SLACK}-mock',` }));
    expect(status).toBe(1);
  });

  it('exempts the canary by value, not by location', () => {
    // The canary passes wherever it is quoted...
    const allowed = scan(sandbox({ 'engine/test/public-api.test.ts': `const secret = '${CANARY}';\n` }));
    expect(allowed.status).toBe(0);

    // ...and the exemption does not extend to anything else in that same file.
    const planted = scan(
      sandbox({ 'engine/test/public-api.test.ts': `const secret = '${CANARY}';\nconst oops = '${SLACK}';\n` }),
    );
    expect(planted.status).toBe(1);
    expect(planted.out).toContain('public-api.test.ts:2');
  });

  it('passes this repo', () => {
    const run = spawnSync(process.execPath, [SCANNER], { cwd: REPO, encoding: 'utf8' });
    expect(`${run.stdout}${run.stderr}`).toContain('clean');
    expect(run.status).toBe(0);
  });

  it('is wired into `npm run check`, so the gate cannot be skipped', () => {
    const pkg = JSON.parse(readFileSync(join(REPO, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(pkg.scripts.scan).toContain('scan-secrets.mjs');
    expect(pkg.scripts.check).toContain('scan');
  });
});
