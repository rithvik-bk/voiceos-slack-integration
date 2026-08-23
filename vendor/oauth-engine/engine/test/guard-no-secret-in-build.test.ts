/**
 * GUARD (G1, must pass forever) — INV-SECRET-1 / INV-SECRET-4: no secret-shaped string
 * survives into build output or into a log line. It extends the existing push-gate scanner
 * (tools/scan-secrets.mjs), which today scans the SOURCE tree, to two surfaces the source
 * scan does not cover:
 *
 *   A. BUILD OUTPUT. The engine runs as node-native TypeScript (no emit step in normal
 *      operation), but any distribution — a bundle, a transpile, a local install stage —
 *      turns these files into emitted JS. This transpiles every engine/src file to JS and
 *      runs the real scanner over the result: a secret introduced in a way that only
 *      appears post-strip (or that the source scan happened to miss) is caught here.
 *
 *   B. LOGS. VoiceOS writes MCP stderr to disk, so a credential that reaches a log line is
 *      a credential on disk. This drives real credential-shaped values through the engine's
 *      redaction boundary (engine/src/redact.ts), writes the RESULT to a file, and runs the
 *      scanner over it. The redacted log must be clean; the raw value must NOT be (the
 *      positive control that proves the scanner would have caught a leak).
 *
 * Every token-shaped literal in this file is assembled from fragments at runtime, so the
 * file itself plants no finding for the source scan (same rule as scan-secrets.test.ts).
 */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as ts from 'typescript';
import { describe, expect, it } from 'vitest';

import { redact, safeProviderMessage } from '../src/redact.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..');
const SRC = join(HERE, '..', 'src');
const SCANNER = join(REPO, 'tools', 'scan-secrets.mjs');

/** Assembled, never a literal — writing these plainly would plant a real finding. */
const SLACK = `xox${'p'}-A1b2C3d4E5f6G7h8i9J0kLmNoPqRsTuV`;
const REFRESH = `xox${'e'}-1-Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0`;
const JWT = `eyJ${'hbGciOiJIUzI1NiJ9'}.${'eyJzdWIiOiIxMjM0NTY3ODkwIn0'}.${'Kx7cQf3n2mLpZ0aWqErTyUiOpAsDfGhJ'}`;

function walk(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const full = join(dir, e.name);
    if (e.isDirectory()) return walk(full);
    return e.isFile() && e.name.endsWith('.ts') ? [full] : [];
  });
}

function scan(dir: string): { status: number | null; out: string } {
  const run = spawnSync(process.execPath, [SCANNER, dir], { encoding: 'utf8' });
  return { status: run.status, out: `${run.stdout}${run.stderr}` };
}

describe('INV-SECRET-1 — build output carries no secret-shaped string', () => {
  it('transpiles engine/src to JS and the scanner reports it clean', () => {
    const out = mkdtempSync(join(tmpdir(), 'build-output-'));
    const files = walk(SRC);
    expect(files.length).toBeGreaterThanOrEqual(10);
    for (const file of files) {
      const js = ts.transpileModule(readFileSync(file, 'utf8'), {
        compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2023 },
      }).outputText;
      writeFileSync(join(out, `${relative(SRC, file).replace(/[\\/]/g, '__')}.js`), js);
    }
    const { status, out: log } = scan(out);
    expect(log, log).toContain('clean');
    expect(status).toBe(0);
  });

  it('the build-output scan actually fires when a secret is present (control)', () => {
    const out = mkdtempSync(join(tmpdir(), 'build-output-dirty-'));
    writeFileSync(join(out, 'leaked.js'), `const t = "${SLACK}";\n`);
    const { status, out: log } = scan(out);
    expect(status).toBe(1);
    expect(log).toContain('slack_token');
    expect(log).not.toContain(SLACK); // the scanner never echoes the value
  });
});

describe('INV-SECRET-4 — redacted logs carry no secret-shaped string', () => {
  it('scrubs every credential shape it is handed, and the scanner confirms it', () => {
    const held = [SLACK, REFRESH];
    const logLines = [
      redact(`token=${SLACK} exchanged ok`, held),
      redact(`refresh rotated to ${REFRESH}`, held),
      redact(`Authorization: Bearer ${JWT}`),
      // A provider error body must yield a credential-free quote even with a token beside it.
      safeProviderMessage({ error: 'invalid_grant', access_token: SLACK }, held) ?? '',
    ].join('\n');

    // The redactor must have removed the raw values before we even reach the scanner.
    expect(logLines).not.toContain(SLACK);
    expect(logLines).not.toContain(REFRESH);
    expect(logLines).not.toContain(JWT);

    const dir = mkdtempSync(join(tmpdir(), 'engine-log-'));
    writeFileSync(join(dir, 'mcp-stderr.log'), `${logLines}\n`);
    const { status, out } = scan(dir);
    expect(out, out).toContain('clean');
    expect(status).toBe(0);
  });

  it('the log scan actually fires on an UNredacted value (control)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'engine-log-dirty-'));
    writeFileSync(join(dir, 'mcp-stderr.log'), `refresh_token=${REFRESH}\n`);
    expect(scan(dir).status).toBe(1);
  });

  it('is anchored to the same scanner the push gate uses', () => {
    const pkg = JSON.parse(readFileSync(join(REPO, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(pkg.scripts.scan).toContain('scan-secrets.mjs');
  });
});
