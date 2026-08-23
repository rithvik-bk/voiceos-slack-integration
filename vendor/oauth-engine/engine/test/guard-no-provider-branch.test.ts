/**
 * GUARD (G1, must pass forever) — INV-CONFIG-1: zero `if (provider === …)` in engine/src.
 *
 * The whole thesis is "a provider is a ROW OF VALUES, one code path per capability value,
 * never one per provider." The instant an engine file branches on provider *identity* —
 * `if (provider === 'slack')`, `switch (provider)`, `profile.name === 'zoom'` — the
 * capability model is a lie and every new provider becomes an edit to the engine instead
 * of a new provider.json. This guard greps the source for that anti-pattern.
 *
 * The hard part is that the codebase *documents* the rule by quoting it: types.ts and
 * exchange.ts literally contain the words `if (provider === 'slack')` inside comments that
 * promise NOT to do it. A naïve grep goes red on the promise. So the detector strips
 * comments (and, in the structural pass, string *contents*) before it looks — a branch in
 * live code is caught, the same words in a comment or a doc string are not.
 *
 * Two passes, comment-stripped both times:
 *   1. NAME pass (strings kept): an equality/`case`/`switch` against a literal that is a
 *      known provider name — catches `x === 'slack'` for any left-hand side.
 *   2. STRUCTURAL pass (string contents blanked, quotes kept): a `provider`-family
 *      identifier compared to any string literal, or a `switch` whose head names provider —
 *      catches a branch on a provider name this test has never heard of.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

/** Names we ship or plan to; a comparison against any of these literals is a branch. */
const PROVIDER_NAMES = [
  'slack', 'zoom', 'reddit', 'github', 'linkedin', 'instagram', 'stripe', 'clickup',
  'notion', 'google', 'gmail', 'dropbox', 'discord', 'figma', 'jira', 'asana', 'salesforce',
];

/**
 * Blank out comments — and optionally string *contents* — while preserving every newline,
 * so a matched line number still points at real code. Quote delimiters are kept even when
 * contents are blanked, so `provider === 'x'` stays structurally visible as `provider === ' '`.
 */
function sanitize(src: string, blankStringContents: boolean): string {
  let out = '';
  let mode: 'code' | 'line' | 'block' | 'sq' | 'dq' | 'tpl' = 'code';
  for (let i = 0; i < src.length; i++) {
    const c = src[i]!;
    const c2 = src[i + 1];
    const nl = c === '\n';
    if (mode === 'code') {
      if (c === '/' && c2 === '/') { mode = 'line'; out += '  '; i++; continue; }
      if (c === '/' && c2 === '*') { mode = 'block'; out += '  '; i++; continue; }
      if (c === "'") { mode = 'sq'; out += "'"; continue; }
      if (c === '"') { mode = 'dq'; out += '"'; continue; }
      if (c === '`') { mode = 'tpl'; out += '`'; continue; }
      out += c;
      continue;
    }
    if (mode === 'line') {
      if (nl) { mode = 'code'; out += '\n'; continue; }
      out += ' ';
      continue;
    }
    if (mode === 'block') {
      if (c === '*' && c2 === '/') { mode = 'code'; out += '  '; i++; continue; }
      out += nl ? '\n' : ' ';
      continue;
    }
    // inside a string / template
    const quote = mode === 'sq' ? "'" : mode === 'dq' ? '"' : '`';
    if (c === '\\') { out += blankStringContents ? '  ' : src.slice(i, i + 2); i++; continue; }
    if (c === quote) { mode = 'code'; out += quote; continue; }
    out += blankStringContents ? (nl ? '\n' : ' ') : c;
  }
  return out;
}

const NAME_RE = new RegExp(
  String.raw`(?:===|!==|==|!=|\bcase)\s*['"](?:` + PROVIDER_NAMES.join('|') + String.raw`)['"]`,
);
// A provider-selecting identifier compared to a string literal, or a switch on one.
const STRUCT_EQ_RE = /\b(?:provider|providerName|provider_name|providerId|provider_id)\s*(?:===|!==|==|!=)\s*['"]/;
const STRUCT_SWITCH_RE = /\bswitch\s*\([^)]*\bprovider\b[^)]*\)/;

/** Line numbers (1-indexed) in `raw` that carry a per-provider branch. */
function findBranches(raw: string): number[] {
  const keepStrings = sanitize(raw, false).split('\n');
  const blankStrings = sanitize(raw, true).split('\n');
  const hits: number[] = [];
  for (let i = 0; i < keepStrings.length; i++) {
    const a = keepStrings[i]!;
    const b = blankStrings[i]!;
    if (NAME_RE.test(a) || STRUCT_EQ_RE.test(b) || STRUCT_SWITCH_RE.test(b)) hits.push(i + 1);
  }
  return hits;
}

function walk(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const full = join(dir, e.name);
    if (e.isDirectory()) return walk(full);
    return e.isFile() && e.name.endsWith('.ts') && !e.name.endsWith('.test.ts') ? [full] : [];
  });
}

describe('INV-CONFIG-1 — no per-provider branch in engine/src', () => {
  const files = walk(SRC);

  it('finds real engine source to scan (not a vacuous pass)', () => {
    expect(files.length).toBeGreaterThanOrEqual(10);
    expect(files.some((f) => f.endsWith('exchange.ts'))).toBe(true);
    expect(files.some((f) => f.endsWith(join('ui', 'pages.ts')))).toBe(true);
  });

  it.each(files.map((f) => [f.slice(SRC.length + 1), f]))(
    'engine/src/%s has zero provider-identity branches',
    (_label, file) => {
      const hits = findBranches(readFileSync(file, 'utf8'));
      expect(hits, `provider-identity branch(es) at line(s) ${hits.join(', ')}`).toEqual([]);
    },
  );

  // The detector must actually fire, or a clean report proves nothing.
  it('flags the branch shapes the invariant forbids', () => {
    expect(findBranches(`if (provider === 'slack') { doSlackThing(); }`)).toEqual([1]);
    expect(findBranches(`if (provider !== "zoom") return;`)).toEqual([1]);
    expect(findBranches(`if (profile.name === 'reddit') { }`)).toEqual([1]);
    expect(findBranches("switch (provider) {\n  case 'slack':\n    break;\n}")).toEqual([1, 2]);
    // provider-family identifier vs a name not on the known list is still structural.
    expect(findBranches(`if (providerName === 'someNewProvider') {}`)).toEqual([1]);
  });

  it('does not flag legitimate, provider-agnostic code', () => {
    // The registry lookup: comparing a parsed profile's name to the REQUESTED provider
    // variable is how getToken resolves a profile — RHS is a variable, not a literal.
    expect(findBranches(`if (parsed.name === provider) return parsed;`)).toEqual([]);
    // A guard against undefined is not a per-provider branch.
    expect(findBranches(`options.provider === undefined ? {} : {};`)).toEqual([]);
    // A switch on a capability VALUE (the whole point) is fine.
    expect(findBranches("switch (mode) {\n  case 'basic':\n    break;\n}")).toEqual([]);
    // The words inside a comment or a doc string never count.
    expect(findBranches(`// never write if (provider === 'slack')`)).toEqual([]);
    expect(findBranches(`/* forbidden: switch (provider) { case 'zoom': } */`)).toEqual([]);
    expect(findBranches("const doc = \"getToken('slack') resolves the slack profile\";")).toEqual([]);
  });
});
