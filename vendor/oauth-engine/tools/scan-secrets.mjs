#!/usr/bin/env node
/**
 * SECRET SCAN (work item P1-I10) — the GitHub-push gate.
 *
 *   node tools/scan-secrets.mjs            # scan this repo
 *   node tools/scan-secrets.mjs <dir>      # scan anything else (used by its own test)
 *
 * exit 0 = clean · exit 1 = findings · exit 2 = usage error.
 *
 * Three design decisions worth the ink:
 *
 * 1. IT NEVER PRINTS WHAT IT FOUND. A scanner that echoes the token into CI output has
 *    published the token to a second place. Findings are `file:line  rule  xoxp-…(19)`.
 *
 * 2. IT MATCHES VALUES, NOT WORDS. This repo's docs discuss `client_secret` and `enc:v1`
 *    on nearly every page, and quote Slack's own doc samples (`xoxp-1234`). A rule that
 *    fires on the *identifier* goes red on prose, gets suppressed, and is then blind on
 *    the day it matters — so every rule requires credential-shaped material after the
 *    identifier, and short doc samples fall under the length floors on purpose.
 *
 * 3. THE ALLOWLIST IS ONE ENTRY, PINNED BY HASH. Exactly one deliberate fake exists in
 *    this repo: the canary in engine/test/public-api.test.ts that proves an EngineError
 *    can never carry a credential. It is allowlisted by SHA-256 of its value, so (a) this
 *    file contains no token-shaped literal of its own, and (b) editing the canary into a
 *    real token turns the gate red instead of inheriting the exemption.
 */

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(join(dirname(fileURLToPath(import.meta.url)), '..'));
const ROOT = resolve(process.argv[2] ?? REPO);

const SKIP_DIRECTORIES = new Set(['node_modules', '.git', 'dist', 'coverage', '.vitest']);
const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.icns', '.ico', '.pdf', '.zip', '.gz', '.tgz',
  '.woff', '.woff2', '.ttf', '.otf', '.mp3', '.mp4', '.mov', '.wav', '.asar', '.node',
]);
const MAX_BYTES = 2_000_000;

/** A NUL byte means "not text" — built at runtime so this file stays clean ASCII. */
const NUL_BYTE = String.fromCharCode(0);

/**
 * Values that are obviously stand-ins, not credentials. Applied to the *captured value*
 * of the assignment-shaped rules only — never to the token-shaped ones, which carry their
 * provider's prefix and are therefore never "just a variable name".
 */
const PLACEHOLDER = [
  /^__[A-Z0-9_]+__$/,                       // __SLACK_CLIENT_SECRET__
  /^[<{$%]/,                                // <secret>, ${SECRET}, $SECRET, %SECRET%
  /\$\{/,                                   // "${env.SECRET}"
  /^[A-Z][A-Z0-9_]*$/,                      // SLACK_CLIENT_SECRET (an env var NAME)
  // A value that opens by announcing it is not real. A genuine credential never does, and
  // `mock-bot-token-do-not-use` in the mock AS is the shape this list exists for — note the
  // vocabulary applies to VALUE rules only, so `xoxp-mock-…` is still a finding.
  /^(?:your|my|the|an?|example|sample|test|fake|dummy|mock|stub|canary|bogus|invalid|placeholder|redacted|hidden|none|null|undefined|todo|tbd|xxx+|abc+|foo|bar)\b/i,
  /^process\.env|^os\.environ|^Deno\.env/,  // a lookup, not a value
  /^[a-z_]+(?:\.[a-z_]+)+$/,                // authed_user.access_token — a dotted path
  /^[.…]/,
  /^(.)\1+$/,                               // aaaaaaaa
];

/**
 * Every rule is `{ id, pattern, capture }`. `capture: true` means group 1 is the value to
 * placeholder-test; otherwise the whole match is the credential.
 *
 * Length floors, and why each is where it is:
 *   slack_token   10  — Slack's published samples are `xoxp-1234` / `xoxe-1-abcd`; every
 *                       real token is far longer. The test canary (13) is caught, and then
 *                       allowlisted by hash, which is what proves the rule works at all.
 *   stripe_key     8  — sk_test_/sk_live_ are never written with a short sample here.
 *   value rules   16  — below that a "secret" is a word like `shhh` in a schema test.
 */
const RULES = [
  // xox[a-z] rather than the five documented prefixes: xoxc/xoxd (browser session tokens)
  // are the ones that leak by accident, and a prefix Slack adds next year is still caught.
  { id: 'slack_token', pattern: /xox[a-z]-[A-Za-z0-9-]{10,}/g, capture: false },
  { id: 'stripe_key', pattern: /sk_(?:test|live)_[A-Za-z0-9]{8,}/g, capture: false },
  { id: 'pem_private_key', pattern: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/g, capture: false },
  { id: 'vault_blob', pattern: /enc:v1:[A-Za-z0-9+/=_-]{16,}/g, capture: false },
  {
    id: 'client_secret_value',
    pattern: /client_secret["'`]?\s*[:=]\s*["'`]?([^\s"'`,;&})\]]{8,})/g,
    capture: true,
  },
  {
    id: 'token_value',
    pattern:
      /(?:access_token|refresh_token|api[_-]?key|secret[_-]?key|private[_-]?key|password)["'`]?\s*[:=]\s*["'`]([A-Za-z0-9._~+/=-]{16,})["'`]/g,
    capture: true,
  },
  { id: 'bearer_header', pattern: /Bearer\s+([A-Za-z0-9._~+/=-]{20,})/g, capture: true },
];

/**
 * THE ENTIRE ALLOWLIST. One entry. Adding a second one is a decision for the auditor,
 * not a convenience for a builder whose scan went red.
 *
 * The exemption is the VALUE, not a location: `engine/test/public-api.test.ts` holds the
 * canary, and the same literal is quoted verbatim by the frozen build contract and the
 * brief that specifies this scanner, so a path-scoped entry would need one exemption per
 * document that discusses the test. Pinning the SHA-256 keeps that safe — any *other*
 * token-shaped string, including one planted in the canary's own file, still fails.
 */
const ALLOWLIST = [
  {
    rule: 'slack_token',
    sha256: '3e82cd7affaf6d98a85c142486d7bf1437cc4781e758584f33970ed93023a555',
    home: join('engine', 'test', 'public-api.test.ts'),
    reason: 'deliberate fake: the canary proving an EngineError never carries a credential',
  },
];

function sha256(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function isAllowlisted(ruleId, value) {
  const hash = sha256(value);
  return ALLOWLIST.some((e) => e.rule === ruleId && e.sha256 === hash);
}

/** `xoxp-…(19)` — enough to find it in the file, not enough to be the credential. */
function redact(value) {
  return `${value.slice(0, 5)}…(${value.length})`;
}

function walk(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  return entries.flatMap((entry) => {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) return SKIP_DIRECTORIES.has(entry.name) ? [] : walk(full);
    if (!entry.isFile()) return [];
    if (BINARY_EXTENSIONS.has(extname(entry.name).toLowerCase())) return [];
    return [full];
  });
}

function readText(file) {
  try {
    if (statSync(file).size > MAX_BYTES) return null;
    const body = readFileSync(file, 'utf8');
    return body.includes(NUL_BYTE) ? null : body; // undeclared binary
  } catch {
    return null;
  }
}

const findings = [];

for (const file of walk(ROOT)) {
  const body = readText(file);
  if (body === null) continue;
  const shown = relative(ROOT, file);

  body.split('\n').forEach((line, index) => {
    for (const rule of RULES) {
      rule.pattern.lastIndex = 0;
      for (const match of line.matchAll(rule.pattern)) {
        const value = rule.capture ? match[1] : match[0];
        if (value === undefined) continue;
        if (rule.capture && PLACEHOLDER.some((p) => p.test(value))) continue;
        if (isAllowlisted(rule.id, value)) continue;
        findings.push({ file: shown, line: index + 1, rule: rule.id, value });
      }
    }
  });
}

if (findings.length === 0) {
  console.log(`scan-secrets: clean — ${RULES.length} rules over ${relative(REPO, ROOT) || '.'}`);
  process.exit(0);
}

console.error(`scan-secrets: ${findings.length} finding(s) — nothing may be pushed`);
for (const f of findings) console.error(`  ${f.file}:${f.line}  ${f.rule}  ${redact(f.value)}`);
process.exit(1);
