#!/usr/bin/env node
/**
 * DRIFT CHECK (work item W13, invariant I-P1 / matrix invariant I1).
 *
 *   node tools/drift-check.mjs            # Phase 0 rules
 *   node tools/drift-check.mjs --phase 1  # + placeholders become hard failures
 *
 * Three things drift between a dashboard and a demo, and all three are silent:
 *   1. the redirect URI (a second spelling = a browser landing on a dead port, no error)
 *   2. the public-config filename (`connect-app.json` has SECRET semantics — §A4)
 *   3. a placeholder that shipped (`__REDDIT_USERNAME__` in a User-Agent is, precisely,
 *      lying about the user-agent — a ban offense, C-RDT-19)
 *
 * THE ALLOWLIST IS PART OF THE RULE, not an escape hatch bolted on afterwards.
 * A naive "only the ladder URIs exist anywhere" rule breaks the moment a provider needs a
 * sanctioned host-alias fallback or a doc quotes a foreign example URL verbatim. A rule
 * that can never go green teaches people to skip it, so the exact exemptions are enumerated
 * here, each with its reason, and nothing else passes:
 *
 *   A. the ladder itself, from engine/src/config.ts (the sole source)
 *   B. sanctioned fallbacks, from the same file (Zoom's pre-decided hosts-alias, §A11a)
 *   C. a bare `localhost:<ladder port>` authority with no path (prose)
 *   D. QUOTED_EXAMPLES — verbatim provider-doc / forum strings we are citing as evidence
 *   E. NOTATIONS — deliberate shorthand like `http://localhost:334xx/callback`
 *   F. a line carrying `drift-check:ignore-line`, or a file carrying `drift-check:ignore-file`
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  PORT_LADDER,
  REDIRECT_HOST,
  REDIRECT_URIS,
  SANCTIONED_FALLBACK_REDIRECTS,
} from '../engine/src/config.ts';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const PHASE = process.argv.includes('--phase') ? process.argv[process.argv.indexOf('--phase') + 1] : '0';

const SCAN_EXTENSIONS = ['.md', '.ts', '.mts', '.mjs', '.js', '.json', '.html', '.sh', '.cmd'];
const SKIP_DIRECTORIES = new Set(['node_modules', '.git', 'dist', 'coverage']);

/** D — verbatim third-party strings. Each is evidence we quote; none is our own config. */
const QUOTED_EXAMPLES = new Map([
  ['http://localhost:8080/auth', "Slack's own PKCE-page example [C-SL-02]"],
  ['https://localhost:3000/', 'Zoom devforum 4700 report [C-ZM-11]'],
  ['http://localhost:3000/api/zoom/callback', 'Zoom devforum 4700 report [C-ZM-12]'],
  ['localhost:3000', 'Zoom devforum 4700 report [C-ZM-11]'],
  ['http://127.0.0.1:{port}/', 'RFC 8252 §7.3 recommendation, quoted to record our deviation'],
  ['http://127.0.0.1', "Zoom redirect-field validation message, verbatim [C-ZM-24]"],
  ['http://[::1]', "Zoom redirect-field validation message, verbatim [C-ZM-24]"],
]);

/** E — deliberate shorthand / formulae for the whole ladder, not a fourth spelling. */
const NOTATIONS = new Set([
  'http://localhost:334xx/callback',
  'http://localhost:334(18|19|20',
  'http://localhost:${port}/callback',
  'http://localhost:<port>/callback',
  'http://localhost:<bound_port>/callback',
  'http://localhost:…',
]);

const ALLOWED = new Set([...REDIRECT_URIS, ...SANCTIONED_FALLBACK_REDIRECTS]);
const BARE_AUTHORITIES = new Set(PORT_LADDER.map((p) => `${REDIRECT_HOST}:${p}`));

/**
 * Anything that looks like it points at this machine, with its port and path if it has
 * them. A bare host — `localhost` in prose, `[::1]` in a sentence about the listener —
 * carries no port and no path and is skipped below: prose is not configuration.
 */
const LOOPBACK =
  /(?:https?:\/\/)?(?:localhost|127\.0\.0\.1|\[::1\]|voiceos\.test)(?::[^\s"'`)\],]*)?(?:\/[^\s"'`)\],]*)?/g;

/** Hosts that are never ours to redirect to, even scheme-only: the ladder speaks `localhost` (§3.4). */
const WRONG_HOSTS = ['127.0.0.1', '[::1]'];

/** A mention of the forbidden filename is fine only where it is being forbidden. */
const FORBIDDING = /never|forbidden|gitignor|secret semantics|permanently|deliberately NOT used|§A4|A4\b/i;

function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) return SKIP_DIRECTORIES.has(entry.name) ? [] : walk(full);
    return SCAN_EXTENSIONS.some((ext) => entry.name.endsWith(ext)) ? [full] : [];
  });
}

function trimPunctuation(match) {
  return match.replace(/[.,;:)]+$/, '');
}

/**
 * Prose, not configuration: a host named in a sentence, with no port and no path.
 * `http://127.0.0.1` is NOT prose — writing the wrong host into a URL is the drift.
 */
function isProse(value) {
  const scheme = /^https?:\/\//.test(value);
  const host = value.replace(/^https?:\/\//, '');
  const bare = /^(?:localhost|127\.0\.0\.1|\[::1\]|voiceos\.test)$/.test(host);
  if (!bare) return false;
  if (!scheme) return true;
  return !WRONG_HOSTS.includes(host);
}

const violations = [];
function flag(file, line, text, why) {
  violations.push({ file: relative(REPO, file), line, text, why });
}

for (const file of walk(REPO)) {
  const body = readFileSync(file, 'utf8');
  if (body.includes('drift-check:ignore-file')) continue;
  const isSelf = file.endsWith(join('tools', 'drift-check.mjs'));

  body.split('\n').forEach((line, index) => {
    const lineNumber = index + 1;
    if (line.includes('drift-check:ignore-line')) return;

    if (!isSelf) {
      for (const raw of line.match(LOOPBACK) ?? []) {
        const value = trimPunctuation(raw);
        if (isProse(value)) continue; // a host named in a sentence, not a redirect URI
        if (ALLOWED.has(value)) continue;
        if (BARE_AUTHORITIES.has(value)) continue;
        if (QUOTED_EXAMPLES.has(value)) continue;
        if (NOTATIONS.has(value)) continue;
        flag(file, lineNumber, value, 'redirect-URI drift — not the ladder, not a sanctioned fallback, not an allowlisted quote');
      }
    }

    if (line.includes('connect-app.json') && !FORBIDDING.test(line) && !isSelf && !file.endsWith('.gitignore')) {
      flag(file, lineNumber, 'connect-app.json', 'forbidden public-config filename (§A4) used as if it were ours');
    }

    // Phase 1: only SHIPPED config may not carry placeholders. Docs and the schema
    // describe them by name on purpose, and the template exists to be filled in.
    const isShippedConfig =
      file.includes(`${join('providers', '')}`) && !file.includes('_template');
    if (PHASE === '1' && isShippedConfig && /__[A-Z_]+__/.test(line)) {
      const token = line.match(/__[A-Z_]+__/)[0];
      flag(file, lineNumber, token, 'placeholder still present in Phase 1 (a shipped __REDDIT_USERNAME__ is a UA lie — C-RDT-19)');
    }
  });
}

/* Cross-check any provider.json profiles against the sole source. The engine repo ships
 * no bundled integrations, so this scans an optional `providers/` folder if one is present
 * (a host that vendors its own profiles here gets the same drift guard for free). */
const integrations = join(REPO, 'providers');
let profileDirs = [];
try {
  profileDirs = readdirSync(integrations);
} catch {
  profileDirs = []; // no providers/ folder — nothing to cross-check
}
for (const name of profileDirs) {
  const file = join(integrations, name, 'provider.json');
  try {
    statSync(file);
  } catch {
    continue;
  }
  const profile = JSON.parse(readFileSync(file, 'utf8'));
  if (profile.redirect_strategy === 'loopback' && profile.redirect_host !== REDIRECT_HOST) {
    // A non-default loopback host is legal ONLY if every URI it produces is sanctioned
    // in config.ts (Zoom's 127.0.0.1 ladder, C-ZM-24) — the sole source still rules.
    const uris = (profile.redirect_ports ?? []).map((p) => `http://${profile.redirect_host}:${p}/callback`);
    if (uris.length === 0 || !uris.every((u) => ALLOWED.has(u))) {
      flag(file, 0, String(profile.redirect_host), `redirect_host must be '${REDIRECT_HOST}' or produce only sanctioned URIs (config.ts is the sole source)`);
    }
  }
  for (const port of profile.redirect_ports ?? []) {
    if (!PORT_LADDER.includes(port)) flag(file, 0, String(port), 'port is not a rung of PORT_LADDER');
  }
  if (!PORT_LADDER.slice(0, profile.redirect_ports?.length ?? 0).every((p, i) => p === profile.redirect_ports[i])) {
    flag(file, 0, JSON.stringify(profile.redirect_ports), 'redirect_ports must be a prefix of PORT_LADDER, in ladder order');
  }
}

if (violations.length === 0) {
  console.log(`drift-check: green — ladder ${REDIRECT_URIS.join(' ')} (phase ${PHASE})`);
  process.exit(0);
}
console.error(`drift-check: ${violations.length} violation(s) (phase ${PHASE})`);
for (const v of violations) console.error(`  ${v.file}:${v.line}  ${v.text}  — ${v.why}`);
process.exit(1);
