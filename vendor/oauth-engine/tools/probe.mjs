#!/usr/bin/env node
/**
 * `handshake probe` — the conformance probe CLI (C-1, C-18 · SPEC Part 1 §2, §20 rung 2).
 *
 * Points the probe at ONE provider, runs the safe measurement sequence (RFC 8414 / OIDC
 * discovery → unauthenticated-exchange client-auth classification → redirect tolerance), and
 * writes `providers/<name>.json` + `providers/<name>.evidence.json`. "Every claim in the
 * matrix has a receipt" (§2), and any field the probe cannot determine is written as
 * `unknown` (INV-CONFIG-5) — there is no guessing.
 *
 * Usage:
 *   node tools/probe.mjs <target-url> --name <name> [options]
 *
 *   <target-url>          Documentation URL, issuer origin, or authorize endpoint (rung 2).
 *   --name <name>         Stable provider key (vault/getToken key). Defaults to the host.
 *   --display <name>      Human display name. Defaults to --name.
 *   --client-id <id>      Public client id (NOT a secret) — sharpens classification.
 *   --authorize-url <u>   Explicit authorize endpoint when discovery omits it.
 *   --token-url <u>       Explicit token endpoint when discovery omits it.
 *   --scopes <a,b,c>      Scopes the connect will request (enables scope_grant later).
 *   --out <dir>           Output directory. Default: ./providers
 *   --no-redirect         Skip network authorize probing (offline discovery-only run).
 *   --print               Also print the profile + evidence to stdout.
 *
 * Zero runtime dependencies. This CLI never accepts a client SECRET on argv, in an env var,
 * or in a file — the engine is architecturally secret-free and so is its probe.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { probe, serialize } from '../engine/src/probe/index.ts';

function parseArgs(argv) {
  const opts = { out: 'providers', probeRedirect: true, print: false };
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--name': opts.name = argv[++i]; break;
      case '--display': opts.display = argv[++i]; break;
      case '--client-id': opts.clientId = argv[++i]; break;
      case '--authorize-url': opts.authorizeUrl = argv[++i]; break;
      case '--token-url': opts.tokenUrl = argv[++i]; break;
      case '--scopes': opts.scopes = String(argv[++i]).split(',').map((s) => s.trim()).filter(Boolean); break;
      case '--out': opts.out = argv[++i]; break;
      case '--no-redirect': opts.probeRedirect = false; break;
      case '--print': opts.print = true; break;
      default:
        if (arg.startsWith('--')) { console.error(`unknown flag: ${arg}`); process.exit(2); }
        positional.push(arg);
    }
  }
  opts.target = positional[0];
  return opts;
}

function defaultName(target) {
  try { return new URL(target).hostname.replace(/^www\./, '').split('.')[0]; }
  catch { return undefined; }
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!opts.target) {
    console.error('usage: node tools/probe.mjs <target-url> --name <name> [options]');
    process.exit(2);
  }
  const name = opts.name ?? defaultName(opts.target);
  if (!name) {
    console.error('could not derive a provider name from the target — pass --name');
    process.exit(2);
  }

  const result = await probe({
    name,
    display_name: opts.display,
    target: opts.target,
    client_id: opts.clientId,
    authorize_url: opts.authorizeUrl,
    token_url: opts.tokenUrl,
    scopes: opts.scopes,
    probeRedirect: opts.probeRedirect,
  });

  const out = serialize(result);
  const dir = resolve(process.cwd(), opts.out);
  mkdirSync(dir, { recursive: true });
  const profilePath = resolve(dir, out.profile_filename);
  const evidencePath = resolve(dir, out.evidence_filename);
  writeFileSync(profilePath, out.profile_json);
  writeFileSync(evidencePath, out.evidence_json);

  const p = result.profile;
  const unknowns = Object.entries(p).filter(([, v]) => v === 'unknown').map(([k]) => k);
  console.log(`probed ${name}`);
  console.log(`  discovery:     ${p.discovery}`);
  console.log(`  client_auth:   ${p.client_auth}`);
  console.log(`  custody_class: ${p.custody_class}`);
  console.log(`  unknown fields: ${unknowns.length ? unknowns.join(', ') : 'none'}`);
  console.log(`  receipts:      ${result.evidence.receipts.length}`);
  console.log(`  wrote ${profilePath}`);
  console.log(`  wrote ${evidencePath}`);
  if (opts.print) {
    console.log('\n--- profile ---\n' + out.profile_json);
    console.log('--- evidence ---\n' + out.evidence_json);
  }
}

main().catch((err) => {
  console.error('probe failed:', err && err.message ? err.message : err);
  process.exit(1);
});
