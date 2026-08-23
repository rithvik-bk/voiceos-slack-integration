/**
 * Slack ⇄ VoiceOS — MCP stdio server (P1-I8, rebuilt for Phase S).
 *
 * This file is deliberately boring: JSON-RPC in, JSON-RPC out, and one call into `tools.ts`.
 * The three laws it inherits from `_template/server.ts` and may never break:
 *
 *  1. **stdout is the MCP wire.** Only JSON-RPC frames go there. Diagnostics go to stderr,
 *     and never a token, code or verifier — VoiceOS writes MCP stderr to disk, which is
 *     exactly the back door that would defeat "tokens never touch disk."
 *  2. **Nothing at import time touches the network.** Their client enforces a 30s connect
 *     gate and a 60s per-tool timeout; a DNS lookup at module load is how you earn a -32000.
 *  3. **connect returns in ~1s.** The browser dance finishes out of band and is polled with
 *     `slack_status(connect_id)`. A tool call never blocks on a human clicking Allow.
 *
 * Phase S adds exactly one act to startup — C1, the toggle-on auto-open. Read law 2 again
 * before touching it: `scheduleStartupAutoConnect()` is NOT awaited and does its work on an
 * unref'd timer, so the 30s `listTools()` gate is never spent waiting on a vault read.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { ProviderProfile } from './engine/index.ts';

import { scheduleStartupAutoConnect } from './lifecycle.ts';
import { callTool, createSlackCtx, toWirePayload } from './tools.ts';

const HERE = dirname(fileURLToPath(import.meta.url));

/** The manifest is the single source of the tool list — tools/list is served from it. */
interface ManifestTool {
  name: string;
  title?: string;
  description: string;
  inputSchema: Record<string, unknown>;
}
interface Manifest {
  name: string;
  version: string;
  tools: ManifestTool[];
}

function readJson<T>(file: string): T {
  return JSON.parse(readFileSync(join(HERE, file), 'utf8')) as T;
}

const manifest = readJson<Manifest>('voiceos.integration.json');
const profile = readJson<ProviderProfile>('provider.json');

function log(line: string): void {
  process.stderr.write(`[${manifest.name}] ${line}\n`);
}

/** One context, built once. Handlers get the token through it; this file never sees one. */
const ctx = createSlackCtx(profile, { log });

/* ─────────────────────────────── JSON-RPC plumbing ─────────────────────────────── */

interface RpcMessage {
  jsonrpc: '2.0';
  id?: number | string | null;
  method?: string;
  params?: Record<string, unknown>;
}

function write(message: Record<string, unknown>): void {
  process.stdout.write(JSON.stringify(message) + '\n');
}

function ok(id: number | string | null | undefined, result: unknown): void {
  write({ jsonrpc: '2.0', id: id ?? null, result });
}

function fail(id: number | string | null | undefined, code: number, message: string): void {
  write({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
}

/* ──────────────────────────────── The dispatch loop ──────────────────────────────── */

async function handle(message: RpcMessage): Promise<void> {
  switch (message.method) {
    case 'initialize':
      ok(message.id, {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: manifest.name, version: manifest.version },
      });
      return;

    case 'notifications/initialized':
      return; // notification — no id, no reply

    case 'ping':
      ok(message.id, {});
      return;

    case 'tools/list':
      ok(message.id, {
        tools: manifest.tools.map((tool) => ({
          name: tool.name,
          description: tool.description,
          inputSchema: tool.inputSchema,
        })),
      });
      return;

    case 'tools/call': {
      const params = message.params ?? {};
      const name = typeof params['name'] === 'string' ? params['name'] : '';
      const args = (params['arguments'] ?? {}) as Record<string, unknown>;
      // callTool never throws: an unknown tool, a refusing provider and a broken handler all
      // come back as structured facts plus a card. `toWirePayload` spreads the rendered card
      // into the SAME JSON payload under `_voiceos_glance` — the wire shape their own
      // reference integrations use — so a card that failed to render is simply absent and the
      // tool's facts still land. Serializing the raw result here — no card, bare text on the
      // wire — is the regression that failed the first audit outright.
      const result = await callTool(name, args, ctx);
      ok(message.id, { content: [{ type: 'text', text: JSON.stringify(toWirePayload(result)) }] });
      return;
    }

    default:
      if (message.id !== undefined) fail(message.id, -32601, `method not found: ${message.method}`);
  }
}

let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk: string) => {
  buffer += chunk;
  let newline = buffer.indexOf('\n');
  while (newline !== -1) {
    const line = buffer.slice(0, newline).trim();
    buffer = buffer.slice(newline + 1);
    if (line.length > 0) {
      try {
        void handle(JSON.parse(line) as RpcMessage);
      } catch {
        log('dropped a malformed frame');
      }
    }
    newline = buffer.indexOf('\n');
  }
});
process.stdin.on('end', () => process.exit(0));

/* ────────────────────────────── C1 — toggle-on auto-open ──────────────────────────────
 *
 * LAST, and unawaited, and that ordering is the whole design: the enable toggle is what
 * spawns this process, so it is the only moment we can turn "the user just switched Slack on"
 * into an approval page without them having to say anything. If the vault already has a
 * usable token this does nothing at all; if it does not, the page opens under B1's two guards
 * (fresh-token check + 120s cooldown stamp written BEFORE the browser opens) so an app
 * relaunch loop can never become a tab loop.
 *
 * Delete this line and C1 does not exist — the connect experience silently degrades to C2/C3.
 */
scheduleStartupAutoConnect();
