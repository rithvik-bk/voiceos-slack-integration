# VoiceOS × Slack

A **custom-MCP integration for VoiceOS** that lets you do real Slack work by voice — read a
cross-channel catch-up digest, read any channel or DM, search, send and schedule messages,
react, reply in thread, set your status and Do Not Disturb — and connect in one tap on
Slack's own approval page.

**No API key is ever pasted. No secret ships in this repo. The token is stored encrypted in
the macOS login Keychain, never in a file on disk.**

Sixteen tools, and **zero lines of auth code**. Every handler is written as if OAuth did not
exist: it asks the engine for a token that is valid *right now* and gets on with the job.

---

## Built on the voiceos-oauth-engine

All of the OAuth machinery — PKCE, the loopback redirect, `state`, the token vault, and
silent refresh — lives in the [**voiceos-oauth-engine**](vendor/oauth-engine), a
provider-agnostic engine that makes `auth: "oauth2"` work for any VoiceOS custom
integration. This repo vendors a frozen source snapshot of it under
[`vendor/oauth-engine/`](vendor/oauth-engine) so the integration is completely
self-contained: it type-checks and runs with nothing outside the folder.

The integration touches the engine through exactly one file, [`engine/index.ts`](engine/index.ts),
which re-exports the engine's three-verb public API:

```
connect(profile)      start the browser dance   → returns in ≲1s, finishes out of band
getToken(provider)    a token valid right now    → refresh happens behind this call
disconnect(provider)  forget everything          → vault entry destroyed
```

That is the whole design: because the engine owns auth, the auth cost of this integration —
and the next one — is zero lines.

---

## How connecting happens (one tap, no API key)

Connecting is out-of-band and two-phase, so a tool call never blocks on a human clicking
Allow:

1. You say **"connect Slack"** (or enable the integration, or call any tool before you're
   connected).
2. The engine binds a loopback port, builds the PKCE authorize URL around the port it
   actually bound, and opens **Slack's own approval page** in your browser.
3. You tap **Allow** once. Slack redirects to `localhost`, the engine exchanges the code,
   runs an identity probe (`auth.test`) to confirm who connected, and stores the token
   **encrypted in the macOS Keychain**.
4. From then on, every tool gets a fresh token transparently — the engine refreshes it
   behind `getToken()`, so you never reconnect unless you revoke access.

The Client Secret is never copied, never stored, never sent: this is a **public PKCE
client**, and [`provider.json`](provider.json) carries only the public `client_id` and the
18 user-token scopes — one scope per command, nothing speculative.

---

## The tools

**Connect + status (2)**
`slack_connect` · `slack_status`

**Read + find (6)**
`slack_catch_up` (cross-channel digest) · `slack_read_channel` · `slack_read_dm` ·
`slack_send_message`\* · `slack_search` · `slack_find`

**Act (8)**
`slack_react`\* · `slack_schedule_message`\* · `slack_set_reminder`\* · `slack_upload_file`\* ·
`slack_thread_reply`\* · `slack_set_status`\* · `slack_disconnect`\* · `slack_health`

`*` = confirmation-gated. Every tool that changes something in a workspace is gated behind a
confirmation card; nothing else is. The approval budget on every read path is exactly one —
Slack's own Allow screen.

### Rules every tool holds to

- **Nothing is guessed.** A spoken name that matches zero or 2+ conversations returns a
  disambiguation card, never "the closest string" — so a message can never be posted to a
  channel you didn't name.
- **Extractive, never generative.** Digests and reads carry verbatim message text. There is
  no LLM anywhere in the tool path; the ranking is arithmetic (mentions, then recency).
- **No invented prose.** Every user-visible string lives in [`copy.ts`](copy.ts) and nowhere
  else.
- **A card can never break a tool.** Card rendering runs inside a guard; a card that fails to
  render is simply absent — it can never be the reason a tool fails.

---

## The native card UI

Every tool result returns structured JSON **plus a rendered card**, so Slack looks native
inside VoiceOS rather than like a raw JSON dump.

- [`cards.ts`](cards.ts) — the card surfaces: Slack-styled replicas plus widget-block cards
  for the success/connect/error states.
- [`widgetKit.ts`](widgetKit.ts) — the widget primitives the cards are composed from.
- [`composer.ts`](composer.ts) — assembles message/digest cards from structured data.
- [`copy.ts`](copy.ts) — the single source of every sentence the spoken and visual layers
  can show, so the two can never disagree.

---

## Repo layout

| path | what it is |
|---|---|
| `voiceos.integration.json` | The VoiceOS manifest — identity, `local-mcp` runtime, the tool declarations the agent routes on, and the confirmation cards that gate the action tools. It is the single source of the tool list. |
| `provider.json` | The public OAuth capability profile the engine runs on — public `client_id`, PKCE, loopback ports, and the only place the 18 user scopes are written. Validated against the engine's `provider.schema.json`. |
| `server.ts` | The MCP stdio server. JSON-RPC on stdout, diagnostics on stderr, nothing at import touches the network, and connect returns in ~1s. |
| `tools.ts` | The registry, dispatcher, wire payload, and the two-phase connect poller (`slack_status`). |
| `toolkit.ts` | The tool contract, `slackFetch` (Bearer + typed `SlackError`), and `requireToken` — the gate every handler calls first. |
| `lifecycle.ts` | The connect triggers and guards (fresh-token check + a cooldown stamp), plus `slack_connect`. |
| `tools-t1.ts` | The read + find tools, and the name resolver that refuses to guess. |
| `tools-t2.ts` | The action tools, and the provenance registry behind "that message". |
| `resolve.ts` | Channel / person / conversation resolution against what Slack actually returned. |
| `cards.ts` · `widgetKit.ts` · `composer.ts` · `copy.ts` | The card UI and its frozen copy. |
| `engine/index.ts` | The one link to the vendored OAuth engine. Never edited. |
| `run.sh` / `run.cmd` | Launchers: bun → node ≥22.18 native TypeScript → local `tsx` → `npx tsx`. |
| `icon.png` | 512×512 marketplace / consent icon. |
| `vendor/oauth-engine/` | Frozen source snapshot of the OAuth engine this integration is built on. |

---

## Run and verify

Requires **Node ≥ 22.18** (native TypeScript type-stripping; no build step, no runtime
dependencies). `bun` is used if present.

```bash
# Type-check the integration + the engine source it depends on
npm install
npm run typecheck

# Talk MCP to it directly — initialize + tools/list
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | /bin/zsh run.sh
# → initialize returns {"name":"Slack","version":"1.1.0"} and tools/list returns all 16 tools.

# Re-verify the vendored engine on its own (typecheck + tests + drift + secret scan)
npm run engine:check
```

---

## Install into VoiceOS as a custom MCP

1. Set your own Slack app's public `client_id` in [`provider.json`](provider.json). Create
   the app at [api.slack.com/apps](https://api.slack.com/apps) as a **public** client, enable
   token rotation, and add `http://localhost:33418`, `:33419`, `:33420` as OAuth redirect
   URLs. No Client Secret is needed and none should be added.
2. Copy this folder into the VoiceOS custom-MCP directory:
   `~/Library/Application Support/VoiceOS/custom-mcps/slack/`. When it leaves this repo, replace
   `engine/` with a real copy of `vendor/oauth-engine/engine/src/` (the vendoring shim exists
   so nothing resolves back outside the deployed folder).
3. VoiceOS reads `voiceos.integration.json`, runs `run.sh` as a `local-mcp`, and lists the
   tools. Enable it, say **"connect Slack"**, tap Allow once — and you're connected.

---

## Security posture

- **Public PKCE client** — no Client Secret anywhere in this repo or on disk.
- **Tokens live in the macOS Keychain**, encrypted, never written to a file.
- **stdout is the MCP wire** — only JSON-RPC frames; no token, code, or verifier is ever
  logged, not even to stderr.
- **`"connected"` is proven by an identity probe** (`auth.test`), never by an HTTP 200 or the
  mere presence of a stored token.

## License

MIT — see [LICENSE](LICENSE).
