# 🏗 ARCHITECTURE — Universal OAuth engine

*The code-level design: HOW the code is laid out. This is the canonical architecture doc — it lives in the repo so `tools/drift-check.mjs` can hold it to the code.*

## The rule

**ONE engine package, built once. The integration layer on top is THIN: a provider profile plus tool code. Zero auth code ever lives inside an integration.** (Anti-pattern being avoided: copying auth logic per integration → N× bugs, unmaintainable, and it kills the "add another provider in minutes" property.)

The corollary that keeps it honest: **every axis on which providers differ is a FIELD in `provider.json`, never an `if (provider === 'x')` in the engine.** One provider has no PKCE, another nests its user token under `authed_user`, a third defaults `code_challenge_method` to `plain` — three facts, three fields, one code path. This is enforced by a guard test that greps `engine/src` for a per-provider branch.

## Repo layout

```
voiceos-oauth-engine/
├── provider.schema.json          # the frozen v1 profile contract (machine-readable twin of types.ts)
├── engine/src/
│   ├── index.ts      # public API: connect(profile) / getToken(name) / disconnect(name) / getConnectStatus(id)
│   ├── config.ts     # SOLE source of REDIRECT_HOST · PORT_LADDER · CALLBACK_PATH · redirectUri()
│   ├── types.ts      # ProviderProfile · TokenRecord · ConnectStatus · error codes
│   ├── pkce.ts       # verifier + S256 challenge (RFC 7636)
│   ├── loopback.ts   # ONE `::` socket (ipv6Only:false) answering `localhost`, `127.0.0.1` and `[::1]`; ladder walk; single callback; state validation (CSRF guard)
│   ├── exchange.ts   # code+verifier → token, direct HTTPS (never via the browser)
│   ├── vault.ts      # login Keychain via /usr/bin/security, enc:v1-style blobs
│   ├── refresh.ts    # edge-triggered refresh (T−10min or on 401, retry once) + cross-process O_EXCL lock
│   ├── device.ts     # device authorization grant (RFC 8628)
│   ├── dcr.ts        # dynamic client registration (RFC 7591)
│   ├── byos.ts       # paste-once desk: one paste → vault, never plaintext
│   ├── relay-client.ts  # talks to the stateless relay for confidential-client custody (B2a/B2b)
│   └── ui/pages.ts   # branded callback pages: success · denied · mismatch · timeout · provider_error
├── relay/            # the stateless relay reference implementation (B2a assertion-signing, B2b sealed forwarding)
└── tools/            # demo.mjs · mock-provider/ · scan-secrets.mjs · drift-check.mjs · probe.mjs
```

`provider.json` = the public per-provider config that makes a provider work: `authorize_url` · `token_url` · `scopes` · `client_id` (public; the author registers the dev app once — **the end user never pastes anything on the PKCE desk**) plus the capability axes above. It is validated by `provider.schema.json`, and lives in the integration layer, not in this repo. A secret-shaped public-config filename is forbidden by the schema (§A4).

## Runtime

**Node-native TypeScript, zero runtime dependencies** (§A2). The engine's whole module graph type-strips and loads under `node` with no build step — `tsc` is a type checker here, never an emitter. The target invocation is `exec node server.ts`; a host that enforces a short connect gate must never have an `npm install` hiding inside the launch path.

## Runtime flows

- **Connect:** "connect &lt;provider&gt;" → the integration calls `engine.connect(profile)` → PKCE → bind a ladder rung **before** opening the browser → browser consent → loopback callback + state check → exchange → vault → identity probe. The integration never sees the mechanics. `connect()` returns in ≲1s and the dance finishes out of band (`getConnectStatus` polls it) because a tool call may never block on a human clicking Allow.
- **Tool call:** tool body → `engine.getToken("<provider>")` → a token valid *right now* (refresh behind the call) → API call. Tool code reads as if auth did not exist.
- **`redirect_uri` is sent, byte-identical, in BOTH the authorize and token requests** (§A8). Omitting it can make a provider silently use the *first registered* URL — bind `:33419`, omit the param, and the browser lands on a dead `:33418` with no error anywhere.
- **"Connected" is only ever produced by the identity probe**, never by an HTTP 200 — some providers return failures as 200 + `{"ok": false}`.

## Adding a provider

The authorization cost of the next provider is zero lines of code; the configuration cost is one `provider.json`. See **[ADD-A-PROVIDER.md](ADD-A-PROVIDER.md)** for the full worked example and the `registerProvider()` wiring, and `tools/mock-provider/` + `make demo` for a runnable reference.

## Registration strategy

- **Model = shared registry:** one dev app per provider, all users share its public `client_id`. In production these live under an organization account — one field to swap.
- **Ladder:** registry (top providers) → Dynamic Client Registration where supported (RFC 7591 — the direction the MCP auth spec standardizes on) → a guided registration wizard as the universal floor.
- **User self-hosting (BYO client_id):** supported as an advanced override, never the default (enterprises want their own app's audit/control; the default stays click-Allow-done, zero paste).
- **Custody follows the profile, not a per-provider decision:** `pkce: S256` + `token_auth: none` → fully on-device (Class A); a secret-bearing exchange routes to a bring-your-own-secret or relay path (B1/B2); DCR self-registration is Class C. The engine's provider config is designed DCR-ready.

---
Sources: the capability model and custody classes in `docs/handshake/SPEC.md`; the redirect ladder in `engine/src/config.ts`; the port model in `docs/registration/PORT-STRATEGY.md`.
