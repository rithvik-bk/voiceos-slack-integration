# HANDSHAKE ENGINE — Module Map & Gap Snapshot

*Benchmark: `docs/handshake/SPEC.md` (handshake-v1). Grounded in a full read of `engine/src/*.ts` + tests.*

> **Point-in-time snapshot.** This is a historical baseline captured when the engine proved one custody class (Class A / public-PKCE) end-to-end. Several gaps listed below as MISSING have since been built out in the repo (the stateless `relay/`, device grant, DCR, the conformance probe, the `make verify` gate, additional KeyStore backends). Read section B as an accurate module map and section C as the baseline gap list it was measured against, not as the current status of every line.

---

## A. SCOPE LINE — what "the engine" is (and is not)

**IN SCOPE — "finish the engine" = SPEC Parts 1–4:**
- **Part 1** Capability model: the conformance **probe**, capability schema completeness, all four grant paths.
- **Part 2** Custody: classes **A / B1 / B2a / B2b / C**, the stateless relay, the pluggable KeyStore.
- **Part 3** Threat model: the attack catalog (§12) each mapped to a test, the **blind** security conformance suite (§13).
- **Part 4** Reliability/ops: refresh lifecycle, scope step-up, background health, multi-account, error taxonomy, redirect strategy, single-flight/supersession, observability.
- The **consent/callback pages** (5 terminal states) — they live in the engine (`ui/pages.ts`) and are judged first.
- The **`auth.client()`** zero-auth-code wrapper (§18) — it is the engine's public adoption surface.

**OUT OF SCOPE (separate programs):**
- The **integration layer** (the per-provider tool code) — SPEC Part 5. The engine is done when a *new* provider is pure config; building the providers is a separate program on top.
- The **product surface** beyond callback pages — custody chip, cards, motion (SPEC Part 6) — host-app UI, not engine.
- The **tool generator** (OpenAPI/MCP → tools) — Part 5 tooling.

> One-line guard for the workflow: *if a task adds a provider, a notch card, or a tool generator, it is out of scope for "finish the engine."*

---

## B. CURRENT STATE — per module (what exists today)

| File | LOC | Implements | Capability values covered |
|---|---|---|---|
| `pkce.ts` | 51 | RFC 7636 verifier + S256 challenge | `pkce: S256`, `none` |
| `authorize.ts` | 56 | Authorize URL; `%20` not `+` (Zoom 4700 fix); scope delimiter as axis; extra params | `scope_param`, `scope_delimiter`, `extra_authorize_params` |
| `loopback.ts` | 455 | One `::` dual-stack socket; fixed **port ladder**; **bind-before-browser**; state match (constant-time); deliver-once; `Sec-Fetch` drive-by guard; branded pages | `redirect_strategy: loopback`, `redirect_host` (localhost/127.0.0.1) |
| `exchange.ts` | 314 | Code→token + refresh grant; `token_auth`/`refresh_auth` as **two** axes; success-predicate; nested token paths (Slack `authed_user.*`); dead-grant classify; redact | `token_auth: none/body/basic_empty_password`; **`basic` = hard-refused** |
| `refresh.ts` | 272 | Edge-triggered refresh; **O_EXCL cross-process lock**, crash-safe (PID+TTL stale takeover); persist-before-release; `authorizedFetch` on-401-retry-once; Slack `{ok:false}`-as-auth-failure | `refresh: rotation/long_lived/none`, `rotation:*` |
| `vault.ts` | 225 | macOS Keychain via `/usr/bin/security -i` (stdin, never argv; hex transport; 128-byte-truncation fix); write-then-verify; delete idempotent | Custody **Class A only** |
| `identity.ts` | 105 | Identity probe — "connected" only after a real handle, never HTTP 200 | `identity_probe` |
| `index.ts` | 538 | Public API `connect/getToken/disconnect/getConnectStatus`; two-phase non-blocking connect; registry; profile resolution (space-in-path fix); status board (bounded 50) | the frozen 3-verb surface |
| `state.ts` | 90 | CSRF state: 32-byte random, TTL, **single-use store** (`consumeState`) | — ⚠️ see gap C-2 |
| `config.ts` | 68 | Sole source of host/ports/ladder/timeouts | port ladder |
| `errors.ts` | 38 | `EngineError` + `EngineErrorCode` (11 codes) | error surface |
| `redact.ts` | 81 | Secret redaction for logs/messages | no-secret-leak |
| `copy.ts` | 117 | Frozen spoken deck (no LLM in any live path) | consent copy |
| `paths.ts` | 52 | Dotted-path readers | token-shape |
| `ui/pages.ts` | — | Branded callback pages | 5 terminal states |

**Verdict:** a genuinely production-grade **Class-A (public/PKCE) engine**, with several hard-won correctness scars already fixed. It proves ONE custody class end-to-end. Everything below is the distance from "excellent Class-A engine" to "the HANDSHAKE capability model."

---

## C. GAP TABLE — engine scope vs SPEC

| # | Capability (SPEC ref) | Status | Note |
|---|---|---|---|
| C-1 | Conformance **probe** (§2, §20 rung 2) | **MISSING** | No `probe`. Every provider.json is hand-written today — violates "measure, not assume." Highest-value missing piece. |
| C-2 | State **single-use + TTL enforced on callback** (§12 CSRF) | **PARTIAL** | `state.ts` has `consumeState()` but `loopback.ts` matches by constant-time compare and **never calls it** — TTL/replay store is effectively unwired. Deliver-once gives partial replay cover; the minted state's TTL is not enforced at the callback. |
| C-3 | Mix-up defense — RFC 9207 `iss` (§12) | **MISSING** | No `iss` validation; concurrent multi-provider connects rely on state-per-listener only. |
| C-4 | Custody **Class A** (public) | **HAVE** | Fully on-device. |
| C-5 | Custody **B1** (bring-your-own client, secret in vault) | **MISSING** | `basic`/confidential is hard-refused in `exchange.ts:77`. No path to store/use a user's own secret. |
| C-6 | Custody **B2a** (assertion-signing relay, `private_key_jwt`) | **MISSING** | No relay; `private_key_jwt` not a capability value. |
| C-7 | Custody **B2b** (hardened forwarding relay + X25519 response encryption) | **MISSING** | No relay service, no ephemeral-encryption return leg. |
| C-8 | Custody **C** (DCR, RFC 7591) | **MISSING** | No dynamic client registration. |
| C-9 | **KeyStore interface** + backends (mac N-API / Win DPAPI / Linux libsecret / encrypted-file) | **MISSING** | Hard-wired to `/usr/bin/security` (dev-grade, mac-only). SPEC §6 wants a pluggable ladder + ACL + code-signed native backend. |
| C-10 | Refresh **rotation + reuse-detection + crash-safe lock** (§8) | **PARTIAL** | Rotation + crash-safe O_EXCL lock + persist-before-release = **HAVE** (strong). **Reuse-detection / family-revocation → clean re-auth** = not explicit. |
| C-11 | **Scope step-up** (incremental + union rule, §9) | **MISSING** | Connect requests the full scope set up front; no per-tool `requires_scopes`, no delta step-up, no union re-request. |
| C-12 | **Background token-health** probe (§10) | **MISSING** | Dead tokens discovered only on live use. No budgeted idle-aware probe / reconnect badge. |
| C-13 | **Multi-account** `getToken(provider, account)` (§11) | **MISSING** | Vault keyed by provider only; `getToken(provider)` single-account. Slack bot-vs-user handled as `token_path`, but two workspaces cannot coexist. |
| C-14 | **Error taxonomy** — closed 9-code set (§15) | **PARTIAL** | Have `EngineErrorCode` (11) + 6 `ConnectErrorCode`. SPEC wants the normalized 9 (`NOT_CONNECTED/CONSENT_DENIED/SCOPE_INSUFFICIENT/TOKEN_EXPIRED/REFRESH_FAILED/REVOKED/RATE_LIMITED/PROVIDER_UNAVAILABLE/CONFIG_INVALID`) each carrying raw provider error + recommended action. |
| C-15 | Redirect strategy completeness (§7) | **PARTIAL** | Fixed-port ladder + bind-before-browser = HAVE. **Reclaim-ours-by-PID / surface-others-by-name** = MISSING (just skips to next rung → `port_blocked`). `custom_scheme`, `https_claimed` = MISSING. |
| C-16 | Single-flight + **supersession** (§14) | **PARTIAL** | One loopback delivers one callback (good). A second `connect()` for the same provider/account does **not** explicitly supersede the first (tear down prior listener, invalidate its state, "superseded" page). |
| C-17 | Device authorization grant, RFC 8628 (§3 path 3) | **MISSING** | No headless/no-browser fallback. |
| C-18 | Discovery RFC 8414 / OIDC (§1 `discovery`) | **MISSING** | Endpoints hand-configured; no `.well-known` fetch. |
| C-19 | PAR RFC 9126 / DPoP RFC 9449 / mTLS sender-constraint (§1) | **MISSING** | `sender_constraint` not a dimension; bearer only. |
| C-20 | **Blind** security conformance suite (§13) | **MISSING** | Security tests exist inline but no isolated, spec-only-authored blind corpus with a reported number. |
| C-21 | **`auth.client()`** zero-auth-code wrapper (§18) | **PARTIAL** | `authorizedFetch(profile,url,…)` exists (silent refresh + 1 retry). Not the `auth.client("slack").post(path,body)` shape; no step-up raise, no sender-constraint application. |
| C-22 | Capability schema expresses every measured provider (§1) | **PARTIAL** | `provider.schema.json` covers the current axes; missing `discovery/dcr/par/sender_constraint/device_flow/scope_grant/revocation` dimensions and custody-class fields. |
| C-23 | Observability / auth-event log (§16) | **MISSING** | No structured, credential-free event log or metrics feed. |
| C-24 | `make verify` one-command gate | **MISSING** | No `make verify` aggregating build+test+lint+invariants+zero-dep+no-secret-leak. |

---

## D. DEFINITION OF DONE (engine)

- [ ] `make verify` green from a **clean checkout**: build + typecheck + invariants + zero-dependency assertion + no-secret-leak assertion + full test suite.
- [ ] The test suite is green (a red suite halts everything) and rising as capabilities land.
- [ ] Every **INVARIANT** (`docs/handshake/INVARIANTS.md`) has a passing test id.
- [ ] Every **claim** in `docs/CLAIMS.md` maps to a test id **or** is marked `UNMEASURED`.
- [ ] The **blind corpus** number exists and is reported honestly (fix the engine, never the corpus).
- [ ] **Custody matrix**: every supported class A/B1/B2a/B2b/C has a passing path + a test proving its custody property (e.g. relay stores nothing).
- [ ] **Consent pages**: all 5 terminal states (connected/denied/mismatch/timeout/error) have a designed treatment.
- [ ] **Zero `if (provider === …)`** in `engine/` — enforced by a test that greps the source.

---

## E. REMAINING WORK — the shape

Closing the gaps in section C is a multi-stage effort, roughly: lock the spec/invariants and extend the capability schema (discovery / dcr / par / sender_constraint / device_flow / scope_grant / custody dimensions); build the custody core (pluggable KeyStore + backends, the BYO-secret path, the stateless relay for assertion-signing and sealed forwarding); complete capability and lifecycle (conformance probe, discovery, DCR, state single-use + `iss`, reuse-detection, scope step-up, multi-account, error taxonomy, redirect reclaim, supersession, device flow); adversarial hardening against a spec-only blind corpus; the `auth.client()` surface and final consent pages; and the `make verify` gate plus observability.

Two items are genuinely human-gated and worth front-loading: (1) a confidential dev-app registration is needed for a real B1/B2 live proof; (2) macOS **code-signing + a keychain-access-group entitlement** is needed for a production KeyStore backend (C-9), or the native backend re-prompts — verify both against the *live* console, not docs.
