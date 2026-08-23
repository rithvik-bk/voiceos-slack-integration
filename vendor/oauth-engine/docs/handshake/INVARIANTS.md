# HANDSHAKE ENGINE — INVARIANTS

*The contract every builder holds to. Each invariant has a **stable id** that never changes
and never gets reused; tests, briefs, and the threat model cite the id, not the prose.*

Benchmark: `docs/handshake/SPEC.md` (handshake-v1). Companion: `docs/handshake/ENGINE-GAP-ANALYSIS.md`.
Locked at **G1** (contract lock). Test floor: **≥ 427** (a red suite halts the program).

---

## How to read this file

- **MUST / MUST NOT / NEVER** are RFC 2119. An invariant is a property that is *always* true
  of a correct engine, in every code path, forever — not a feature and not a goal.
- **Stable id**: `INV-<DOMAIN>-<n>`. Append-only. If an invariant is retired it is struck
  through here and its id is never re-issued.
- **Enforced by** names the test that proves it *today*. `Guard now` = a test committed at
  G1 and green this run. `Target G#` = the gate that will land the test; the property is
  binding on builders from now, the automated proof arrives at that gate. Every `Target`
  invariant must reach a passing test id (or be marked `UNMEASURED` in `CLAIMS.md`) before
  its gate closes — that is the engine's Definition-of-Done rule.
- **The rule for every builder:** you may not close a gate while any invariant it owns is
  regressed. When you fix an `❌/⚠️`, you mint a permanent check for it here.

---

## A. Provider-agnosticism — a provider is a row of values

| id | Invariant | SPEC | Enforced by |
|---|---|---|---|
| **INV-CONFIG-1** | No `engine/src` file MUST contain a per-provider branch — `if (provider === '…')`, `switch (provider)`, `profile.name === '<name>'`. Provider *identity* MUST NEVER select a code path. | §1 · DoD | **Guard now:** `guard-no-provider-branch.test.ts` |
| **INV-CONFIG-2** | A provider config MUST NOT be able to introduce a new code path — only select among existing ones. Config is data: it is read, never `eval`'d, and `success_predicate` is `{path,equals}`, never a JS expression. | §12 | Guard now: `exchange.test.ts`, `guard-no-provider-branch.test.ts`, `malicious-config.blind.test.ts`; Target G4 (REDTEAM) |
| **INV-CONFIG-3** | The engine MUST implement one code path per capability **value**, not per provider. Both poles of every axis the engine branches on MUST be exercised. | §1 | Guard now: `pkce.test.ts`, `exchange.test.ts`, `refresh.test.ts` (both poles of each axis); `guard-no-provider-branch.test.ts` |
| **INV-CONFIG-4** | `provider.schema.json` and `engine/src/types.ts#ProviderProfile` MUST stay in lockstep, and every `provider.json` MUST validate against **both**. | §1 | Guard now: `provider.schema.json` + `make typecheck` (types side); per-`provider.json` conformance is enforced in the integration layer that ships profiles |
| **INV-CONFIG-5** | Any capability field the probe cannot determine MUST be emitted as `unknown`, and the engine MUST treat `unknown` as the most conservative value. There is no guessing. | §1 · §2 | Target G3 (probe) |

## B. Custody — the rung is derived, and the strong ones leak nothing

| id | Invariant | SPEC | Enforced by |
|---|---|---|---|
| **INV-CUST-1** | The custody class (`custody_class`, `relay_mode`, `relay_eligible`) MUST be **derived** from the measured profile, never hand-authored, and MUST be displayed to the user at connect time. | §4 · §5b | Target G2 |
| **INV-CUST-2** | For a Class A provider, no client secret MUST exist anywhere — not in a committed file, not on the device. `client_secret` is forbidden in any `provider.json`. | §4 | Guard now: `scan-secrets.test.ts` + `provider.schema.json` (forbids `client_secret`) |
| **INV-CUST-3** | The relay MUST persist nothing: no token, no refresh token, no session state, no database. Its request lifecycle is memory-only. | §5 | Target G2 (relay: "stores nothing") |
| **INV-CUST-4** | In relay mode `assertion_signing` (B2a) the relay MUST NEVER see the authorization code, the PKCE verifier, or any access/refresh token — it returns a signed client assertion only; the device performs the exchange. | §5b | Target G2 |
| **INV-CUST-5** | A code MAY transit the relay only if PKCE protects it: `relay_eligible` is true iff `pkce !== 'none'`, and a `relay` redirect strategy requires a `relay_url`. | §5 | Guard now: `relay-client.test.ts` (+ schema `allOf`) |
| **INV-CUST-6** | `disconnect()` MUST delete the local credential first and unconditionally; local removal MUST NEVER wait on, or fail because of, a network call. Upstream revocation is a durable best-effort task, and state is reported honestly (`revoked` vs `forgotten, revocation pending`). | §6 | Target G3 |
| **INV-CUST-7** | The encrypted-file key-store backend MUST NEVER be selected silently and MUST be labeled weaker wherever it appears. | §6 · §12 | Target G2 |

## C. Secrets & credentials never leak

| id | Invariant | SPEC | Enforced by |
|---|---|---|---|
| **INV-SECRET-1** | No secret-shaped string MUST appear in source, **build output**, logs, error messages, stack traces, crash dumps, or temp files. | §5 · §6 · §13 | **Guard now:** `scan-secrets.test.ts` (source) + `guard-no-secret-in-build.test.ts` (build output) |
| **INV-SECRET-2** | A secret MUST NEVER be passed as a command-line argument. | §6 · §12 | Guard now: `vault.test.ts`; Target G2 (KeyStore) |
| **INV-SECRET-3** | A token or secret MUST NEVER be written to disk unencrypted, including during atomic-write temp phases. | §6 | Guard now: `vault.test.ts`; Target G2 |
| **INV-SECRET-4** | Every string surfaced to a log, page, or error MUST pass the redaction boundary; held credentials and credential-shaped runs are scrubbed. A provider error quote is built from an allowlist of fields, never by stringifying a body. | §6 · §12 | **Guard now:** `guard-no-secret-in-build.test.ts` (log path via `redact`/`safeProviderMessage`) |
| **INV-SECRET-5** | The stored item MUST carry an ACL restricting read to the signing identity wherever the platform supports it. | §6 | Target G2 |

## D. State, CSRF & mix-up

| id | Invariant | SPEC | Enforced by |
|---|---|---|---|
| **INV-STATE-1** | `state` MUST be cryptographically random (≥ 32 bytes), single-use, TTL-bounded, and bound to the pending flow. | §12 | Guard now: `state.test.ts`; Target G3 (callback wiring, C-2) |
| **INV-STATE-2** | A callback MUST be accepted only if its `state` matches the currently-live flow token; a mismatched or superseded state is refused and logged. **Admission is authoritative.** | §14 | Guard now: `loopback.test.ts`; Target G3 |
| **INV-STATE-3** | Mix-up defense: a response from provider A MUST NEVER satisfy a pending flow for provider B — `state` is bound to provider identity and RFC 9207 `iss` is validated where present. | §12 | Target G3 |

## E. PKCE & authorization code

| id | Invariant | SPEC | Enforced by |
|---|---|---|---|
| **INV-PKCE-1** | Where the profile says S256 is supported, S256 MUST be used; `plain` MUST be refused. A downgrade is treated as an attack, not a compatibility mode. | §12 | Guard now: `pkce.test.ts`; Target G4 |
| **INV-PKCE-2** | The PKCE verifier MUST NEVER leave the process; a stolen authorization code MUST be useless without it. | §12 | Guard now: `pkce.test.ts`; Target G4 |

## F. Redirect & loopback

| id | Invariant | SPEC | Enforced by |
|---|---|---|---|
| **INV-REDIR-1** | No code path MUST open a browser before a successful listener bind. Bind-before-browser is absolute; a failed bind ends the flow with an actionable message, never a dead tab. | §7 · §12 | Guard now: `loopback.test.ts` |
| **INV-REDIR-2** | The `redirect_uri` MUST be exact and byte-identical across the authorize and token requests. | §7 · §12 | Guard now: `loopback.test.ts` / `exchange.test.ts` |
| **INV-REDIR-3** | The loopback listener MUST reject non-GET requests, MUST validate the Host header is a loopback literal, and MUST deliver at most one valid callback. | §12 | Guard now: `loopback.test.ts` |
| **INV-REDIR-4** | A held port MUST be reclaimed only when it is verifiably **ours** (lockfile PID + flow token + matching signed executable); anything else is reported by name/PID and NEVER touched. | §7 | Target G3 (C-15) |

## G. Token lifecycle & refresh

| id | Invariant | SPEC | Enforced by |
|---|---|---|---|
| **INV-REFRESH-1** | Refresh MUST be edge-triggered (before expiry and on 401) and single-flight: concurrent callers produce exactly one refresh, via a cross-process lock. | §8 | Guard now: `refresh.test.ts` |
| **INV-REFRESH-2** | The refresh lock MUST be crash-safe — TTL + liveness check — so a process that dies mid-refresh never deadlocks future calls. | §8 | Guard now: `refresh.test.ts` |
| **INV-REFRESH-3** | Under rotation, the new token MUST be persisted before use, a consumed refresh token MUST NEVER be retried, and family revocation MUST surface a clean re-auth prompt. | §8 · §12 | Guard now: `refresh.test.ts` (persist-before-release); Target G3 (reuse-detection, C-10) |
| **INV-REFRESH-4** | Expiry decisions MUST tolerate clock skew and MUST NEVER trust a local clock alone for a security decision. | §8 | Target G3 |
| **INV-REFRESH-5** | Every stored credential record MUST carry a schema version so a future engine can migrate rather than orphan. | §8 | Guard now: `vault.test.ts` / `types.ts` (`TokenRecord`); Target G3 |

## H. Scope

| id | Invariant | SPEC | Enforced by |
|---|---|---|---|
| **INV-SCOPE-1** | Granted scopes MUST be tracked separately from requested; a withheld required scope MUST fail loudly at connect time, not inside a later tool call. | §8 · §9 | Target G3 (C-11) |
| **INV-SCOPE-2** | Where `scope_grant !== 'incremental'`, a step-up MUST re-request the **union** of previously-granted and newly-needed scopes (re-consenting with only the new scope drops the old ones on several providers). | §9 | Target G3 |
| **INV-SCOPE-3** | A scope step-up MUST be user-attributable — traceable to a transcript-grounded action, never triggered by content the assistant merely read. | §9 | Target G3 |

## I. Single-flight, supersession & connect shape

| id | Invariant | SPEC | Enforced by |
|---|---|---|---|
| **INV-FLOW-1** | At most one live flow MUST exist per `(provider, account)`; a second `connect()` within the TTL supersedes the first — prior listener torn down, its state invalidated, its late redirect landing on a "superseded" page. | §14 | Target G3 (C-16) |
| **INV-FLOW-2** | Cancellation is advisory; admission is authoritative. Correctness MUST NEVER depend on tearing the old listener down in time — a superseded flow's code is refused even if valid. | §14 | Target G3 |
| **INV-FLOW-3** | `connect()` MUST return fast and complete out of band; it MUST NEVER block on a human clicking Allow. | §14 | Guard now: `connect-flow.test.ts` / `public-api.test.ts` |

## J. Identity & multi-account

| id | Invariant | SPEC | Enforced by |
|---|---|---|---|
| **INV-IDENT-1** | "connected" MUST be produced by the identity probe resolving a real handle, NEVER by an HTTP 200. | §11 · identity.ts | Guard now: `connect-flow.test.ts` (identity probe → connected) |
| **INV-IDENT-2** | The account identifier MUST derive from the identity probe, not a display name; `getToken(provider, account?)` MUST disambiguate rather than silently pick when an account is ambiguous. | §11 | Target G3 (C-13) |

## K. Errors, reliability & observability

| id | Invariant | SPEC | Enforced by |
|---|---|---|---|
| **INV-ERR-1** | Every engine failure MUST normalize to the closed taxonomy (`NOT_CONNECTED, CONSENT_DENIED, SCOPE_INSUFFICIENT, TOKEN_EXPIRED, REFRESH_FAILED, REVOKED, RATE_LIMITED, PROVIDER_UNAVAILABLE, CONFIG_INVALID`), each carrying the raw provider error and a recommended action. | §15 | Guard now: `errors.ts` / `public-api.test.ts`; Target G3 (normalize to 9, C-14) |
| **INV-REL-1** | The engine MUST have zero runtime dependencies; nothing MUST be installed inside a connect window. | §14 | Guard now: `package.json` (no `dependencies`); Target G6 (`make verify`) |
| **INV-REL-2** | Token-endpoint retry MUST use jittered backoff on 429/5xx, MUST NEVER retry a 4xx client error, and MUST be bounded. | §14 | Target G3 |
| **INV-REL-3** | The background health probe MUST be budgeted (hard daily cap inside the rate limit), MUST back off on failure, MUST NEVER run during an active turn, MUST be idle/connectivity-aware, and MUST be silent on success. | §10 | Target G3 (C-12) |
| **INV-OBS-1** | The auth-event log MUST contain no credential material. | §16 | Target G6 (C-23) |
| **INV-INTEG-1** | Provider configs MUST be signed or checksummed; a tampered config MUST be rejected before it can select a path. | §12 | Target G4 |

---

## Invariants wired at G1 (green this run)

`INV-CONFIG-1` · `INV-CONFIG-2/3/4` · `INV-CUST-2/5` · `INV-SECRET-1/4` · plus the pre-existing
suite already covering `INV-STATE-1/2`, `INV-PKCE-1/2`, `INV-REDIR-1/2/3`, `INV-REFRESH-1/2/3/5`,
`INV-IDENT-1`, `INV-FLOW-3`, `INV-REL-1`. Everything marked **Target G#** is binding now and
gets its automated proof at the named gate; none may be closed without minting the check here.
