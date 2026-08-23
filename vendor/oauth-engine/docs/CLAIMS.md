# HANDSHAKE — CLAIMS → PROOF

*Every claim the engine makes maps to a **test id** that proves it, or is marked **`UNMEASURED`**
with what is missing and what would close it. This is the engine's Definition-of-Done rule
and the honesty contract of SPEC §30: "one provider proven
is an existence proof, not a universality proof." A claim with no receipt is a claim we do not
make.*

- **Test id** = a file under `engine/test/` (the engine suite the locked gate runs as
  `npx vitest run`) or under `relay/test/` (the relay package, run under its own
  `relay/vitest.config.ts`). File-level ids match how the rest of this repo cites proofs.
- **Gate id** = a `make verify` target (`Makefile`) for the operational assertions that are checks
  rather than unit tests (zero runtime deps, the source secret scan).
- Benchmarks: `docs/handshake/SPEC.md`, `docs/handshake/INVARIANTS.md`,
  `docs/handshake/ENGINE-GAP-ANALYSIS.md`.
- Suite state at this writing: **engine 897 tests green** (`npx vitest run`), **relay 41 tests
  green** (`cd relay && npx vitest run`), `tsc --noEmit` clean, `make verify` green from a clean
  checkout.

---

## A. Invariants (`docs/handshake/INVARIANTS.md`)

Every invariant, its enforcing test, and its status. `HAVE` = a passing automated proof exists
today. `UNMEASURED` = binding on builders but its automated proof is not yet landed (the gate that
owns it is named).

### Provider-agnosticism

| id | Claim | Proof | Status |
|---|---|---|---|
| INV-CONFIG-1 | No `engine/src` file branches on provider identity | `guard-no-provider-branch.test.ts` | HAVE |
| INV-CONFIG-2 | A config selects among existing paths, never introduces one (`success_predicate` is `{path,equals}`, never eval'd) | `exchange.test.ts`, `guard-no-provider-branch.test.ts` | HAVE |
| INV-CONFIG-3 | One code path per capability **value**; both poles of every branched axis are exercised | `pkce.test.ts`, `exchange.test.ts`, `refresh.test.ts` | HAVE |
| INV-CONFIG-4 | `provider.schema.json` and `types.ts#ProviderProfile` stay in lockstep | `provider.schema.json` + `make typecheck` (types side); per-`provider.json` conformance is checked in the integration layer that ships profiles | PARTIAL |
| INV-CONFIG-5 | An undeterminable field is emitted `unknown`; the engine treats `unknown` as the most conservative value | `probe.test.ts` | HAVE |

### Custody

| id | Claim | Proof | Status |
|---|---|---|---|
| INV-CUST-1 | Custody class/relay mode is **derived** from the measured profile, never hand-authored; displayed at connect | `probe.test.ts` | HAVE |
| INV-CUST-2 | Class A has no client secret anywhere; `client_secret` forbidden in any `provider.json` | `scan-secrets.test.ts` (+ `provider.schema.json` forbids `client_secret`) | HAVE |
| INV-CUST-3 | The relay persists nothing — no token, no refresh token, no session, no database | `relay/test/statelessness.test.ts`, `relay/test/handlers.test.ts` | HAVE (relay suite) |
| INV-CUST-4 | B2a (assertion signing): relay never sees the code, verifier, or any token — returns a signed assertion only; device performs the exchange | `relay/test/jwt.test.ts`, `relay/test/handlers.test.ts`, `relay-client.test.ts` | HAVE (relay + engine) |
| INV-CUST-5 | A code transits the relay only under PKCE (`relay_eligible` ⇔ `pkce !== 'none'`); a `relay` redirect requires a `relay_url` | `relay-client.test.ts` (+ schema `allOf`) | HAVE |
| INV-CUST-6 | `disconnect()` deletes locally first and unconditionally; revocation is best-effort and never blocks local removal; state reported honestly | `public-api.test.ts`, `connect-flow.test.ts` (local-first + revoke best-effort); B2b onward-encryption `relay/test/seal.test.ts` | HAVE |
| INV-CUST-7 | The encrypted-file key-store backend is never selected silently and is labeled weaker | `keystore.test.ts` | HAVE |

### Secrets

| id | Claim | Proof | Status |
|---|---|---|---|
| INV-SECRET-1 | No secret-shaped string in source, build output, logs, errors, dumps, temp files | `scan-secrets.test.ts`, `guard-no-secret-in-build.test.ts`; gate `make no-secret-leak` | HAVE |
| INV-SECRET-2 | A secret is never a command-line argument | `vault.test.ts`, `keystore.test.ts` | HAVE |
| INV-SECRET-3 | A token/secret is never written to disk unencrypted, temp phases included | `vault.test.ts`, `keystore.test.ts` | HAVE |
| INV-SECRET-4 | Every surfaced string passes the redaction boundary; provider quotes built from an allowlist | `guard-no-secret-in-build.test.ts`, `observability.test.ts` (log path) | HAVE |
| INV-SECRET-5 | The stored item carries an ACL restricting read to the signing identity where supported | `keystore.test.ts` | PARTIAL — interface + macOS `security` backend tested; the code-signed N-API ACL is **UNMEASURED** (needs code-signing + keychain-access-group entitlement; SPEC §34) |

### State, CSRF, mix-up

| id | Claim | Proof | Status |
|---|---|---|---|
| INV-STATE-1 | `state` is ≥32-byte random, single-use, TTL-bounded, bound to the flow | `state.test.ts`, `callback-state.test.ts` | HAVE |
| INV-STATE-2 | A callback is accepted only if its state matches the live flow token; mismatched/superseded is refused and logged | `loopback.test.ts`, `singleflight.test.ts` | HAVE |
| INV-STATE-3 | Mix-up defense: provider A's response can never satisfy provider B; RFC 9207 `iss` validated where present | `mixup.test.ts` | HAVE |

### PKCE & redirect & loopback

| id | Claim | Proof | Status |
|---|---|---|---|
| INV-PKCE-1 | S256 is used where supported; `plain` is refused (downgrade = attack) | `pkce.test.ts` | HAVE |
| INV-PKCE-2 | The verifier never leaves the process; a stolen code is useless without it | `pkce.test.ts` | HAVE |
| INV-REDIR-1 | No browser opens before a successful bind; a failed bind ends the flow with an actionable message | `loopback.test.ts` | HAVE |
| INV-REDIR-2 | `redirect_uri` is byte-identical across authorize and token requests | `loopback.test.ts`, `exchange.test.ts` | HAVE |
| INV-REDIR-3 | The listener rejects non-GET, validates a loopback Host header, delivers ≤1 valid callback | `loopback.test.ts` | HAVE |
| INV-REDIR-4 | A held port is reclaimed only when verifiably ours; anything else is reported, never touched | `port-reclaim.test.ts` | HAVE |

### Token lifecycle & refresh

| id | Claim | Proof | Status |
|---|---|---|---|
| INV-REFRESH-1 | Refresh is edge-triggered and single-flight via a cross-process lock | `refresh.test.ts` | HAVE |
| INV-REFRESH-2 | The refresh lock is crash-safe (TTL + liveness), never deadlocks | `refresh.test.ts` | HAVE |
| INV-REFRESH-3 | Under rotation: persist-before-use, never retry a consumed token, family revocation → clean re-auth | `refresh.test.ts`, `reuse.test.ts` | HAVE |
| INV-REFRESH-4 | Expiry decisions tolerate clock skew and never trust the local clock alone | `refresh.test.ts` | HAVE |
| INV-REFRESH-5 | Every stored credential record carries a schema version | `vault.test.ts` | HAVE |

### Scope, flow, identity

| id | Claim | Proof | Status |
|---|---|---|---|
| INV-SCOPE-1 | Granted scopes tracked separately from requested; a withheld required scope fails loudly at connect | `scope.test.ts`, `client.test.ts` | HAVE |
| INV-SCOPE-2 | Where not `incremental`, a step-up re-requests the **union** of granted ∪ new scopes | `scope.test.ts` | HAVE |
| INV-SCOPE-3 | A step-up is user-attributable, never triggered by content the assistant merely read | `scope.test.ts`, `client.test.ts` | HAVE |
| INV-FLOW-1 | ≤1 live flow per (provider, account); a second connect supersedes the first | `singleflight.test.ts` | HAVE |
| INV-FLOW-2 | Cancellation is advisory, admission is authoritative; a superseded code is refused even if valid | `singleflight.test.ts`, `connect-flow.test.ts` | HAVE |
| INV-FLOW-3 | `connect()` returns fast and completes out of band; never blocks on the human | `connect-flow.test.ts`, `public-api.test.ts` | HAVE |
| INV-IDENT-1 | "connected" is produced by the identity probe resolving a handle, never an HTTP 200 | `connect-flow.test.ts` | HAVE |
| INV-IDENT-2 | The account id derives from the probe, not a display name; ambiguity is surfaced, never silently picked | `account.test.ts` | HAVE |

### Errors, reliability, observability

| id | Claim | Proof | Status |
|---|---|---|---|
| INV-ERR-1 | Every failure normalizes to the closed 9-code taxonomy, each carrying the raw provider error + a recommended action | `taxonomy.test.ts`, `public-api.test.ts` | HAVE |
| INV-REL-1 | The engine has zero runtime dependencies; nothing installs inside a connect window | Gate `make zero-dep` (`package.json` has no `dependencies`) | HAVE |
| INV-REL-2 | Token-endpoint retry uses jittered backoff on 429/5xx, never on 4xx, and is bounded | `client.test.ts`, `taxonomy.test.ts` (429→`RATE_LIMITED`, on-401 retry-once); device-poll backoff `device.test.ts` | PARTIAL — the on-401 single retry and 429 classification are proven; a dedicated **jittered-backoff-bounded** token-endpoint test is **UNMEASURED** (Target: a retry-policy unit test) |
| INV-REL-3 | The health probe is budgeted, backs off on failure, never runs during a turn, is idle/connectivity-aware, and is silent on success | `health.test.ts` | HAVE |
| INV-OBS-1 | The auth-event log contains no credential material | `observability.test.ts`, `guard-no-secret-in-build.test.ts` | HAVE |
| INV-INTEG-1 | Provider configs are signed/checksummed; a tampered config is rejected before it can select a path | — | **UNMEASURED** (Target G4; a config-checksum verification path + tamper test) |

---

## B. Metrics (SPEC §29)

| Metric | Definition | Proof | Status |
|---|---|---|---|
| Time to token (p50, p95) | From connect start to a usable credential | `observability.test.ts` (fresh mint records a sample; cache hits excluded; `percentile` nearest-rank) | HAVE (measurement path); **the field p50/p95 across real providers is UNMEASURED** until a live matrix run |
| Connect success rate | Per provider = success / (success + failure) | `observability.test.ts` | HAVE (measurement path) |
| Silent refresh rate | Share of serves without user interaction; target 1.0 | `observability.test.ts` (`fresh`/`refreshed` silent, `reauth_required` counts against) | HAVE (measurement path) |
| Re-auth rate per provider | Reauth serves + health breaks per provider | `observability.test.ts`, `health.test.ts` (broken transition records a reauth serve) | HAVE (measurement path) |
| Needs-attention ranking | Providers ranked by failures + reauths + broken-health | `observability.test.ts` | HAVE |
| Integration auth cost (LOC = 0) | Lines of auth code in a new integration | `client-zero-auth.test.ts`, `client.test.ts` (`auth.client()` shape; no token variable) | HAVE (existence proof on the wrapper); the **falsified-across-N-integrations** number is out of engine scope |
| Time to add a provider | p50 from `handshake add` to a verified connect | — | **UNMEASURED** (needs the CLI + timed runs; SPEC §30) |
| Wizard question count | Questions to profile an unknown provider | — | **UNMEASURED** (user wizard is out of engine scope; SPEC §20) |
| Tool coverage | Share of a provider's endpoints with a passing generated tool | — | **UNMEASURED** (tool generator out of scope; SPEC §21) |
| Conformance coverage | Providers passing the probe, by custody class | `probe.test.ts` (probe classifies correctly); **the matrix across real providers is UNMEASURED** (SPEC §30: one provider is an existence proof) | PARTIAL |
| On-device custody rate | Share of providers whose tokens never touch a server | Class-A on-device proven end to end; **distribution across real providers UNMEASURED** | PARTIAL |

---

## C. Custody ladder (SPEC §4, §5b) — every rung has a path and a custody proof

| Rung | Claim | Proof | Status |
|---|---|---|---|
| A (public) | No secret anywhere; fully on-device | `vault.test.ts`, `connect-flow.test.ts`, `scan-secrets.test.ts` | HAVE |
| B1 (BYO secret) | User's own secret in their keychain; nothing shared | `byos.test.ts`, `keystore.test.ts` | HAVE |
| B2a (assertion signing) | Relay signs, never sees a token, code, or verifier | `relay/test/jwt.test.ts`, `relay/test/handlers.test.ts`, `relay-client.test.ts` | HAVE (relay + engine) |
| B2b (exchange forwarding, hardened) | Relay exchanges once; X25519 ephemeral onward-encryption; stores nothing | `relay/test/seal.test.ts`, `relay/test/statelessness.test.ts`, `relay-client.test.ts` | HAVE (relay + engine) |
| C (DCR, RFC 7591) | Engine self-registers per user; credentials on device | `dcr.test.ts` | HAVE |
| — | A **live** B1/B2 proof against a real confidential dev app | — | **UNMEASURED** — human-gated: needs a confidential dev-app registration (SPEC §30, ENGINE-GAP §E) |

---

## D. Threat catalog (SPEC §12) — each attack is a test, not a paragraph

| Attack | Mitigation proof | Status |
|---|---|---|
| CSRF on the callback | `state.test.ts`, `callback-state.test.ts` | HAVE |
| Authorization-code interception | `pkce.test.ts` | HAVE |
| PKCE downgrade | `pkce.test.ts` | HAVE |
| Mix-up between concurrent providers | `mixup.test.ts` | HAVE |
| Local port squatting | `loopback.test.ts`, `port-reclaim.test.ts` | HAVE |
| DNS rebinding on the loopback listener | `loopback.test.ts` (Host-header validation) | HAVE |
| Open redirect via `redirect_uri` | `loopback.test.ts`, `exchange.test.ts` (byte-exact match) | HAVE |
| Refresh-token replay | `reuse.test.ts`, `refresh.test.ts` | HAVE |
| Token leakage through logs/errors | `scan-secrets.test.ts`, `guard-no-secret-in-build.test.ts`, `observability.test.ts` | HAVE |
| Secret leakage through process arguments | `vault.test.ts`, `keystore.test.ts` | HAVE |
| Malicious provider config | `malicious-config.blind.test.ts`, `exchange.test.ts`, `guard-no-provider-branch.test.ts` (config selects, never introduces a path); config **signing/checksum** = **UNMEASURED** (INV-INTEG-1, Target G4) | PARTIAL |
| Downgrade to plaintext key storage | `keystore.test.ts` (encrypted-file never silent, labeled weaker) | HAVE |
| Malicious profile phishing the authorize URL | Token-endpoint pinned to the authorize registrable domain — **UNMEASURED** (SPEC §20; a profile-supply-chain test) | UNMEASURED |
| Blind security conformance corpus | — | **UNMEASURED** (SPEC §13; the pre-committed, spec-only-authored corpus with a reported number is Target G4) |

---

## E. Standing honesty (SPEC §30) — what is proven vs stated-as-not-yet

**Proven by a run (this repo):**
- Engine suite green (`npx vitest run`), relay suite green (`cd relay && npx vitest run`),
  `tsc --noEmit` clean, `make verify` green from a clean checkout.
- Full OAuth round trip proven end to end on one provider (Class A), tokens on device.
- All four grant paths implemented and unit-proven: loopback+PKCE, loopback+client-auth, device
  (RFC 8628, `device.test.ts`), non-OAuth credentials (`byos.test.ts`).
- The five custody rungs each have a path + a custody-property test (§C above).
- Observability + background health, the two ops items this program closes, are wired into the
  live connect/refresh path and unit-proven (`observability.test.ts`, `health.test.ts`).

**Stated as not yet measured (with what would close each):**
- The **provider matrix** across real providers — one provider is an existence proof, not a
  universality proof. Closed by re-running the probe across N real providers and publishing the
  table with evidence receipts.
- **Custody-class distribution** across real providers — closed by the same matrix run.
- **Time-to-token p50/p95 as a field number** — the measurement path exists (§B); the number needs
  live connects across providers.
- **A live B1/B2 proof** — human-gated on a confidential dev-app registration.
- **The code-signed native keychain ACL** (INV-SECRET-5) — needs macOS code-signing +
  keychain-access-group entitlement; the CLI fallback is development-grade and labeled as such.
- **Config signing/checksum** (INV-INTEG-1) and the **blind security corpus** (SPEC §13) — Target G4.
- **Token-endpoint jittered-backoff-bounded retry** (INV-REL-2) as a dedicated test.
- Mobile and Windows key-store backends — designed, unproven (SPEC §34).

*The rule that keeps this file honest: fix the engine, never the claim. A row moves from
`UNMEASURED`/`PARTIAL` to `HAVE` only when a named, green test id backs it.*
