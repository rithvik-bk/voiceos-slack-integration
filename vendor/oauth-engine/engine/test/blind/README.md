# Blind attack corpus — `engine/test/blind/`

Authored by a **blind red-team** whose only inputs were `docs/handshake/SPEC.md`
(Part 3, §12–§13 threat model) and `docs/handshake/INVARIANTS.md`. No engine
source, no existing test, and no pod note was read. The engine's interface was
learned only by *running* it (enumerating exports and probing input→output at
runtime), never by reading its source text — running is not reading.

Each `test()` is exactly **one attack case**. A green test = the engine **defended**
that attack. A red test = the engine **failed** it, and the assertion message is the
observable symptom. The "blind number" is `defended / total` across every case here.

The fixer works against the engine, never against this corpus. These cases are the
spec's promises turned into adversarial inputs; if a promise is not yet kept, the
case is *supposed* to be red until the engine earns it.

| File | Threat-model entry (SPEC §12/§13) | Invariants |
|---|---|---|
| `state-tamper-replay.blind.test.ts` | tampered / replayed `state`, superseded flow admission | INV-STATE-1/2, INV-FLOW-1/2 |
| `pkce-downgrade.blind.test.ts` | PKCE downgrade, verifier confinement | INV-PKCE-1/2 |
| `mixup-provider.blind.test.ts` | RFC 9207 mix-up between concurrent providers | INV-STATE-3 |
| `refresh-replay.blind.test.ts` | refresh-token replay after rotation, family revocation | INV-REFRESH-3 |
| `malicious-config.blind.test.ts` | malicious provider config / code-injection via config | INV-CONFIG-2, INV-CUST-2 |
| `relay-assertion-oracle.blind.test.ts` | relay abuse — assertion oracle, silent relay redirect | INV-CUST-3/4/5 |
| `multi-account-confusion.blind.test.ts` | multi-account confusion, silent wrong-account pick | INV-IDENT-2 |
| `open-redirect.blind.test.ts` | open redirect via `redirect_uri` | INV-REDIR-2/3 |
| `secret-leakage.blind.test.ts` | secret leakage through logs / errors | INV-SECRET-1/4 |
