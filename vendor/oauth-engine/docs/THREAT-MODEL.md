# THREAT MODEL — the zero-paste OAuth engine
*Work item W11 · opened 2026-08-16 (audit fix round 1) · owner: whoever last touched `engine/src/loopback.ts`*

Scope: everything an attacker can reach because this engine exists — the loopback listener, the
authorization code in flight, the vault, and the strings that end up on a projector. Out of
scope: an attacker who already has the user's Mac password or root, which defeats the Keychain
and therefore defeats everything downstream.

The rule this document follows: **a risk we accept is written down with its blast radius, not
left implicit in a code comment.** Anything not written here is either mitigated below or was
never thought about — and the second kind is the one that bites.

---

## The assets, in order of what it costs to lose one

| # | Asset | Loss looks like |
|---|---|---|
| A1 | The user's access/refresh token | An attacker reads their Slack |
| A2 | An authorization code in flight | Same, one exchange later |
| A3 | The PKCE verifier | Only dangerous WITH A2 |
| A4 | Availability of the connect flow | The demo dies on stage; no data loss |
| A5 | Truth of what is said/shown | We claim something false in front of the user |

---

## T1 — A local process races the real callback (code theft)
**Mitigated.** The code is only ever accepted with a `state` that matches the one this process
minted (32 random bytes, single-use, 60s TTL, constant-time compare — `engine/src/state.ts`,
compared in `loopback.ts`). A wrong-state hit gets the mismatch page and **does not** end the
wait, so a guesser cannot cancel the real flow either. PKCE means a stolen code is useless
without the verifier, which never leaves this process.

## T2 — A page on the internet hits `http://localhost:33418/callback`
**Mitigated for code delivery** by T1 (no valid `state`, no delivery). **Mitigated for the DoS
variant** by fetch metadata — see W11 below.

## T3 — Token bytes reaching disk or a log
**Mitigated.** Tokens live only in the macOS Keychain (`security` generic passwords, service
`com.voiceos.connect.<provider>`); nothing is written to a file. No `code`, `state`, verifier or
token is logged at any level, and none is interpolated into a callback page — the pages are
screen-shared, so the redaction rule applies to pixels too. `tools/scan-secrets.mjs` is the
push gate, and the build-output scan is exercised by `engine/test/guard-no-secret-in-build.test.ts`.

## T4 — A hostile `provider.json`
**Mitigated.** Profiles are validated against `provider.schema.json`; the vault service string
is built from the profile `name`, so a traversal-shaped name is rejected before it reaches
`security`. Values are passed to `execFile` as argv, never through a shell.

## T5 — A false sentence on the projector (A5)
**Mitigated, and it has bitten twice.** Every spoken string is a row of the frozen copy deck
in `engine/src/copy.ts`, exercised by the copy/pages tests. The two
real defects both had the same shape — *blaming the provider for something that was not the
provider's doing*: `provider_error` used to render an empty channel, and it used to render a
browser that would not launch. Both now have their own ratified rows.

---

## W11 — RESIDUAL RISK: an unauthenticated error callback can cancel an in-flight connect

**The shape.** `engine/src/loopback.ts` honors `?error=access_denied` carrying **no `state`**,
because RFC 6749 §4.1.2.1's "`state` is REQUIRED if the request had one" is not something every
provider actually does on Cancel, and the deliberate Cancel beat (D8) is in the demo script.
Anyone able to send that request settles the flow as `denied_by_user`; the real callback then
arrives to a terminal page and its code is never accepted.

**Checked, not assumed (2026-08-16):** Slack's OAuth documentation
(docs.slack.dev/authentication/installing-with-oauth/) documents only the success redirect. It
does not state what the Cancel button emits, so "Slack echoes `state` on deny" is **unverified**
and cannot be relied on. The empirical answer is a human clicking Cancel on the real consent
screen — it is a line item in the demo rehearsal, and if Slack does echo `state`, the state-less
branch can be deleted outright and this entry closed.

**What was fixed in round 1.** The remote half is gone. A state-less error is now honored only
when the request looks like a real top-level navigation (`Sec-Fetch-Dest: document` /
`Sec-Fetch-Mode: navigate`); a browser labels a drive-by `<img>`/`fetch` GET differently and
cannot forge those headers, so a web page can no longer cancel a connect. Absent fetch-metadata
headers are accepted deliberately (pre-2020 browsers, and our own tests): hardening the remote
vector must not add a new way for the live demo to fail.

**What remains.** A **local** process on this Mac can still send `Sec-Fetch-Dest: document` by
hand and cancel an in-flight connect.

- **Blast radius:** availability only (A4). No credential is exposed, nothing is written, and
  the user hears the deck's `denied_by_user` line and can say "connect Slack" again — the exact
  recovery the script already rehearses. An error carrying a *wrong* `state` is still rejected
  outright, and a *code* is never accepted without a matching state.
- **Attacker required:** arbitrary local code execution — which already beats a Keychain prompt
  and every other control here.
- **Accepted** at this blast radius. Closing it fully means refusing state-less errors, which
  trades a local-only DoS for the risk of a dead Cancel beat against an undocumented provider
  behaviour. Revisit the moment the rehearsal answers the Slack question.
