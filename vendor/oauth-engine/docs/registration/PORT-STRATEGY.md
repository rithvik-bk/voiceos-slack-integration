# PORT STRATEGY — fixed ladder, not ephemeral
*Decides the loopback port model and freezes the literal redirect URI strings for provider registrations. Conforms to the engine contract (§A3 single-socket listener · §A5 length-1 ladder for single-URI providers · §A8 byte-identical redirect_uri · W1 config constants). Every provider fact below was verified against live official docs; URLs cited inline.*

---

## 1 · THE DECISION

**Fixed port ladder. Never ephemeral.**

```
PORT_LADDER   = [33418, 33419, 33420]     // walk in order; first bindable wins
REDIRECT_HOST = 'localhost'
CALLBACK_PATH = '/callback'
redirectUri(port) = `http://localhost:${port}/callback`
```

- **Slack** registers all three ladder rungs (three redirect URLs in one manifest paste).
- **Zoom** registers all three where the form allows (Redirect URL field takes one; Allow List takes the rest — see §4.2).
- **Reddit** registers exactly one — `33418` — because the form accepts exactly one URI. Its ladder is length-1: `redirect_ports: [33418]`. If 33418 is bound, the ONLY recovery is the `port_blocked` state (contract §A5, ratified as a designed decision, not a bug).

The engine walks the ladder, binds the first free port, and **always sends the exact bound URI — byte-identical — in both the authorize request and the token exchange** (contract §A8; unit test required; Slack's omitted-param behavior in §3.1 is why).

## 2 · THE LITERAL STRINGS THE AUTHOR PASTES

These three are the **only redirect URIs this project registers or binds**. Any other spelling of *our* redirect (`127.0.0.1`, a trailing slash, `https`, a different path) is drift and fails `tools/drift-check.mjs`.

**What the drift check actually allows** (the rule and its exemptions live together in `tools/drift-check.mjs`, so the rule is runnable rather than aspirational — an earlier version of this paragraph said "the only redirect strings that exist anywhere in this project," which was never true and could never go green):

| # | Allowed | Why |
|---|---|---|
| A | the three ladder URIs below | generated from `engine/src/config.ts`, the sole source |
| B | `http://voiceos.test:33418/callback` | Zoom's **sanctioned** hosts-alias fallback (§A11a — the sanctioned Zoom hosts-alias fallback) — pre-registered on purpose, listed in `SANCTIONED_FALLBACK_REDIRECTS` |
| C | a bare `localhost:33418` authority in prose | no port-plus-path URI, nothing to mis-register |
| D | verbatim provider-doc / forum quotes (`http://localhost:8080/auth`, `https://localhost:3000/`, …) | evidence we cite; enumerated with reasons in `QUOTED_EXAMPLES` |
| E | ladder notations (`http://localhost:334xx/callback`, `redirectUri(port)`) | shorthand for all three rungs, not a fourth spelling |
| F | a line marked `<!-- drift-check:ignore-line -->` (or a file marked `drift-check:ignore-file`) | for a line that must quote a stale string on purpose — e.g. a doc that must quote the pre-A9 architecture wording |

Anything else fails, and the relay URL (once a host is chosen, §E6) is added to the allowlist in the same commit that puts it in a `provider.json`.

**Slack** (api.slack.com/apps → create from manifest → `oauth_config.redirect_urls`):
```
http://localhost:33418/callback
http://localhost:33419/callback
http://localhost:33420/callback
```

**Zoom** (marketplace.zoom.us → app → Redirect URL field + OAuth Allow List — report each verdict separately per contract §A11a):
```
http://localhost:33418/callback        ← Redirect URL field
http://localhost:33418/callback        ← Allow List entry 1
http://localhost:33419/callback        ← Allow List entry 2
http://localhost:33420/callback        ← Allow List entry 3
```

**Reddit** (reddit.com/prefs/apps → "installed app" → redirect uri — the form takes ONE):
```
http://localhost:33418/callback
```

## 3 · WHY FIXED, NOT EPHEMERAL — the standard vs. the world

### 3.1 What RFC 8252 §7.3 says (the ephemeral-port ideal) [NORMATIVE]
Fetched live 2026-08-16 — https://datatracker.ietf.org/doc/html/rfc8252#section-7.3:

> "The authorization server MUST allow any port to be specified at the time of the request for loopback IP redirect URIs, to accommodate clients that obtain an available ephemeral port from the operating system at the time of the request."

If all three providers honored that MUST, we would bind port 0, take whatever the OS gave us, and never register a port at all. **None of the three honors it:**

| Provider | Live evidence (fetched 2026-08-16) | Verdict on ephemeral ports |
|---|---|---|
| **Slack** | docs.slack.dev/authentication/installing-with-oauth/: *"Your `redirect_uri` must match or be a subdirectory of a Redirect URL configured under App Management"* — and port numbers must align with the registered URL (custom ports require explicit configuration in the registered Redirect URL). Also: with multiple registered URLs and **no** `redirect_uri` param, *"the OAuth flow will use the first Redirect URL listed"* — the silent dead-33418 trap behind contract §A8. | ❌ Port is part of the registered-URL match. No wildcard. |
| **Zoom** | developers.zoom.us/docs/integrations/oauth/: *"Your redirect URI. Use the same OAuth Redirect URL in your Marketplace app"*; PKCE exchange requires *"the same redirect URI used in the authorization request."* Docs are silent on ports/wildcards — silence in a registered-URL model means no. | ❌ Registered-URL match. (Whether `localhost` saves at all was open unknown U2 — now CLOSED: Zoom's redirect field rejects the literal `localhost` and blesses the IP literal, so Zoom registers on `LOOPBACK_IP_HOST` in `engine/src/config.ts`.) |
| **Reddit** | github.com/reddit-archive/reddit/wiki/OAuth2: *"If this does not match the registered redirect_uri, the authorization request will fail"* and at token exchange: *"Yes, you need it here again, and yes, it must match exactly."* One registered URI per app. | ❌ Exact match, single URI. Hardest constraint of the three — it alone forces a pre-agreed port. |

**Conclusion:** RFC 8252's ephemeral-port model requires authorization-server cooperation that Slack, Zoom, and Reddit all withhold. A port must be registered, so a port must be fixed in advance. Fixed ladder is the only design that satisfies all three simultaneously; Reddit's single-URI form is the binding constraint that collapses its ladder to one rung.

### 3.2 Why a *ladder* of three, not one port
One fixed port is a single point of failure: anything squatting on 33418 (another app, a zombie listener) kills every connect. Three registered rungs give Slack and Zoom two escape hatches at zero protocol cost — the engine binds the first free rung and sends that exact URI. Three (not five, not ten) because each rung is a string typed into two dashboards and a manifest, and the marginal reliability of rung 4 is negligible while the drift surface grows linearly. Reddit gets no escape hatch by provider fiat; the compensating control is procedural: `lsof -i :33418` is a hard line on the pre-demo checklist and the `port_blocked` copy-deck state must be proven to fire by test (contract §A5, matrix invariant I2).

### 3.3 Why 33418/33419/33420 specifically
- **IANA-unassigned:** the live IANA service-names-port-numbers CSV was queried 2026-08-16 for ports 33418–33420 — zero assignments. [EMPIRICAL — `curl … | awk -F, '$2==33418||$2==33419||$2==33420'` returned nothing]
- **Below the OS ephemeral range:** on the demo Mac, `sysctl net.inet.ip.portrange.first/last` = 49152–65535 [EMPIRICAL, measured 2026-08-16]. The OS will never hand 33418–33420 out as an outbound ephemeral port, so we don't race the kernel for our own mailbox.
- **Outside the dev-tool default belt:** nothing popular lives there (3000/5173/8000/8080/8888 crowd is far away), so collision with other local tooling is unlikely.
- **Contiguous:** one config constant, human-memorable, and the ladder reads as intentional in a code review.

### 3.4 Host: `localhost`, a deliberate deviation from the RFC's recommendation
RFC 8252 §7.3 *recommends* the loopback IP literal (`http://127.0.0.1:{port}/`) over `localhost` (misconfigured-resolver and firewall arguments). We deviate, deliberately, and record it here:

1. **Slack's http-redirect blessing is scoped to the word `localhost`.** docs.slack.dev/authentication/using-pkce/: *"Redirects to `localhost` (e.g. `http://localhost:8080/auth`) are treated as desktop redirects if the app has opted into PKCE."* Slack's docs never mention `127.0.0.1`; registering the string their docs bless is the low-risk move on the flagship provider.
2. **The RFC's failure mode is neutralized by our listener.** The engine binds ONE `::` socket with `ipv6Only: false` that answers `localhost`, `127.0.0.1`, and `[::1]` alike (contract §A3, measured). Whatever the user's resolver returns for `localhost` — A or AAAA — lands in the same mailbox.
3. **Consistency beats purity.** One host string across three dashboards, provider.json files, docs, and tests is exactly what `drift-check.mjs` can enforce. Mixed `127.0.0.1`-here-`localhost`-there is how the §A8 dead-redirect class of bug is born.

Residual risk (a machine with `localhost` mis-resolved to a non-loopback address) is accepted and belongs in THREAT-MODEL.md's residual-risk section (W11).

## 4 · REGISTRATION NOTES THAT FALL OUT OF THIS DECISION

### 4.1 Slack
All three URIs go in the single manifest paste (`oauth_config.redirect_urls`, contract §A14). Because Slack matches "match **or subdirectory** of a registered URL," our exact-string engine behavior is strictly inside Slack's tolerance. The omitted-param → first-registered-URL behavior is why the registration lists **33418 first** — if a bug ever drops the param, the browser at least lands on the rung the engine tries first.

### 4.2 Zoom
The Redirect URL field appears to take one URI; the OAuth Allow List takes several. Ladder walking on Zoom is therefore only as real as the Allow List makes it — the two verdicts are reported **separately** (contract §A11a), and if only the single Redirect URL field is honored for the dance, Zoom degrades to a length-1 ladder like a single-URI provider, which the engine already supports via `redirect_ports: [33418]`. No code change either way.

### 4.3 Reddit
`redirect_ports: [33418]` in provider.json is not a shortcut — it is the provider's shape. Do not "fix" it to three rungs; the form takes one URI and the exchange requires the exact registered string.

## 5 · ENGINE INVARIANTS THIS DOC BINDS (already in the contract; restated as the port-strategy's contract surface)

- **I-P1** `engine/src/config.ts` (W1, shipped) is the sole source of `PORT_LADDER`, `REDIRECT_HOST`, `CALLBACK_PATH`, `redirectUri(port)`. Every other file — any provider.json, docs/ARCHITECTURE.md, this doc — must spell our redirect as `http://localhost:334(18|19|20)/callback`, with only the §2 A–F exemptions. Enforced by `tools/drift-check.mjs`, which imports the constants from `config.ts` rather than restating them, and additionally cross-checks every `provider.json`'s `redirect_host`/`redirect_ports` against the ladder.
- **I-P2** The URI sent in the authorize request and the token exchange is the exact bound rung, byte-identical, never omitted (contract §A8; unit test in W6).
- **I-P3** `state` encodes the bound port (`nonce.port`) so a callback arriving on the wrong rung is rejected, single-use, 60s TTL (W4).
- **I-P4** Ladder exhaustion (all registered rungs bound) → `port_blocked` copy-deck state, spoken line + branded page; a test proves it fires (contract §A5 / invariant I2).
- **I-P5** Bind-before-browser, always: the listener owns the rung before the authorize URL opens — mandatory everywhere, load-bearing on no-PKCE Reddit (THREAT-MODEL.md W11).

## 6 · CLAIM LEDGER (for W12's claims.json)

| ID | Claim | Type | Source (fetched 2026-08-16) |
|---|---|---|---|
| C-PS1 | RFC 8252 §7.3: AS MUST allow any port at request time for loopback redirect URIs | NORMATIVE | datatracker.ietf.org/doc/html/rfc8252#section-7.3 |
| C-PS2 | RFC 8252 §7.3 recommends loopback IP literal over `localhost` | NORMATIVE | same |
| C-PS3 | Slack: redirect_uri must match/be subdirectory of a registered Redirect URL; ports must align; omitted param → first registered URL | NORMATIVE (vendor doc) | docs.slack.dev/authentication/installing-with-oauth/ |
| C-PS4 | Slack: `http://localhost:…` redirects are desktop redirects once PKCE is on; docs never bless `127.0.0.1` | NORMATIVE (vendor doc) | docs.slack.dev/authentication/using-pkce/ |
| C-PS5 | Reddit: redirect_uri must exactly match the single registered URI, at authorize AND exchange | NORMATIVE (vendor doc) | github.com/reddit-archive/reddit/wiki/OAuth2 |
| C-PS6 | Zoom: exchange requires the same redirect URI as authorize; docs silent on ports/localhost (U2 — CLOSED, resolved to the IP-literal host in `engine/src/config.ts`) | NORMATIVE (vendor doc, silence noted) | developers.zoom.us/docs/integrations/oauth/ |
| C-PS7 | Ports 33418–33420 are IANA-unassigned | EMPIRICAL | IANA service-names-port-numbers.csv, awk query, zero rows |
| C-PS8 | Demo-Mac ephemeral range is 49152–65535 (ladder can't be OS-assigned) | EMPIRICAL | `sysctl net.inet.ip.portrange.first/last` on this Mac |

## 7 · ACTION ITEMS
Nothing new. The strings in §2 are the ones embedded in each provider's registration steps (contract §E items 3–5). Paste them exactly — including the absence of a trailing slash. Per contract §E8, the form's verbatim accept/reject text for each URI field is the report-back evidence.
