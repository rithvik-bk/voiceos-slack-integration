# Add a provider

Adding a provider touches **zero engine code**. The engine has one branch per capability *value*, never one per provider *name* — `if (provider === 'x')` is a permanent bug, enforced by a test that greps the source. So a new provider is a single `provider.json` config file that you hand to the engine with `registerProvider()`. That is the whole job.

The runnable reference for everything below is in the repo:

- **`tools/mock-provider/server.mjs`** — a complete, self-contained OAuth authorization server plus a `mockProviderProfile()` that returns a valid, engine-ready profile. Read it to see a working profile object next to the server it describes.
- **`tools/demo.mjs`** (`make demo`) — drives the real engine through the full `connect → getToken → refresh` round trip against that mock provider, with no account, no registration, and no secret. Run it, then read it top to bottom: it is the shortest possible example of wiring a provider into the engine.

## Step 1 — describe the provider (`provider.json`)

Every way this provider differs from the happy path is a **field**, not a code path. Read them off the provider's live OAuth docs. Here is a complete, worked example for a public / PKCE provider (Custody Class A — nothing leaves the device). It is the same shape `mockProviderProfile()` produces, so you can diff your file against a known-good one:

```json
{
  "$schema": "../provider.schema.json",
  "schema_version": 1,

  "name": "acme",
  "display_name": "Acme",

  "client_type": "public",
  "client_id": "acme-pub-8f2c1a90",

  "pkce": "S256",

  "redirect_strategy": "loopback",
  "redirect_host": "localhost",
  "redirect_ports": [33418, 33419, 33420],

  "authorize_url": "https://acme.com/oauth/authorize",
  "token_url": "https://acme.com/oauth/token",
  "api_base": "https://api.acme.com/v1",

  "scope_param": "scope",
  "scope_delimiter": " ",
  "scopes": ["tasks.read", "tasks.write"],
  "extra_authorize_params": {},

  "token_auth": "none",
  "refresh_auth": "client_id_body",

  "token_path": "access_token",
  "refresh_token_path": "refresh_token",
  "expires_in_path": "expires_in",
  "success_predicate": null,

  "refresh": "rotation",
  "rotation": "optional-enabled",
  "access_token_ttl": 3600,

  "identity_probe": {
    "url": "https://api.acme.com/v1/me",
    "method": "GET",
    "auth": "bearer",
    "handle_path": "user.name",
    "workspace_path": "team.name"
  },

  "_placeholders": ["client_id"]
}
```

**What each group is doing** (all validated against `provider.schema.json` at the repo root):

- **Identity** — `name` / `display_name`, and the **public** `client_id`. A client ID is not a secret, so it ships committed in this file. There is no `client_secret` here and there never can be: the schema structurally cannot hold one (Class A/B1/C keep secrets in the vault; only a relay ever holds an app secret, out of band).
- **Grant selection** — `pkce: "S256"` + `token_auth: "none"` is what lands this provider on **Custody Class A**. Change `token_auth` to a secret-bearing value and the engine routes to a B1/B2 path instead — same config file, different derived class.
- **Redirect** — `redirect_host` matters: `localhost`, `127.0.0.1`, and `[::1]` are **not** interchangeable in provider allowlists, and the redirect URI must be byte-identical between the authorize and token requests. `localhost` is the default; use `127.0.0.1` only where the provider's own registration form demands the IP literal. Register the three `redirect_ports` in the provider console so a busy port has fallbacks (some providers register exactly one URI — then use a length-1 ladder, `redirect_ports: [33418]`).
- **Token shape** — `token_path` is where the access token lives in the response (top-level `access_token` here; some providers nest it deeper). `success_predicate: null` means the HTTP status is the whole verdict; set it to `{ "path": "ok", "equals": true }` when a provider returns `200` with `{"ok": false}`.
- **Refresh** — `refresh` + `rotation` tell the engine whether refresh tokens rotate, so reuse-detection and the crash-safe cross-process refresh lock behave correctly.
- **Identity probe** — the engine reports "connected" only after this returns a real handle, never on a bare HTTP 200. `handle_path` / `workspace_path` are dotted paths into the response.

Anything the provider does that is not covered by an existing field is the one case where you stop and add a **capability dimension** to the schema — not a provider branch. In practice the fields already cover the axes providers actually vary on.

## Step 2 — register it, then call three verbs

Hand the parsed profile to the engine once at startup. From then on the calling code only ever touches `connect`, `getToken`, and `disconnect` — auth is **absent** from your code. You never see a token variable, a PKCE verifier, or a refresh call.

```ts
import { registerProvider, getToken } from '../engine/src/index.ts';

const profile = JSON.parse(await readFile('./provider.json', 'utf8'));
registerProvider(profile);            // teach the engine this provider

// getToken() returns a token that is valid right now — refresh, rotation,
// and the cross-process lock already happened before it returned.
const token = await getToken(profile.name);
const res = await fetch(`${profile.api_base}/tasks`, {
  headers: { authorization: `Bearer ${token}` },
});
```

Or use the zero-auth-code client wrapper, which injects the credential, refreshes on expiry, and retries once on a 401:

```ts
const api = auth.client("acme");
const res = await api.get("/tasks");
```

If you prefer not to call `registerProvider()`, the engine also resolves a profile from disk: place your `provider.json` next to the engine (see `profileCandidates()` in `engine/src/index.ts`) and `getToken(name)` will load it. `registerProvider()` is the recommended path.

**Lines of authorization code in this integration: zero.** That is the claim, and it is falsifiable — grep your code for anything that does PKCE, opens a port, or touches a token, and you find nothing.

## The integration layer sits on top

The user-facing surface — the tool bodies a person invokes, the integration manifest, and the consent-screen icon — is a **separate layer built on top of this engine** and lives outside this repository. This repo gives that layer exactly one dependency: a provider-agnostic auth broker it configures with a `provider.json` and drives with three verbs. Whatever framework hosts your tools, the wiring above is all the engine asks of it.

## That's the whole job

1. Write `provider.json` from the provider's live docs; paste the public `client_id`.
2. `registerProvider(profile)` once at startup.
3. Call `getToken(name)` (or `auth.client(name)`) from your tool code.

No engine file changed. The authorization cost of this provider was zero lines of code, and its capability profile is data the next person can reuse. Validate your file the way the engine does — against `provider.schema.json` — and confirm the end-to-end flow with `make demo`.
