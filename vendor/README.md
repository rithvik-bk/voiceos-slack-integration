# vendor/ — frozen engine snapshot

This integration is built on the **voiceos-oauth-engine** — one provider-agnostic OAuth
engine (PKCE · loopback · `state` · Keychain vault · silent refresh) that does all of the
auth work so the integration itself contains zero auth code.

**oauth-engine/** is a source snapshot of that engine, vendored here so this repo is fully
self-contained: it type-checks and runs with nothing outside the folder.

- Source: `~/voiceos-oauth-engine` · branch `main` · commit `4826d96` (2026-08-23)
- Excludes: `node_modules`, `.git`, `dist`.
- Contains the engine source (`engine/src/`), the callback assets, the provider schema, the
  stateless relay, and the full test suite (engine + relay + blind adversarial tests).

The one link between the integration and this snapshot is `../engine/index.ts`, which
re-exports `oauth-engine/engine/src/index.ts` — the engine's three-verb public API
(`connect` · `getToken` · `disconnect`, plus `getConnectStatus`).

Re-verify the engine on its own (from this folder):

    cd oauth-engine && npm ci && npm run check      # typecheck + tests + drift + secret scan
