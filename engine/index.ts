/**
 * VENDORING SHIM — the integration's single point of contact with the OAuth engine.
 *
 * Every other file in this integration imports from `./engine/index.ts` and nothing else.
 * The integration itself contains ZERO auth logic: no PKCE, no loopback port, no `state`,
 * no token store, no refresh. All of that lives in the vendored engine and is reached only
 * through the three-verb public API this line re-exports (connect · getToken · disconnect,
 * plus getConnectStatus for the two-phase poll).
 *
 * In this standalone repo the engine is vendored under `vendor/oauth-engine/` (a frozen
 * snapshot of the open-source voiceos-oauth-engine), so this re-export resolves entirely
 * inside the repo — the integration is self-contained and needs nothing outside it to
 * type-check or run.
 *
 * When VoiceOS packs this folder into its custom-MCP directory, the pack step overwrites
 * this `engine/` directory with a real copy of the engine's `engine/src/`. `server.ts` and
 * the tool files never change: they import `./engine/index.ts` either way.
 */
export * from '../vendor/oauth-engine/engine/src/index.ts';
