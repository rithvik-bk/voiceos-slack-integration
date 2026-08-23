/**
 * Conformance-probe type surface (C-1, C-18 — SPEC Part 1 §2, §20 rung 2).
 *
 * The probe MEASURES a provider and emits two artifacts:
 *   1. `providers/<name>.json`         — a partial {@link ProviderProfile}, measured fields only.
 *   2. `providers/<name>.evidence.json` — the redacted request/response receipt behind every
 *                                          field. "Every claim in the matrix has a receipt" (§2).
 *
 * The governing law is INV-CONFIG-5: any field the probe cannot determine is emitted as
 * `unknown` (or simply omitted from the profile so the engine's own conservative default
 * applies). There is no guessing. A receipt is attached whether the answer was found or not,
 * because "we looked and could not tell" is itself a measurement worth showing a founder.
 *
 * Style law (matches engine/src/types.ts): no `enum`, no runtime `namespace`, no parameter
 * properties. Node strips these types, it does not compile them.
 */

/*
 * Capability-dimension types are declared HERE, local to the probe, on purpose. The engine's
 * `ProviderProfile` (engine/src/types.ts) grows these same fields under the G1 capability-schema
 * work (C-22); duplicating the closed value sets here keeps the probe a strictly-additive module
 * that typechecks with or without that edit, and the string literals are byte-identical so a
 * probed profile deserializes straight into the extended `ProviderProfile` once it lands.
 * See the integration note: `MeasuredProfile` collapses to `Partial<ProviderProfile>` then.
 */

/** How the token endpoint authenticates the client — the axis that decides custody (SPEC §1). */
export type ClientAuth = 'none' | 'secret_post' | 'secret_basic' | 'private_key_jwt' | 'mtls' | 'unknown';
/** Whether endpoints can be fetched from `.well-known` (RFC 8414 / OIDC) vs hand-configured. */
export type Discovery = 'rfc8414' | 'oidc' | 'none' | 'unknown';
/** RFC 7591 dynamic client registration — unlocks Custody Class C. */
export type Dcr = 'rfc7591' | 'none' | 'unknown';
/** RFC 9126 pushed authorization requests. */
export type Par = 'rfc9126' | 'none' | 'unknown';
/** How each subsequent API call is bound: bearer / DPoP (RFC 9449) / mTLS. */
export type SenderConstraint = 'bearer' | 'dpop' | 'mtls' | 'unknown';
/** RFC 8628 device authorization grant — the no-browser/no-loopback fallback. */
export type DeviceFlow = 'rfc8628' | 'none' | 'unknown';
/** Whether granted scopes may differ from requested; `incremental` enables step-up. */
export type ScopeGrant = 'exact' | 'downgradeable' | 'incremental' | 'unknown';
/** Whether disconnect can revoke upstream (RFC 7009 / proprietary) or only forget. */
export type Revocation = 'rfc7009' | 'proprietary' | 'none' | 'unknown';
/** DERIVED custody rung (§4, §5b). */
export type CustodyClass = 'A' | 'B1' | 'B2a' | 'B2b' | 'C' | 'unknown';
/** DERIVED relay sub-mode when a relay is involved (§5b). */
export type RelayMode = 'none' | 'assertion_signing' | 'exchange_forwarding' | 'unknown';
/** Reddit genuinely has no PKCE — hence S256|none, matching the engine's `PkceMode`. */
export type PkceMode = 'S256' | 'none';

/**
 * The subset of a provider profile the probe MEASURES. Field names + value literals are
 * byte-identical to the engine's `ProviderProfile`, so `providers/<name>.json` loads straight
 * into the engine once the G1 schema extension lands. Everything optional: an unmeasured field
 * is simply absent (the engine applies its conservative default) and a probed-but-unclassified
 * field carries the literal `'unknown'`.
 */
export interface MeasuredProfile {
  $schema?: string;
  schema_version?: number;
  name: string;
  display_name?: string;
  authorize_url?: string;
  token_url?: string;
  revoke_url?: string;
  client_id?: string;
  pkce?: PkceMode;
  client_auth?: ClientAuth;
  discovery?: Discovery;
  dcr?: Dcr;
  par?: Par;
  sender_constraint?: SenderConstraint;
  device_flow?: DeviceFlow;
  scope_grant?: ScopeGrant;
  revocation?: Revocation;
  custody_class?: CustodyClass;
  relay_mode?: RelayMode;
  redirect_host?: string;
  token_path?: string;
  refresh_token_path?: string;
  expires_in_path?: string;
  refresh?: 'rotation' | 'long_lived' | 'none';
  rotation?: 'forced' | 'optional-enabled' | 'optional-off' | 'none';
  _notes?: Record<string, string>;
}

/** JSON scalars a receipt is allowed to record as the measured value. */
export type ReceiptValue = string | number | boolean | null | string[];

/**
 * The proof behind ONE measured field. `method` is the technique ('rfc8414-discovery',
 * 'unauthenticated-token-exchange', 'authorize-redirect-tolerance', 'token-response-shape',
 * 'first-refresh-rotation'), and `request`/`response` are the redacted wire trace that
 * justifies `value`. When the probe could not determine the field, `value` is `'unknown'`
 * and `note` says what was missing.
 */
export interface Receipt {
  /** The `ProviderProfile` field (or SPEC §1 dimension) this receipt justifies. */
  field: string;
  /** What the probe concluded. `'unknown'` when undeterminable (INV-CONFIG-5). */
  value: ReceiptValue;
  /** How it was measured. */
  method: string;
  /** The safe request the probe issued, if any. */
  request?: { method: string; url: string; body?: string };
  /** The provider's answer — status plus a redacted, length-capped body. */
  response?: { status: number; body?: string };
  /** Why the value is what it is — mandatory when `value` is `'unknown'`. */
  note?: string;
}

/** The full receipt set for one provider — the `<name>.evidence.json` file. */
export interface ProbeEvidence {
  provider: string;
  /** ISO 8601 instant the probe ran. */
  probed_at: string;
  /** The seed the probe was pointed at (documentation URL, issuer, or authorize endpoint). */
  target: string;
  receipts: Receipt[];
}

/**
 * The measured profile plus its evidence. `profile` is a PARTIAL ProviderProfile: only the
 * fields the probe could measure are present, and any that were probed-but-unclassifiable
 * carry the literal `'unknown'` the engine treats as most-conservative.
 */
export interface ProbeResult {
  profile: MeasuredProfile;
  evidence: ProbeEvidence;
}

/** Injected in tests; production uses the platform `fetch`. Mirrors exchange.ts's HttpOptions. */
export interface ProbeHttp {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}
