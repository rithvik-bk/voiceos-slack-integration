/**
 * Engine type surface — SCAFFOLD (work item W16 → consumed by W1/W2/W4).
 *
 * Two things live here and nowhere else:
 *  1. `ProviderProfile` — the v1 capability model. Every axis on which Slack, Zoom and
 *     Reddit actually differ is a FIELD, never an `if (provider === 'reddit')` in the
 *     engine. Field set = docs/handshake/SPEC.md capability axes.
 *  2. `ConnectStatus` — the product-surface contract, frozen up front so the rendering
 *     layer is built against a fixed shape, not archaeology.
 *
 * Style law: no `enum`, no parameter properties, no runtime `namespace`. Node strips types,
 * it does not compile them (tsconfig `erasableSyntaxOnly`).
 */

/* ─────────────────────────── Provider capability model (v1) ─────────────────────────── */

/** Public = no secret ships anywhere. All three flagship providers are public clients. */
export type ClientType = 'public' | 'confidential';

/** Reddit genuinely has no PKCE — hence the desk is named "zero-paste", not "PKCE". */
export type PkceMode = 'S256' | 'none';

/* ── Capability dimensions (SPEC §1). Every measured axis carries `unknown`: the probe
 *    emits it where it cannot classify, and the engine treats it as the most conservative
 *    value (§2, "there is no guessing"). All optional on ProviderProfile — the three live
 *    profiles predate them and must keep validating. ── */

/**
 * How the TOKEN endpoint authenticates the client — SPEC §1's single most consequential
 * axis, the one that decides custody class. Distinct from `TokenAuth`, which is the wire
 * encoding the exchange already speaks: `none`+`pkce:S256` is Class A; anything else needs
 * a secret and selects a B/C path.
 */
export type ClientAuth = 'none' | 'secret_post' | 'secret_basic' | 'private_key_jwt' | 'mtls' | 'unknown';
/** Whether endpoints can be fetched from `.well-known` instead of hand-configured (§1). */
export type Discovery = 'rfc8414' | 'oidc' | 'none' | 'unknown';
/** RFC 7591 dynamic client registration — unlocks Custody Class C (§1). */
export type Dcr = 'rfc7591' | 'none' | 'unknown';
/** RFC 9126 pushed authorization requests (§1). */
export type Par = 'rfc9126' | 'none' | 'unknown';
/** How each subsequent API call is bound: bearer, DPoP (RFC 9449), or mTLS (§1). */
export type SenderConstraint = 'bearer' | 'dpop' | 'mtls' | 'unknown';
/** RFC 8628 device authorization grant — the no-browser/no-loopback fallback (§1, §3). */
export type DeviceFlow = 'rfc8628' | 'none' | 'unknown';
/** Whether granted scopes may differ from requested; `incremental` enables step-up (§1, §9). */
export type ScopeGrant = 'exact' | 'downgradeable' | 'incremental' | 'unknown';
/** Whether disconnect can revoke upstream (RFC 7009 / proprietary) or only forget (§1, §6). */
export type Revocation = 'rfc7009' | 'proprietary' | 'none' | 'unknown';

/**
 * DERIVED, never hand-authored — the custody rung, computed from the measured profile
 * (§4, §5b): A public · B1 user's-own-secret · B2a relay-signs-never-sees-token ·
 * B2b relay-exchanges-once-encrypted · C self-registered. Displayed at connect time.
 */
export type CustodyClass = 'A' | 'B1' | 'B2a' | 'B2b' | 'C' | 'unknown';
/** DERIVED custody sub-mode when a relay is involved (§5b). */
export type RelayMode = 'none' | 'assertion_signing' | 'exchange_forwarding' | 'unknown';

export type RedirectStrategy = 'loopback' | 'hosts-alias' | 'relay' | 'scheme';

/**
 * How the *code exchange* authenticates. Reddit = HTTP Basic with an empty password.
 * `secret_basic`/`secret_post` are the confidential (B1) client-secret methods; `basic` is
 * retained as a back-compat alias for `secret_basic`. All three route through byos.ts.
 */
export type TokenAuth =
  | 'none'
  | 'basic_empty_password'
  | 'basic'
  | 'secret_basic'
  | 'secret_post'
  | 'body';

/**
 * How a *refresh* authenticates — a separate axis from `token_auth` on purpose.
 * Slack's public-client refresh auth is genuinely undocumented (§A10, open unknown U1),
 * so `unknown` is a first-class value and the mock AS implements all three plausible modes.
 * Collapsing this into `token_auth` would hard-code the ambiguity into exchange.ts.
 */
export type RefreshAuth =
  | 'client_id_body'
  | 'basic_empty_password'
  | 'basic'
  | 'secret_basic'
  | 'secret_post'
  | 'none'
  | 'unknown';

/** Slack asks for user scopes under `user_scope`, not `scope`. */
export type ScopeParam = 'scope' | 'user_scope';

/** Whether the provider rotates refresh tokens, and whether we chose it (§A1). */
export type RotationMode = 'forced' | 'optional-enabled' | 'optional-off' | 'none';

export type RefreshModel = 'rotation' | 'long_lived' | 'none';

/**
 * ONE encoding for "did this 200 actually succeed?", across all providers (§A16).
 *
 * `null`/absent = the HTTP status is the whole verdict (Zoom, Reddit). A predicate object
 * = the body must also agree (Slack's `{"ok": false}` inside an HTTP 200). Deliberately
 * NOT a JS expression string and NOT an enum token: the engine evaluates `path`/`equals`,
 * and anything it cannot evaluate is a config bug the schema catches, never an `eval`.
 */
export type SuccessPredicate = { path: string; equals: string | number | boolean } | null;

/**
 * "connected" is produced by this probe, never by an HTTP 200 — a token endpoint
 * returning 200 with `{"ok": false}` is a known provider specialty.
 *
 * Field set reconciled across representative providers (§A16): early profiles
 * had invented `display_name_path`, `account_id_path`, `display_prefix`, `auth` and
 * `requires_scope` against a four-field type. All five are real needs, so they are typed
 * here rather than deleted — but there is exactly one spelling of each.
 */
export interface IdentityProbe {
  /** Absolute HTTPS URL, e.g. https://slack.com/api/auth.test */
  url: string;
  method?: 'GET' | 'POST';
  /** Dotted path to the handle inside the JSON response, e.g. `user`. */
  handle_path: string;
  /** Rendered in front of the handle, e.g. Reddit's `/u/`. Display only. */
  handle_prefix?: string;
  /** Dotted path to the workspace/tenant label, e.g. `team`. Optional. */
  workspace_path?: string;
  /** Dotted path to the provider's opaque account id, e.g. Slack `user_id`. */
  account_id_path?: string;
  /** How the probe authenticates. Default `bearer`. */
  auth?: 'bearer' | 'none';
  /** Scope without which the probe cannot run (Zoom `user:read:user`) — documentation. */
  requires_scope?: string;
  /** Body-level success test, same encoding as the token endpoint's. */
  success_predicate?: SuccessPredicate;
}

/**
 * Superset of the three providers' real rate-limit shapes (§A16). Every field optional:
 * Slack publishes a per-minute number, Zoom a tier + per-second + per-day, Reddit a
 * per-minute number plus live budget headers. One type, no per-provider branch.
 */
export interface RateLimit {
  requests_per_minute?: number;
  per_second?: number;
  per_day?: number;
  /** Provider's own tier label, e.g. Zoom `light`. */
  tier?: string;
  /** Response headers carrying the live budget, e.g. Reddit's `X-Ratelimit-*`. */
  headers?: Record<string, string>;
  /** Free-text provider rule we must not violate (e.g. Reddit's UA policy). */
  note?: string;
}

/**
 * The committed, PUBLIC per-provider config. File name is `provider.json` (§A4), and the
 * machine-readable copy of this interface is `provider.schema.json` at the repo root.
 * The two are the twin sources of truth for a provider profile: validate every provider.json
 * against the schema, and assign the parsed object to this interface for the compile-time check.
 *
 * Keys beginning with `_` (`_notes`, `_doc`, `_placeholders`) and `$schema` are metadata:
 * ignored by the engine, allowed by the schema, never read at runtime.
 */
export interface ProviderProfile {
  /** JSON-Schema pointer for editors. Metadata only. */
  $schema?: string;
  /** Provider-profile schema version. v1 today. */
  schema_version?: number;

  /** Stable key used by getToken()/disconnect() and as the vault account name. */
  name: string;
  /** Display name rendered in the branded callback page and spoken copy. */
  display_name: string;

  authorize_url: string;
  token_url: string;
  /** Optional: upstream revocation endpoint. `disconnect()` calls it when present (§A16). */
  revoke_url?: string;
  /** Optional: API host for tools + identity probe, e.g. Reddit `https://oauth.reddit.com`. */
  api_base?: string;
  /** Public client id. The only value the integration author pastes. Never a secret. */
  client_id: string;

  client_type: ClientType;
  pkce: PkceMode;

  /* ── Capability dimensions (SPEC §1). Optional: absent = not-yet-measured, and the three
   *    live profiles omit them. A probe (C-1) fills them in; `unknown` = measured-but-unclassified. ── */
  /** How the token endpoint authenticates the client — the axis that decides custody (§1). */
  client_auth?: ClientAuth;
  /** Whether endpoints can be fetched from `.well-known` (RFC 8414 / OIDC) vs hand-configured (§1). */
  discovery?: Discovery;
  /** RFC 7591 dynamic client registration — unlocks Custody Class C (§1). */
  dcr?: Dcr;
  /**
   * RFC 7591 registration endpoint (the `registration_endpoint` from RFC 8414 metadata). Required
   * to self-register when `dcr: 'rfc7591'`; the engine POSTs client metadata here and stores the
   * returned credentials on-device (Custody Class C, §4). Never a secret. (C-8)
   */
  registration_url?: string;
  /** RFC 9126 pushed authorization requests (§1). */
  par?: Par;
  /** How each subsequent API call is bound: bearer / DPoP / mTLS (§1). */
  sender_constraint?: SenderConstraint;
  /** RFC 8628 device authorization grant — the no-browser/no-loopback fallback (§1, §3). */
  device_flow?: DeviceFlow;
  /**
   * RFC 8628 §3.1 device authorization endpoint. Required to select the device grant path: the
   * engine POSTs client_id + scope here and receives the user_code + verification_uri to show.
   * Never a secret; only meaningful when `device_flow: 'rfc8628'`. (C-17)
   */
  device_authorization_url?: string;
  /** Whether granted scopes may differ from requested; `incremental` enables step-up (§1, §9). */
  scope_grant?: ScopeGrant;
  /** Whether disconnect can revoke upstream or only forget locally (§1, §6). */
  revocation?: Revocation;

  /** DERIVED, never hand-authored: the custody rung this provider lands on (§4, §5b). */
  custody_class?: CustodyClass;
  /** DERIVED custody sub-mode when a relay is involved (§5b). */
  relay_mode?: RelayMode;

  redirect_strategy: RedirectStrategy;
  /** Always `localhost` for loopback providers — the sole source is engine/src/config.ts. */
  redirect_host: string;
  /** Ports registered with the provider, in ladder order. Reddit's has length 1. */
  redirect_ports: number[];
  /** Required iff `redirect_strategy === 'relay'` — where the static bounce page lives (§A16). */
  relay_url?: string;

  scopes: string[];
  scope_param: ScopeParam;
  /** Separator when scopes are serialized. Default `' '` (percent-encoded `%20`, never `+`). */
  scope_delimiter?: string;

  token_auth: TokenAuth;
  refresh_auth: RefreshAuth;

  /** e.g. Reddit `{ duration: 'permanent' }` — without it there is no refresh token at all. */
  extra_authorize_params?: Record<string, string>;
  /**
   * Headers sent on EVERY request to this provider, token exchange included — Reddit's
   * mandatory User-Agent lives here and nowhere else (§A16).
   */
  static_headers?: Record<string, string>;
  /** Headers added to the token endpoint only, for genuinely exchange-scoped headers. */
  token_endpoint_extra_headers?: Record<string, string>;

  /** Dotted path to the access token, e.g. Slack `authed_user.access_token`. */
  token_path: string;
  /** Dotted path to the refresh token when it is not top-level (Slack nests it). */
  refresh_token_path?: string;
  /** Dotted path to `expires_in` when it is not top-level (Slack nests it). */
  expires_in_path?: string;
  /** Body-level success test. `null`/absent = the HTTP status is the whole verdict. */
  success_predicate?: SuccessPredicate;

  refresh: RefreshModel;
  rotation: RotationMode;
  /** Seconds. Slack under rotation = 43200. */
  access_token_ttl?: number;
  /** Seconds, or `null` where the provider documents no expiry (Reddit). */
  refresh_ttl?: number | null;

  rate_limit?: RateLimit;
  identity_probe: IdentityProbe;

  /** Brand mark data URI for the loopback callback pages. Cosmetic only; never fetched. */
  brand_icon?: string;

  /** Derived, never hand-written: a code may transit the relay only if PKCE protects it. */
  relay_eligible?: boolean;

  /** RFC 9207 issuer identifier. When set, the callback's `iss` MUST equal it (mix-up defense, C-3). */
  issuer?: string;
  /** Provider metadata authorization_response_iss_parameter_supported: it always returns `iss` (C-3). */
  authorization_response_iss_parameter_supported?: boolean;

  /** Human notes kept next to the values they explain. Never read at runtime. */
  _notes?: Record<string, string>;
  _doc?: string;
  /** Tokens a Phase-0 file may still contain, e.g. `__REDDIT_USERNAME__` (§A16). */
  _placeholders?: string[];
}

/* ────────────────────────────────── Token records ────────────────────────────────── */

/**
 * What the vault stores, per provider. Rotated refresh token + absolute expiry are written
 * from the FIRST write, never retrofitted later.
 * A value from this record may never reach `console.*` or an Error message.
 */
export interface TokenRecord {
  provider: string;
  access_token: string;
  refresh_token?: string;
  /** Epoch ms. Absolute, computed at write time from `expires_in`. */
  expires_at?: number;
  scopes: string[];
  /** Identity resolved by the probe — safe to display, never a credential. */
  identity?: { handle: string; workspace?: string };
  /** Epoch ms of the write that produced this record. */
  obtained_at: number;
}

/* ─────────────────────────── Product-surface status contract ─────────────────────────── */

export type ConnectPhase =
  | 'idle'
  | 'launching-browser'
  | 'awaiting-consent'
  | 'exchanging'
  | 'connected'
  | 'error';

export type ConnectErrorCode =
  | 'denied_by_user'
  | 'port_blocked'
  | 'expired_or_revoked'
  | 'state_mismatch'
  | 'timeout'
  | 'provider_error';

export interface ConnectStatus {
  phase: ConnectPhase;
  connect_id: string;
  provider: string;
  /** From the frozen copy deck. Never generated — no LLM in any live path. */
  spoken: string;
  /** Set only after the identity probe succeeds. */
  identity?: { handle: string; workspace?: string };
  /**
   * RFC 8628 (C-17) — the code + URL the user enters on another device, present during the
   * `awaiting-consent` phase of a device-grant connect. NEVER carries the `device_code`, which is
   * the secret the engine polls with; only the human-facing `user_code` and verification URL.
   */
  device?: {
    user_code: string;
    verification_uri: string;
    /** Prefilled URL (user_code embedded) when the provider offers one, for a QR/one-tap path. */
    verification_uri_complete?: string;
    /** Epoch ms after which the user_code stops working and the connect fails as expired. */
    expires_at: number;
  };
  error?: {
    code: ConnectErrorCode;
    hint: string;
    /** The provider's own error string, verbatim. Never our paraphrase. */
    provider_message?: string;
  };
}

/**
 * Every engine failure maps to one of these. The `ConnectErrorCode` half is what the
 * product surface renders; the rest are internal faults that must still never be a
 * bare string thrown from a random module.
 */
export type EngineErrorCode =
  | ConnectErrorCode
  | 'not_implemented'
  | 'config_invalid'
  | 'vault_unavailable'
  | 'refresh_failed'
  | 'not_connected';
