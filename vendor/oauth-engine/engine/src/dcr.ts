/**
 * Custody Class C — RFC 7591 dynamic client registration. Closes C-8.
 *
 * Every honest OAuth story has one step no library can automate away: a provider must be told
 * which application is asking, which means a client registered in a developer console
 * (SPEC §19). Composio prepaid that clicking for a fixed catalog; Class A/B1 ship a pasted
 * client id. RFC 7591 is the one path where NOBODY registers: the provider exposes a
 * registration endpoint, the engine self-registers a client on the fly — per user, per
 * device — and the resulting credentials live on the device (SPEC §4 Class C, §24: "the MCP
 * authorization spec builds on DCR"). A dcr-capable provider therefore needs no pre-registered
 * client_id at all; this module mints one.
 *
 * Two custody properties hold here, and both have tests:
 *
 *   1. The registered credentials never leave the device. They are minted into the macOS
 *      Keychain with the exact transport `vault.ts`/`byos.ts` proved out — the secret (a DCR
 *      client_secret, when the provider issues one) rides `security -i` on STDIN as `-X <hex>`,
 *      never argv (invisible to `ps`), never shell-interpolated (`spawn` with an argv array, no
 *      shell), never written to disk as a file, and write-then-verified so a silent Keychain
 *      failure cannot masquerade as a real one.
 *   2. A returned client_secret is registered with `redact()` by the caller before any provider
 *      response is turned into a string, and this module never logs it and never throws with it
 *      in the message — the same boundary the token vault holds.
 *
 * Storage layout: service `com.voiceos.dcr.<provider>`, account `voiceos-dcr`, value = a
 * single-line pure-ASCII JSON {@link RegisteredClient}. Distinct from the token vault
 * (`com.voiceos.connect.<provider>`) and the B1 store (`com.voiceos.byoc.<provider>`) so the
 * three never collide, and destroyed independently by {@link deleteRegisteredClient} at
 * disconnect.
 *
 * The engine self-registers a PUBLIC client (`token_endpoint_auth_method: "none"`) wherever the
 * provider supports PKCE: that keeps custody fully on-device (the credential is a client_id, not
 * a secret) and reuses the Class A exchange path with zero new exchange code. A provider that
 * insists on issuing a client_secret still has it vaulted here on-device, and it is mirrored into
 * the B1 store so the confidential exchange path (byos.applyConfidentialAuth) authenticates with
 * it — no per-provider branch, the routing is a capability value.
 */

import { storeClientCredentials } from './byos.ts';
import { defaultRunner, type ByosOptions, type RunResult, type SecurityRunner } from './byos.ts';
import { EngineError } from './errors.ts';
import type { ProviderProfile } from './types.ts';

/** Account label for the Class C credential items. Distinct from the vault's and B1's. */
export const DCR_ACCOUNT = 'voiceos-dcr';

/** Shown in Keychain Access. No spaces: it is a token in the `security -i` command stream. */
const KIND = 'VoiceOS-Connect-DCR-client';

/** `security`'s exit code for "the item is not there." Not an error for us. */
const ERR_ITEM_NOT_FOUND = 44;

/** Built from an ASCII source string on purpose: this file stays copy-pasteable everywhere. */
const NON_ASCII = new RegExp('[\\u0080-\\uFFFF]', 'g');

/** A registration endpoint that has not answered in this long is a hung flow, not a slow net. */
const REGISTER_TIMEOUT_MS = 20_000;

/**
 * What a provider hands back from an RFC 7591 registration, kept verbatim on the device.
 *
 * `client_id` is the only guaranteed field. `client_secret` appears only when the provider
 * registered a confidential client; when it is absent the registered client is public and
 * custody is a pure client-id-on-device story. The registration-management fields
 * (`registration_access_token`, `registration_client_uri`) let a future engine update or delete
 * the registration upstream (RFC 7591 §3, RFC 7592); they are stored so that capability is not
 * lost, and the access token is treated as a secret.
 */
export interface RegisteredClient {
  client_id: string;
  client_secret?: string;
  /** Epoch seconds when the secret expires. `0` = never (RFC 7591 §3.2.1). */
  client_secret_expires_at?: number;
  /** RFC 7592 registration-management credential — a secret. */
  registration_access_token?: string;
  /** RFC 7592 registration-management endpoint for this client. */
  registration_client_uri?: string;
  /** The redirect_uris this client was registered with — used to detect a stale registration. */
  redirect_uris?: string[];
}

/** The secret-shaped fields of a {@link RegisteredClient}, for the caller's `redact()` list. */
export function secretsOf(client: RegisteredClient): string[] {
  const out: string[] = [];
  if (client.client_secret !== undefined && client.client_secret !== '') out.push(client.client_secret);
  if (client.registration_access_token !== undefined && client.registration_access_token !== '') {
    out.push(client.registration_access_token);
  }
  return out;
}

/* ─────────────────────────────────── key derivation ─────────────────────────────────── */

/** The Keychain service for a provider's Class C credentials. Validates the provider name first. */
export function dcrService(provider: string): string {
  if (!/^[a-z0-9][a-z0-9._-]*$/i.test(provider)) {
    throw new EngineError('config_invalid', 'provider name is not a legal vault key', {
      hint: `Provider names are [A-Za-z0-9._-]; got ${JSON.stringify(provider)}.`,
    });
  }
  return `com.voiceos.dcr.${provider}`;
}

function isNotFound(result: RunResult): boolean {
  return result.code === ERR_ITEM_NOT_FOUND || /could not be found/i.test(result.stderr);
}

function firstLine(text: string): string {
  return text.split('\n')[0]?.trim() ?? '';
}

/**
 * Single-line, pure-ASCII JSON — both properties load-bearing for the stdin transport, so this
 * mirrors the vault's serializer exactly. A raw newline in the payload would be reinterpreted as
 * a second `security -i` command; JSON.stringify escapes newlines, and the tripwire below refuses
 * anything that slips through.
 */
function serialize(client: RegisteredClient): string {
  const json = JSON.stringify(client).replace(
    NON_ASCII,
    (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`,
  );
  if (/[\r\n]/.test(json)) {
    throw new EngineError('config_invalid', 'refusing to store a multi-line DCR credential', {
      hint: 'The Keychain command stream is newline-delimited; a credential containing a raw newline would be reinterpreted as a command.',
    });
  }
  return json;
}

/* ─────────────────────────────────────── write ─────────────────────────────────────── */

/**
 * Store (or replace) the self-registered client for `provider` on-device. Delete-then-add
 * (idempotent) mirrors the token vault and B1 store.
 *
 * @throws EngineError `config_invalid` when `client_id` is empty.
 * @throws EngineError `vault_unavailable` when the Keychain refuses the write or the write does
 *         not survive a read-back.
 */
export async function storeRegisteredClient(
  provider: string,
  client: RegisteredClient,
  options: ByosOptions = {},
): Promise<void> {
  const runner: SecurityRunner = options.runner ?? defaultRunner;
  const service = dcrService(provider);

  if (typeof client.client_id !== 'string' || client.client_id.trim() === '') {
    throw new EngineError('config_invalid', 'a self-registered client needs a non-empty client_id', {
      hint: `RFC 7591 registration for ${provider} returned no client_id.`,
    });
  }

  const payload = serialize(client);
  const hex = Buffer.from(payload, 'utf8').toString('hex');

  await deleteRegisteredClient(provider, options);

  // argv is `['-i']` — the command (secret hex included) rides stdin, invisible to `ps`.
  const result = await runner(
    ['-i'],
    `add-generic-password -a ${DCR_ACCOUNT} -s ${service} -D ${KIND} -X ${hex}\n`,
  );
  if (result.code !== 0) {
    // stderr is echoed only via firstLine (security's own diagnostic); our payload went on
    // stdin, so this cannot leak a secret.
    throw new EngineError('vault_unavailable', 'the Keychain refused the DCR credential write', {
      hint: `security add-generic-password exited ${result.code} for ${service}. ${firstLine(result.stderr)}`,
    });
  }

  const readBack = await readRegisteredClient(provider, options);
  if (readBack === null || readBack.client_id !== client.client_id) {
    throw new EngineError('vault_unavailable', 'the DCR credential write did not survive a read-back', {
      hint: `Wrote ${service} and read back ${readBack === null ? 'nothing' : 'a different record'}. Nothing is cached on disk, so the safe state is unregistered.`,
    });
  }
}

/* ─────────────────────────────────────── read ─────────────────────────────────────── */

/**
 * THE ONLY read path for a stored Class C credential.
 *
 * @returns the stored client, or `null` when this provider has no self-registered client yet.
 */
export async function readRegisteredClient(
  provider: string,
  options: ByosOptions = {},
): Promise<RegisteredClient | null> {
  const runner: SecurityRunner = options.runner ?? defaultRunner;
  const service = dcrService(provider);

  const result = await runner(['find-generic-password', '-a', DCR_ACCOUNT, '-s', service, '-w']);
  if (result.code !== 0) {
    if (isNotFound(result)) return null;
    throw new EngineError('vault_unavailable', 'the Keychain refused the DCR credential read', {
      hint: `security find-generic-password exited ${result.code} for ${service}. ${firstLine(result.stderr)}`,
    });
  }

  const raw = result.stdout.trim();
  if (raw === '') return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // The stored bytes are NEVER echoed into the error: they may hold a secret.
    throw new EngineError('vault_unavailable', 'the vaulted DCR credential is not valid JSON', {
      hint: `Keychain item ${service} holds ${raw.length} bytes that do not parse. Re-run the ${provider} connect to re-register.`,
    });
  }

  if (parsed === null || typeof parsed !== 'object') return null;
  const record = parsed as Partial<RegisteredClient>;
  if (typeof record.client_id !== 'string' || record.client_id === '') return null;
  return record as RegisteredClient;
}

/* ────────────────────────────────────── delete ────────────────────────────────────── */

/**
 * Destroy the self-registered client for `provider`. Idempotent, so a disconnect that removes the
 * token, the B1 secret and this record never fails on a missing one.
 */
export async function deleteRegisteredClient(
  provider: string,
  options: ByosOptions = {},
): Promise<void> {
  const runner: SecurityRunner = options.runner ?? defaultRunner;
  const service = dcrService(provider);
  const result = await runner(['delete-generic-password', '-a', DCR_ACCOUNT, '-s', service]);
  if (result.code === 0 || isNotFound(result)) return;
  throw new EngineError('vault_unavailable', 'the Keychain refused the DCR credential delete', {
    hint: `security delete-generic-password exited ${result.code} for ${service}. ${firstLine(result.stderr)}`,
  });
}

/* ──────────────────────────────── the registration call ──────────────────────────────── */

/** Injected in tests; production uses the platform `fetch`. */
export interface DcrHttpOptions {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export interface RegisterInput {
  /** Every redirect URI the loopback might bind, so any bound port matches this client (§7). */
  redirectUris: string[];
  http?: DcrHttpOptions;
}

/**
 * The RFC 7591 client-metadata request body, derived entirely from the measured profile — no
 * provider branch. A public client is requested wherever PKCE is available (custody stays fully
 * on-device); `refresh_token` is asked for only when the profile issues refresh tokens.
 */
function registrationBody(profile: ProviderProfile, redirectUris: string[]): Record<string, unknown> {
  const grantTypes = ['authorization_code'];
  if (profile.refresh !== 'none') grantTypes.push('refresh_token');
  return {
    redirect_uris: redirectUris,
    token_endpoint_auth_method: profile.pkce === 'S256' ? 'none' : 'client_secret_post',
    grant_types: grantTypes,
    response_types: ['code'],
    client_name: profile.display_name,
    scope: profile.scopes.join(' '),
  };
}

function coerceClient(payload: unknown, redirectUris: string[]): RegisteredClient {
  if (payload === null || typeof payload !== 'object') {
    throw new EngineError('provider_error', 'the registration endpoint returned a non-object body', {
      hint: 'RFC 7591 requires a JSON object with at least a client_id.',
    });
  }
  const record = payload as Record<string, unknown>;
  const clientId = record.client_id;
  if (typeof clientId !== 'string' || clientId === '') {
    throw new EngineError('provider_error', 'the registration endpoint returned no client_id', {
      hint: 'RFC 7591 §3.2.1 requires a client_id in a successful registration response.',
    });
  }
  const client: RegisteredClient = { client_id: clientId, redirect_uris: redirectUris };
  if (typeof record.client_secret === 'string' && record.client_secret !== '') {
    client.client_secret = record.client_secret;
  }
  if (typeof record.client_secret_expires_at === 'number') {
    client.client_secret_expires_at = record.client_secret_expires_at;
  }
  if (typeof record.registration_access_token === 'string' && record.registration_access_token !== '') {
    client.registration_access_token = record.registration_access_token;
  }
  if (typeof record.registration_client_uri === 'string' && record.registration_client_uri !== '') {
    client.registration_client_uri = record.registration_client_uri;
  }
  return client;
}

/**
 * Self-register a client with `provider` per RFC 7591 and return the credentials. Performs one
 * HTTPS round trip to `profile.registration_url`; stores nothing (the caller decides custody).
 *
 * @throws EngineError `config_invalid` when the profile is not dcr-capable or names no
 *         registration endpoint.
 * @throws EngineError `provider_error` when the endpoint is unreachable, answers non-2xx, or
 *         returns a body that is not a valid registration.
 */
export async function registerClient(
  profile: ProviderProfile,
  input: RegisterInput,
): Promise<RegisteredClient> {
  if (profile.dcr !== 'rfc7591') {
    throw new EngineError('config_invalid', `${profile.name} is not marked dcr: 'rfc7591'`, {
      hint: 'Only a provider whose measured profile reports RFC 7591 dynamic client registration self-registers.',
    });
  }
  const endpoint = profile.registration_url;
  if (typeof endpoint !== 'string' || endpoint === '') {
    throw new EngineError('config_invalid', `${profile.name} has dcr: 'rfc7591' but no registration_url`, {
      hint: 'The measured profile must carry the registration_endpoint (RFC 8414 metadata) as registration_url before the engine can self-register.',
    });
  }
  if (input.redirectUris.length === 0) {
    throw new EngineError('config_invalid', 'DCR needs at least one redirect_uri to register', {
      hint: 'Pass the loopback redirect URIs the connect flow will use.',
    });
  }

  const http = input.http ?? {};
  const doFetch = http.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), http.timeoutMs ?? REGISTER_TIMEOUT_MS);

  let response: Response;
  try {
    response = await doFetch(endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
        ...(profile.static_headers ?? {}),
      },
      body: JSON.stringify(registrationBody(profile, input.redirectUris)),
      signal: controller.signal,
      redirect: 'error',
    });
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : 'network failure';
    throw new EngineError('provider_error', 'could not reach the registration endpoint', {
      hint: `POST ${endpoint} failed: ${detail}`,
      cause,
    });
  } finally {
    clearTimeout(timer);
  }

  const text = await response.text();
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    // The body is NOT echoed: a non-JSON registration response is exactly the case where an
    // error page (or a proxy dump) could carry credential material.
    throw new EngineError('provider_error', 'the registration endpoint returned a non-JSON body', {
      hint: `HTTP ${response.status} from ${endpoint}, ${text.length} bytes that are not JSON.`,
    });
  }

  // RFC 7591 §3.2.1: success is 201 Created; some servers answer 200. Anything else is a refusal.
  if (response.status !== 201 && response.status !== 200) {
    const record = payload as Record<string, unknown> | null;
    const providerError =
      record !== null && typeof record.error === 'string' ? record.error : undefined;
    throw new EngineError('provider_error', `${profile.name} refused the client registration`, {
      hint: `HTTP ${response.status} from ${endpoint}.`,
      ...(providerError === undefined ? {} : { providerMessage: providerError }),
    });
  }

  return coerceClient(payload, input.redirectUris);
}

/* ─────────────────────────── the connect-facing entry points ─────────────────────────── */

/**
 * Return a usable self-registered client for `profile`, registering one on first use.
 *
 * Cache-or-register: a stored record whose secret has not expired and that already covers every
 * requested redirect URI is reused (no network); otherwise the engine registers a fresh client,
 * stores it on-device, and — when the provider issued a client_secret — mirrors the credentials
 * into the B1 store so the confidential exchange path authenticates with them. This is what makes
 * a dcr-capable provider need no pre-registered client_id.
 */
export async function ensureRegisteredClient(
  profile: ProviderProfile,
  input: RegisterInput & { runner?: SecurityRunner },
): Promise<RegisteredClient> {
  const runnerOptions: ByosOptions = input.runner === undefined ? {} : { runner: input.runner };

  const cached = await readRegisteredClient(profile.name, runnerOptions);
  if (cached !== null && isReusable(cached, input.redirectUris)) return cached;

  const client = await registerClient(profile, input);
  await storeRegisteredClient(profile.name, client, runnerOptions);

  // A registered secret must reach the confidential exchange path. Mirror it into the B1 store so
  // byos.applyConfidentialAuth can read it — the routing is the token_auth capability value the
  // effective profile sets (see applyRegisteredClient), never a provider branch.
  if (client.client_secret !== undefined && client.client_secret !== '') {
    await storeClientCredentials(
      profile.name,
      { client_id: client.client_id, client_secret: client.client_secret },
      runnerOptions,
    );
  }

  return client;
}

/** A stored client is reusable iff its secret has not expired and it covers every needed URI. */
function isReusable(client: RegisteredClient, redirectUris: string[]): boolean {
  const expiry = client.client_secret_expires_at;
  // 0 (or absent) = never expires; a positive value is epoch SECONDS.
  if (typeof expiry === 'number' && expiry > 0 && expiry * 1000 <= Date.now()) return false;
  const covered = new Set(client.redirect_uris ?? []);
  return redirectUris.every((uri) => covered.has(uri));
}

/**
 * The effective profile the authorize/exchange path runs against once a client is registered —
 * the frozen public API is untouched; this is what threads the self-minted client_id through.
 *
 * When the provider issued a secret, the effective profile flips to the confidential wire modes
 * (`secret_post`), so exchange.ts routes through byos.applyConfidentialAuth to the mirrored
 * credentials. When it did not, the profile is public and the Class A exchange path is unchanged.
 */
export function applyRegisteredClient(
  profile: ProviderProfile,
  client: RegisteredClient,
): ProviderProfile {
  const base: ProviderProfile = { ...profile, client_id: client.client_id };
  if (client.client_secret !== undefined && client.client_secret !== '') {
    return {
      ...base,
      client_type: 'confidential',
      token_auth: 'secret_post',
      refresh_auth: 'secret_post',
    };
  }
  return base;
}
