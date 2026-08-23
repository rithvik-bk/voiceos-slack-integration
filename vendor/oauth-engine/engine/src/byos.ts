/**
 * B1 — bring-your-own confidential client (SPEC Part 2 §4, custody class B1). Closes C-5.
 *
 * The engine was born architecturally incapable of holding a client secret: exchange.ts
 * rejects `token_auth: 'basic'` loudly, on purpose, because a secret baked into a shipped
 * public config leaks to every user (SPEC §4). B1 is the honest way to unblock the
 * confidential providers people actually want (Slack, Notion): the *user* registers their
 * OWN app with the provider, and THEIR secret lives in THEIR keychain. Nothing is
 * distributed, nothing is shared — "custody is perfect" (SPEC §4). The cost is a
 * five-minute, once-per-provider setup wizard that calls {@link storeClientCredentials}.
 *
 * This module owns three things and nothing else:
 *   1. Custody of the user's `client_id` + `client_secret` in the macOS Keychain — same
 *      transport discipline the token vault proved out (see the header of `vault.ts`):
 *        - the secret is NEVER a command-line argument (`security add-generic-password -w
 *          <value>` puts it in the process table for any `ps` to read). The write rides
 *          `security -i`, which reads its command from stdin; the payload travels as
 *          `-X <hex>`, and hex has no quotes/spaces/backslashes for the tokenizer to eat.
 *        - the secret is NEVER shell-interpolated: `spawn` with an argv ARRAY, no shell.
 *        - the secret is NEVER written to disk as a file — Keychain only, no fallback.
 *        - write-then-verify, because a silently-failed Keychain write and a real one look
 *          identical to the caller until it matters.
 *   2. A single read path — {@link readClientCredentials} — so the invariant the tests pin
 *      is literally true: the secret is only ever obtained by reading the Keychain.
 *   3. {@link applyConfidentialAuth}, the helper exchange.ts calls to authenticate a
 *      confidential token/refresh request. It reads the vaulted credentials, applies either
 *      `client_secret_post` (RFC 6749 §2.3.1, secret in the body) or `client_secret_basic`
 *      (secret in an Authorization header), and RETURNS the secret so the caller can hand it
 *      to `redact()` — the secret is scrubbed from any surfaced string, never logged.
 *
 * Custody boundary (the property the tests enforce): a value returned by
 * {@link readClientCredentials}/{@link applyConfidentialAuth} may never reach `console.*`,
 * an Error `message`/`hint`, argv, or a file. The only place it exists at rest is the
 * Keychain item this module writes.
 *
 * Storage layout: service `com.voiceos.byoc.<provider>`, account `voiceos-byoc`, value = a
 * single-line pure-ASCII JSON `{ "client_id": ..., "client_secret": ... }`. Distinct from
 * the token vault's `com.voiceos.connect.<provider>` so the two never collide, and destroyed
 * independently by {@link deleteClientCredentials} at disconnect.
 */

import { spawn } from 'node:child_process';

import { EngineError } from './errors.ts';

const SECURITY = '/usr/bin/security';

/** Account label for the B1 credential items. Distinct from the token vault's `voiceos`. */
export const BYOC_ACCOUNT = 'voiceos-byoc';

/** Shown in Keychain Access. No spaces: it is a token in the `security -i` command stream. */
const KIND = 'VoiceOS-Connect-BYOC-client';

/** `security`'s exit code for "the item is not there." Not an error for us. */
const ERR_ITEM_NOT_FOUND = 44;

/** Built from an ASCII source string on purpose: this file stays copy-pasteable everywhere. */
const NON_ASCII = new RegExp('[\\u0080-\\uFFFF]', 'g');

/**
 * The two RFC 6749 confidential client-authentication methods B1 supports.
 *
 *   `secret_post`  — client_secret_basic's sibling: `client_id` + `client_secret` in the
 *                    form body (RFC 6749 §2.3.1, the `client_secret_post` variant).
 *   `secret_basic` — HTTP Basic `Authorization: Basic base64(client_id:client_secret)`.
 *
 * The engine's legacy `token_auth: 'basic'` value means exactly `secret_basic` and is
 * accepted as an alias by {@link isConfidentialAuth}/{@link applyConfidentialAuth}, so no
 * shipped profile has to be rewritten for the router to reach this module.
 */
export type ConfidentialAuthMode = 'secret_post' | 'secret_basic';

/** The user's own registered app credentials for one provider. */
export interface ClientCredentials {
  client_id: string;
  client_secret: string;
}

/**
 * Run `security` with an argv array and an optional stdin payload — the exact seam the token
 * vault uses. Injectable so custody tests can inspect argv/stdin without touching the real
 * Keychain; production always uses the platform `spawn`.
 */
export interface SecurityRunner {
  (args: readonly string[], stdin?: string): Promise<RunResult>;
}

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface ByosOptions {
  /** Injected in tests; production always uses {@link defaultRunner}. */
  runner?: SecurityRunner;
}

/**
 * The production runner: `spawn` with no shell, payload on stdin. Never `shell: true` — the
 * payload contains a user-controlled secret, and a shell in this path turns it into a
 * command.
 */
export const defaultRunner: SecurityRunner = (args, stdin) =>
  new Promise((resolve, reject) => {
    const child = spawn(SECURITY, [...args], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk: string) => {
      stderr += chunk;
    });
    child.once('error', (error) => {
      reject(
        new EngineError('vault_unavailable', 'could not run the macOS Keychain helper', {
          hint: `${SECURITY} failed to start. B1 stores the client secret only in the Keychain; there is no file fallback by design.`,
          cause: error,
        }),
      );
    });
    child.once('close', (code) => resolve({ code: code ?? -1, stdout, stderr }));
    if (stdin !== undefined) child.stdin.end(stdin);
    else child.stdin.end();
  });

/* ─────────────────────────────────── key derivation ─────────────────────────────────── */

/** The Keychain service for a provider's B1 credentials. Validates the provider name first. */
export function byocService(provider: string): string {
  if (!/^[a-z0-9][a-z0-9._-]*$/i.test(provider)) {
    throw new EngineError('config_invalid', 'provider name is not a legal vault key', {
      hint: `Provider names are [A-Za-z0-9._-]; got ${JSON.stringify(provider)}.`,
    });
  }
  return `com.voiceos.byoc.${provider}`;
}

function isNotFound(result: RunResult): boolean {
  return result.code === ERR_ITEM_NOT_FOUND || /could not be found/i.test(result.stderr);
}

function firstLine(text: string): string {
  return text.split('\n')[0]?.trim() ?? '';
}

/**
 * Single-line, pure-ASCII JSON — both properties load-bearing for the stdin transport, so
 * this mirrors the vault's serializer exactly.
 */
function serialize(creds: ClientCredentials): string {
  const json = JSON.stringify({
    client_id: creds.client_id,
    client_secret: creds.client_secret,
  }).replace(
    NON_ASCII,
    (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`,
  );
  if (/[\r\n]/.test(json)) {
    // Unreachable via JSON.stringify (it escapes newlines) — kept as a tripwire, because
    // `security -i` is a newline-delimited command stream and a raw newline in the payload
    // would turn the tail of a secret into a second Keychain command.
    throw new EngineError('config_invalid', 'refusing to store a multi-line client secret', {
      hint: 'The Keychain command stream is newline-delimited; a credential containing a raw newline would be reinterpreted as a command.',
    });
  }
  return json;
}

/* ─────────────────────────────────────── write ─────────────────────────────────────── */

/**
 * Store (or replace) the user's registered client credentials for `provider`. This is the
 * B1 setup-wizard's one write. Delete-then-add (idempotent) mirrors the token vault.
 *
 * @throws EngineError `config_invalid` when either field is empty.
 * @throws EngineError `vault_unavailable` when the Keychain refuses the write or the write
 *         does not survive a read-back.
 */
export async function storeClientCredentials(
  provider: string,
  creds: ClientCredentials,
  options: ByosOptions = {},
): Promise<void> {
  const runner = options.runner ?? defaultRunner;
  const service = byocService(provider);

  if (typeof creds.client_id !== 'string' || creds.client_id.trim() === '') {
    throw new EngineError('config_invalid', 'B1 needs a non-empty client_id', {
      hint: `Register your own app with ${provider} and paste its client id.`,
    });
  }
  if (typeof creds.client_secret !== 'string' || creds.client_secret.trim() === '') {
    // The empty check names the field, never a value.
    throw new EngineError('config_invalid', 'B1 needs a non-empty client_secret', {
      hint: `Register your own app with ${provider} and paste its client secret.`,
    });
  }

  const payload = serialize(creds);
  const hex = Buffer.from(payload, 'utf8').toString('hex');

  await deleteClientCredentials(provider, options);

  // argv is `['-i']` — the command (secret hex included) rides stdin, invisible to `ps`.
  const result = await runner(
    ['-i'],
    `add-generic-password -a ${BYOC_ACCOUNT} -s ${service} -D ${KIND} -X ${hex}\n`,
  );
  if (result.code !== 0) {
    // stderr is echoed only via firstLine, which is `security`'s own diagnostic — it never
    // contains our payload (that went on stdin), so this cannot leak the secret.
    throw new EngineError('vault_unavailable', 'the Keychain refused the B1 credential write', {
      hint: `security add-generic-password exited ${result.code} for ${service}. ${firstLine(result.stderr)}`,
    });
  }

  const readBack = await readClientCredentials(provider, options);
  if (readBack === null || readBack.client_secret !== creds.client_secret) {
    throw new EngineError('vault_unavailable', 'the B1 credential write did not survive a read-back', {
      hint: `Wrote ${service} and read back ${readBack === null ? 'nothing' : 'a different record'}. Nothing is cached on disk, so the safe state is unconfigured.`,
    });
  }
}

/* ─────────────────────────────────────── read ─────────────────────────────────────── */

/**
 * THE ONLY read path for a B1 secret — the property the custody tests enforce is that the
 * secret is obtained here and nowhere else.
 *
 * @returns the stored credentials, or `null` when this provider has no B1 client registered.
 */
export async function readClientCredentials(
  provider: string,
  options: ByosOptions = {},
): Promise<ClientCredentials | null> {
  const runner = options.runner ?? defaultRunner;
  const service = byocService(provider);

  const result = await runner(['find-generic-password', '-a', BYOC_ACCOUNT, '-s', service, '-w']);
  if (result.code !== 0) {
    if (isNotFound(result)) return null;
    throw new EngineError('vault_unavailable', 'the Keychain refused the B1 credential read', {
      hint: `security find-generic-password exited ${result.code} for ${service}. ${firstLine(result.stderr)}`,
    });
  }

  const raw = result.stdout.trim();
  if (raw === '') return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // The stored bytes are NEVER echoed into the error: they are the secret.
    throw new EngineError('vault_unavailable', 'the vaulted B1 credential is not valid JSON', {
      hint: `Keychain item ${service} holds ${raw.length} bytes that do not parse. Re-run the ${provider} setup to rewrite it.`,
    });
  }

  if (parsed === null || typeof parsed !== 'object') return null;
  const record = parsed as Partial<ClientCredentials>;
  if (
    typeof record.client_id !== 'string' ||
    record.client_id === '' ||
    typeof record.client_secret !== 'string' ||
    record.client_secret === ''
  ) {
    return null;
  }

  return { client_id: record.client_id, client_secret: record.client_secret };
}

/* ────────────────────────────────────── delete ────────────────────────────────────── */

/**
 * Destroy the B1 credentials for `provider`. Idempotent, so a disconnect that removes both
 * the token (vault.deleteToken) and the client secret (here) never fails on the missing one.
 */
export async function deleteClientCredentials(
  provider: string,
  options: ByosOptions = {},
): Promise<void> {
  const runner = options.runner ?? defaultRunner;
  const service = byocService(provider);
  const result = await runner(['delete-generic-password', '-a', BYOC_ACCOUNT, '-s', service]);
  if (result.code === 0 || isNotFound(result)) return;
  throw new EngineError('vault_unavailable', 'the Keychain refused the B1 credential delete', {
    hint: `security delete-generic-password exited ${result.code} for ${service}. ${firstLine(result.stderr)}`,
  });
}

/* ──────────────────────────────── the exchange-facing helper ──────────────────────────────── */

/** Modes that require a client secret and therefore route through this module. */
const CONFIDENTIAL_MODES = new Set(['basic', 'secret_basic', 'secret_post']);

/** True for the confidential auth modes B1 handles (including the legacy `'basic'` alias). */
export function isConfidentialAuth(mode: string): boolean {
  return CONFIDENTIAL_MODES.has(mode);
}

/**
 * Authenticate a confidential token/refresh request with the user's vaulted B1 credentials.
 *
 * Reads the credentials from the Keychain (the ONLY read of the secret), applies client
 * authentication to `body`/`headers` per `mode`, and RETURNS the secret so the caller can
 * register it with `redact()` before any provider response is turned into a string. The
 * caller must do that registration — this function never logs and never throws with a
 * secret in the message.
 *
 *   `secret_post`  → `client_id` + `client_secret` in the form body.
 *   `secret_basic` (or the legacy `'basic'`) → `Authorization: Basic base64(id:secret)`.
 *
 * @throws EngineError `config_invalid` when no B1 client is registered for this provider —
 *         the cue for the product surface to launch the five-minute setup wizard. The error
 *         carries no credential material because none was read.
 */
export async function applyConfidentialAuth(
  provider: string,
  mode: ConfidentialAuthMode | 'basic',
  body: URLSearchParams,
  headers: Record<string, string>,
  options: ByosOptions = {},
): Promise<string> {
  if (!isConfidentialAuth(mode)) {
    throw new EngineError('config_invalid', 'applyConfidentialAuth called for a non-confidential mode', {
      hint: `Mode '${String(mode)}' is not a confidential client-auth method; route public modes through applyClientAuth.`,
    });
  }

  const creds = await readClientCredentials(provider, options);
  if (creds === null) {
    throw new EngineError('config_invalid', `${provider} needs a bring-your-own (B1) client`, {
      hint: `This confidential client requires a client secret. Register your own app with ${provider} and store its client secret via the B1 setup (storeClientCredentials) before connecting.`,
    });
  }

  if (mode === 'secret_post') {
    body.set('client_id', creds.client_id);
    body.set('client_secret', creds.client_secret);
  } else {
    // secret_basic and the legacy 'basic' alias.
    headers.authorization = `Basic ${Buffer.from(`${creds.client_id}:${creds.client_secret}`, 'utf8').toString('base64')}`;
  }

  return creds.client_secret;
}
