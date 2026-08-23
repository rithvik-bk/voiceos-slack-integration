/**
 * P1-I5 — the vault. Token custody, delegated to a pluggable KeyStore (C-9, SPEC §6).
 *
 * The demo has a beat where the presenter greps the disk live and finds no token. That beat
 * is only honest if a token is persisted through exactly one narrow, secret-safe path. This
 * file keeps the TokenRecord serialize/parse and the provider→key mapping, and hands the
 * opaque serialized string to a {@link KeyStore} backend for storage. The backend owns the
 * §6 invariants (no secret in argv, no plaintext on disk, restrictive ACL, local-only
 * delete); the selector (`selectKeyStore`) picks the strongest backend the platform offers
 * and never downgrades to a weak one silently.
 *
 * On macOS the backend is `/usr/bin/security` via the same `security -i` / hex transport the
 * original vault proved out — see engine/src/keystore/security-backend.ts for the scars.
 *
 * Layout: KeyStore key = `com.voiceos.connect.<provider>`, value = the JSON TokenRecord.
 * One item per provider; `deleteToken` destroys it.
 */

import { accountKey, emptyIndex, parseIndex, serializeIndex } from './account.ts';
import type { AccountIndex } from './account.ts';
import { EngineError } from './errors.ts';
import { selectKeyStore } from './keystore/index.ts';
import type { KeyStore } from './keystore/index.ts';
import type { TokenRecord } from './types.ts';

export const VAULT_ACCOUNT = 'voiceos';

/** Built from an ASCII source string on purpose: this file stays copy-pasteable everywhere. */
const NON_ASCII = new RegExp('[\\u0080-\\uFFFF]', 'g');

export function vaultService(provider: string): string {
  if (!/^[a-z0-9][a-z0-9._-]*$/i.test(provider)) {
    throw new EngineError('config_invalid', 'provider name is not a legal vault key', {
      hint: `Provider names are [A-Za-z0-9._-]; got ${JSON.stringify(provider)}.`,
    });
  }
  return `com.voiceos.connect.${provider}`;
}

/**
 * C-13 — the KeyStore key for one account's token: `(provider + account)` when an `accountId`
 * is given, the bare provider otherwise. The account-keyed form is the entire mechanism by
 * which two accounts of one provider get two Keychain items instead of the second silently
 * clobbering the first (the wave-1 MEDIUM). The bare form is kept for callers that predate the
 * account dimension and for the legacy single-slot record; `accountKey()` validates both halves.
 */
function keyFor(provider: string, accountId?: string): string {
  return accountId === undefined || accountId === ''
    ? vaultService(provider)
    : vaultService(accountKey(provider, accountId));
}

/** KeyStore key for a provider's account INDEX — the display-safe (provider,account) map that
 *  routes `getToken(provider, account?)`. `.accounts` cannot collide with a token key, whose
 *  account form is `<provider>.acct.<hex>`. */
function indexService(provider: string): string {
  return `${vaultService(provider)}.accounts`;
}

/** Lazily selected, cached for the process. `selectKeyStore()` throws on an unsupported platform. */
let cachedStore: KeyStore | undefined;
function store(): KeyStore {
  return (cachedStore ??= selectKeyStore());
}

/** Single-line, pure-ASCII JSON. Both properties are load-bearing for the stdin transport. */
function serialize(record: TokenRecord): string {
  const json = JSON.stringify(record).replace(
    // Escape every non-ASCII code unit: `security` prints non-UTF8-safe data back as hex,
    // and an identity handle with an emoji in it would otherwise round-trip as garbage.
    NON_ASCII,
    (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`,
  );
  if (/[\r\n]/.test(json)) {
    // Unreachable via JSON.stringify (it escapes newlines) — kept as a tripwire, because
    // `security -i` is a newline-delimited command stream and a raw newline in the payload
    // would turn the tail of a token into a second Keychain command.
    throw new EngineError('vault_unavailable', 'refusing to store a multi-line secret', {
      hint: 'The Keychain command stream is newline-delimited; a record containing a raw newline would be reinterpreted as a command.',
    });
  }
  return json;
}

/* ─────────────────────────────────────── write ─────────────────────────────────────── */

/**
 * Store (or replace) the record for `provider`. The backend does delete-then-add and
 * write-then-verify (§P1-I5 "crash-safe") — a Keychain write that silently failed and one
 * that succeeded look identical from here until the demo, so it is the backend that reads the
 * value back and compares before returning.
 */
export async function putToken(
  provider: string,
  record: TokenRecord,
  accountId?: string,
): Promise<void> {
  const payload = serialize({ ...record, provider });
  await store().put(keyFor(provider, accountId), payload);
}

/* ─────────────────────────────────────── read ─────────────────────────────────────── */

/** The vaulted record, or `null` when this provider/account has never been connected. */
export async function readToken(
  provider: string,
  accountId?: string,
): Promise<TokenRecord | null> {
  const raw = await store().get(keyFor(provider, accountId));
  if (raw === null) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // The stored bytes are NEVER echoed into the error: they are the secret.
    throw new EngineError('vault_unavailable', 'the vaulted record is not valid JSON', {
      hint: `The Keychain item for ${provider} holds ${raw.length} bytes that do not parse. Disconnect and reconnect ${provider} to rewrite it.`,
    });
  }

  if (parsed === null || typeof parsed !== 'object') return null;
  const record = parsed as Partial<TokenRecord>;
  if (typeof record.access_token !== 'string' || record.access_token === '') return null;

  return {
    provider,
    access_token: record.access_token,
    ...(typeof record.refresh_token === 'string' ? { refresh_token: record.refresh_token } : {}),
    ...(typeof record.expires_at === 'number' ? { expires_at: record.expires_at } : {}),
    scopes: Array.isArray(record.scopes) ? record.scopes.filter((s) => typeof s === 'string') : [],
    ...(record.identity !== undefined && typeof record.identity.handle === 'string'
      ? {
          identity: {
            handle: record.identity.handle,
            ...(typeof record.identity.workspace === 'string'
              ? { workspace: record.identity.workspace }
              : {}),
          },
        }
      : {}),
    obtained_at: typeof record.obtained_at === 'number' ? record.obtained_at : 0,
  };
}

/* ────────────────────────────────────── delete ────────────────────────────────────── */

/**
 * Destroy the record for `provider`. Idempotent: disconnecting something that was never
 * connected succeeds silently rather than throwing at a user who just wants it gone.
 */
export async function deleteToken(provider: string, accountId?: string): Promise<void> {
  await store().delete(keyFor(provider, accountId));
}

/* ─────────────────────────────────── account index ─────────────────────────────────── */

/**
 * The (provider → accounts) index that routes `getToken(provider, account?)`.
 *
 * The index is display-safe — handles and workspace labels, never a token — so it rides in the
 * KeyStore next to the tokens it maps. Reads are TOTAL: a missing or corrupt index degrades to
 * an empty index (via {@link parseIndex}) rather than throwing, because a bad index must never
 * be what makes `getToken` crash.
 */
export async function readAccountIndex(provider: string): Promise<AccountIndex> {
  const raw = await store().get(indexService(provider)).catch(() => null);
  if (raw === null) return emptyIndex();
  return parseIndex(raw);
}

/** Persist the account index for `provider`. The backend hex-encodes the payload, so a handle
 *  with non-ASCII characters round-trips without the escaping the token path also applies. */
export async function writeAccountIndex(provider: string, index: AccountIndex): Promise<void> {
  await store().put(indexService(provider), serializeIndex(index));
}

/** Forget a provider's account index. Idempotent, like {@link deleteToken}. */
export async function deleteAccountIndex(provider: string): Promise<void> {
  await store().delete(indexService(provider));
}
