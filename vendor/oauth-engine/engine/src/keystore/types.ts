/**
 * C-9 — the pluggable KeyStore interface (SPEC Part 2 §6).
 *
 * The previous engine hard-wired persistence to `/usr/bin/security` inside `vault.ts`. That
 * is correct for development and mac-only; SPEC §6 wants a documented backend LADDER so a
 * new platform (or a hardened production build) is a backend swap, not a rewrite of the vault.
 *
 * A KeyStore is deliberately narrow: it stores an opaque secret STRING under a key and gives
 * it back. It knows nothing about TokenRecords, OAuth, or providers — `vault.ts` serializes a
 * record to a string and hands it here. That keeps the security-sensitive surface (the four
 * §6 invariants below) in ONE small, per-backend place, testable in isolation.
 *
 * The four invariants every backend must uphold, each with a test (SPEC §6):
 *   1. A secret is never passed as a command-line argument.
 *   2. A secret is never written to disk unencrypted — INCLUDING atomic-write temp phases.
 *   3. The stored item carries an ACL restricting read to the signing identity where the
 *      platform supports it (mac: default restrictive ACL, never `-A`; file: mode 0600).
 *   4. Disconnect (`delete`) removes locally, unconditionally, first — never blocked by, and
 *      never failing because of, a network call. (Durable revocation is enqueued ABOVE the
 *      keystore; the keystore's job is only the unconditional local delete.)
 */

/** Custody strength of a backend. `weak` backends are NEVER selected silently (see `select.ts`). */
export type KeyStoreStrength = 'strong' | 'weak';

/** Stable ids for the backends in the §6 ladder. */
export type KeyStoreBackendId =
  | 'macos-security-cli'
  | 'encrypted-file';

export interface KeyStore {
  /** Which backend this is — surfaced in logs and the connect UI, never a secret. */
  readonly id: KeyStoreBackendId;
  /** `weak` backends must be explicitly opted into; the selector refuses them silently. */
  readonly strength: KeyStoreStrength;
  /** One-line, secret-free description for logs / the connect custody chip. */
  readonly label: string;

  /**
   * Store (or replace) the secret under `key`. Write-then-verify: a backend MUST read the
   * value back and confirm it before resolving, because a silently-failed write and a real
   * one look identical to the caller until the token is needed. Throws `EngineError` on
   * failure; the thrown message/hint NEVER contains the secret.
   */
  put(key: string, secret: string): Promise<void>;

  /** The stored secret, or `null` when nothing is stored under `key`. Never throws on absence. */
  get(key: string): Promise<string | null>;

  /**
   * Remove the secret under `key`. Idempotent (deleting nothing succeeds) and LOCAL-ONLY:
   * it performs no network call and cannot fail because of one. This is the unconditional
   * first half of §6's disconnect rule.
   */
  delete(key: string): Promise<void>;
}
