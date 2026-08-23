/**
 * The relay's only tunables, in one place (mirrors the engine's `config.ts` discipline).
 *
 * Every value here is a security parameter, not a preference:
 *   - the assertion TTL is how long a signed client-assertion is a valid bearer credential
 *     if it leaks in flight; 60s is enough for one immediate token exchange and nothing more
 *   - the AEAD/KDF identifiers are pinned so a downgrade is a code change, never a request
 *     parameter (an attacker must not be able to negotiate the relay down to a weaker seal)
 */

/** RFC 7523 client assertion lifetime. One exchange's worth of validity, no reuse window. */
export const ASSERTION_TTL_SECONDS = 60;

/** A token endpoint that has not answered in this long is a hung flow, not a slow network. */
export const EXCHANGE_TIMEOUT_MS = 20_000;

/** The pinned return-leg seal (SPEC §5b). Advertised, never negotiated. */
export const SEAL_AEAD = 'A256GCM' as const;
export const SEAL_KDF = 'HKDF-SHA256' as const;

/**
 * HKDF domain separation. Binds the derived key to this relay's B2b return leg so the same
 * ECDH secret can never be coerced into deriving a key for some other context.
 */
export const SEAL_HKDF_INFO = 'handshake-relay/b2b/response-encryption/v1';

/** urn per RFC 7523 §2.2 — the client_assertion_type the device forwards to the provider. */
export const JWT_BEARER_ASSERTION_TYPE =
  'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
