/**
 * The B2b return-leg seal (SPEC §5b, "Ephemeral response encryption").
 *
 * The device generates a single-use X25519 keypair per flow and sends the relay its public
 * key. The relay generates its OWN single-use X25519 keypair, derives a shared secret by
 * ECDH, stretches it through HKDF-SHA256 into an AES-256-GCM key, and seals the provider's
 * token bytes. Only the device — holding a private key that never left it — can open the
 * result. The relay discards its ephemeral private key when the flow completes.
 *
 * Two properties this file is responsible for, each a line in the audit sentence:
 *   1. the token is removed from every surface downstream of the relay process — response
 *      logs, caches, intermediaries, error reporting, crash dumps taken after the flow —
 *      because what leaves the process is ciphertext no downstream party can open;
 *   2. paired with `zeroize`, the plaintext token is removed from a memory image captured
 *      any time OTHER than the exchange instant itself: the plaintext buffer is wiped the
 *      moment the AEAD has consumed it.
 *
 * The honest limit (SPEC §5b) is unchanged and this file does not pretend otherwise: a fully
 * compromised relay AT the instant of exchange sees that one token. Zeroization bounds the
 * window; it does not close it. B1 remains the recommendation for the security-sensitive.
 */

import {
  createCipheriv,
  createDecipheriv,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from 'node:crypto';

import { SEAL_AEAD, SEAL_HKDF_INFO, SEAL_KDF } from './config.ts';
import { RelayError } from './types.ts';

/** The 12-byte ASN.1 SPKI prefix for an X25519 public key (RFC 8410 id-X25519). */
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const X25519_RAW_LEN = 32;

/**
 * Wrap a raw 32-byte X25519 public key into a node KeyObject. We accept the RAW key on the
 * wire (the smallest, most interoperable form the device can emit from WebCrypto or libsodium)
 * and re-clothe it in SPKI here, rather than making the device speak DER.
 */
export function importDeviceX25519(raw: Buffer): KeyObject {
  if (raw.length !== X25519_RAW_LEN) {
    throw new RelayError(
      'bad_request',
      `device X25519 public key must be ${X25519_RAW_LEN} raw bytes, got ${raw.length}`,
    );
  }
  const spki = Buffer.concat([X25519_SPKI_PREFIX, raw]);
  try {
    return createPublicKey({ key: spki, format: 'der', type: 'spki' });
  } catch {
    throw new RelayError('bad_request', 'device X25519 public key is not a valid point');
  }
}

/** Export a node X25519 public KeyObject back to the raw 32 bytes for the wire. */
export function exportRawX25519(publicKey: KeyObject): Buffer {
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return spki.subarray(spki.length - X25519_RAW_LEN);
}

export interface Sealed {
  relayPublicKeyRaw: Buffer;
  iv: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
  enc: typeof SEAL_AEAD;
  kdf: typeof SEAL_KDF;
}

/**
 * Overwrite a buffer's contents with zeros. Best-effort by JS's nature — the engine can't
 * guarantee no interpreter-internal copy was made — but it removes the one plaintext copy
 * WE hold, which is the copy that would sit in a heap dump taken after the flow. Exported so
 * a test can prove the plaintext buffer is wiped after sealing.
 */
export function zeroize(...buffers: Array<Buffer | undefined>): void {
  for (const b of buffers) if (b !== undefined) b.fill(0);
}

/**
 * Seal `plaintext` to the device's X25519 public key.
 *
 * `plaintext` is CONSUMED: it is zeroized before this function returns, whether the seal
 * succeeds or throws. Callers must pass a buffer they own and must not read it afterwards.
 * The relay's ephemeral private key never leaves this function's scope and is dropped when
 * it returns (there is no handle to it anywhere else).
 */
export function seal(plaintext: Buffer, devicePublicKey: KeyObject): Sealed {
  const ephemeral = generateKeyPairSync('x25519');
  let sharedSecret: Buffer | undefined;
  let derivedKey: Buffer | undefined;
  const iv = randomBytes(12);

  try {
    sharedSecret = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: devicePublicKey });
    // HKDF binds the AEAD key to this exact context (SEAL_HKDF_INFO); the salt is empty by
    // design — the ECDH secret is already high-entropy and single-use per flow.
    derivedKey = Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.alloc(0), Buffer.from(SEAL_HKDF_INFO, 'utf8'), 32));

    const cipher = createCipheriv('aes-256-gcm', derivedKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      relayPublicKeyRaw: exportRawX25519(ephemeral.publicKey),
      iv,
      ciphertext,
      tag,
      enc: SEAL_AEAD,
      kdf: SEAL_KDF,
    };
  } finally {
    // The plaintext token and every intermediate key material are wiped on every path.
    zeroize(plaintext, sharedSecret, derivedKey);
  }
}

/**
 * The device side of the seal, kept here so tests (and a device SDK) can round-trip against
 * the exact derivation the relay used. In production this runs on the device, never on the
 * relay — the relay has no private key capable of opening its own ciphertext.
 */
export function open(sealed: Sealed, devicePrivateKey: KeyObject): Buffer {
  const relayPub = importDeviceX25519(sealed.relayPublicKeyRaw);
  const sharedSecret = diffieHellman({ privateKey: devicePrivateKey, publicKey: relayPub });
  const key = Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.alloc(0), Buffer.from(SEAL_HKDF_INFO, 'utf8'), 32));
  const decipher = createDecipheriv('aes-256-gcm', key, sealed.iv);
  decipher.setAuthTag(sealed.tag);
  const out = Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]);
  zeroize(sharedSecret, key);
  return out;
}
