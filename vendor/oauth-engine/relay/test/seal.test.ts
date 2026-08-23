/**
 * B2b return-leg seal (SPEC §5b). The properties under test are the ones the audit sentence
 * claims: only the device can open it, a wrong key or a tampered ciphertext fails closed, and
 * the plaintext buffer is zeroized the moment the AEAD has consumed it.
 */

import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { exportRawX25519, importDeviceX25519, open, seal, zeroize } from '../src/seal.ts';

function deviceKeypair() {
  const kp = generateKeyPairSync('x25519');
  return { privateKey: kp.privateKey, publicRaw: exportRawX25519(kp.publicKey) };
}

describe('seal / open round trip', () => {
  it('the device — and only the device — recovers the plaintext', () => {
    const device = deviceKeypair();
    const token = Buffer.from('{"access_token":"mock-super-secret-x","expires_in":3600}', 'utf8');
    const expected = Buffer.from(token); // copy: seal wipes its input

    const sealed = seal(token, importDeviceX25519(device.publicRaw));
    const opened = open(sealed, device.privateKey);

    expect(opened.equals(expected)).toBe(true);
    expect(sealed.enc).toBe('A256GCM');
    expect(sealed.kdf).toBe('HKDF-SHA256');
    expect(sealed.relayPublicKeyRaw.length).toBe(32);
    expect(sealed.iv.length).toBe(12);
    expect(sealed.tag.length).toBe(16);
  });

  it('a different device key cannot open it (AEAD fails closed)', () => {
    const device = deviceKeypair();
    const attacker = deviceKeypair();
    const sealed = seal(Buffer.from('secrettoken', 'utf8'), importDeviceX25519(device.publicRaw));
    expect(() => open(sealed, attacker.privateKey)).toThrow();
  });

  it('a tampered ciphertext is rejected by the auth tag', () => {
    const device = deviceKeypair();
    const sealed = seal(Buffer.from('secrettoken', 'utf8'), importDeviceX25519(device.publicRaw));
    sealed.ciphertext[0] = (sealed.ciphertext[0] ?? 0) ^ 0xff;
    expect(() => open(sealed, device.privateKey)).toThrow();
  });

  it('a tampered tag is rejected', () => {
    const device = deviceKeypair();
    const sealed = seal(Buffer.from('secrettoken', 'utf8'), importDeviceX25519(device.publicRaw));
    sealed.tag[0] = (sealed.tag[0] ?? 0) ^ 0xff;
    expect(() => open(sealed, device.privateKey)).toThrow();
  });

  it('each seal uses a fresh relay ephemeral key and iv (no reuse across flows)', () => {
    const device = deviceKeypair();
    const pub = importDeviceX25519(device.publicRaw);
    const a = seal(Buffer.from('same-plaintext', 'utf8'), pub);
    const b = seal(Buffer.from('same-plaintext', 'utf8'), pub);
    expect(a.relayPublicKeyRaw.equals(b.relayPublicKeyRaw)).toBe(false);
    expect(a.iv.equals(b.iv)).toBe(false);
    expect(a.ciphertext.equals(b.ciphertext)).toBe(false); // fresh key+iv → different ciphertext
  });
});

describe('zeroization', () => {
  it('seal wipes its plaintext input buffer before returning', () => {
    const device = deviceKeypair();
    const token = Buffer.from('a-real-looking-access-token-value', 'utf8');
    expect(token.some((b) => b !== 0)).toBe(true); // non-zero going in

    seal(token, importDeviceX25519(device.publicRaw));

    // The plaintext copy the relay held is gone: every byte is now zero.
    expect(token.every((b) => b === 0)).toBe(true);
  });

  it('zeroize wipes and tolerates undefined', () => {
    const b = Buffer.from('secret', 'utf8');
    zeroize(b, undefined);
    expect(b.every((x) => x === 0)).toBe(true);
  });
});

describe('X25519 key import', () => {
  it('accepts a raw 32-byte public key and rejects a wrong length', () => {
    const { publicRaw } = deviceKeypair();
    expect(() => importDeviceX25519(publicRaw)).not.toThrow();
    expect(() => importDeviceX25519(Buffer.alloc(31))).toThrow(/32 raw bytes/);
    expect(() => importDeviceX25519(Buffer.alloc(33))).toThrow(/32 raw bytes/);
  });

  it('round-trips a public key through raw export/import', () => {
    const kp = generateKeyPairSync('x25519');
    const raw = exportRawX25519(kp.publicKey);
    const reimported = importDeviceX25519(raw);
    expect(exportRawX25519(reimported).equals(raw)).toBe(true);
  });
});
