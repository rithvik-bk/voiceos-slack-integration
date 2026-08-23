/**
 * KeyStore module barrel (C-9, SPEC §6). NOT the engine's public index — this is the keystore
 * subsystem's own surface, imported by `vault.ts` (see the integration note in the C-9 brief).
 */

export type { KeyStore, KeyStoreBackendId, KeyStoreStrength } from './types.ts';
export { MacSecurityKeyStore, SECURITY_ACCOUNT } from './security-backend.ts';
export { EncryptedFileKeyStore } from './encrypted-file-backend.ts';
export { selectKeyStore } from './select.ts';
export type { SelectOptions } from './select.ts';
