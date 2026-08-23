/**
 * The relay package's public surface (SPEC Part 2 §5, §5b).
 *
 * The relay is a self-contained, zero-dependency, memory-only service. It shares no runtime
 * code with the engine. An embedder needs `createRelay` + `RelayKeyStore`; a device SDK needs
 * `open` (the return-leg decrypt) and the wire types; everything else is internal.
 */

export { createRelay, type RelayServerOptions } from './server.ts';
export { RelayKeyStore, type SigningKey, type ClientSecret } from './keystore.ts';
export { RelayLog, type RelayEvent, type RelayEventName, type LogSink } from './log.ts';
export { signAssertion, forwardExchange, type HandlerDeps } from './handlers.ts';
export { seal, open, importDeviceX25519, exportRawX25519, zeroize, type Sealed } from './seal.ts';
export { signClientAssertion, keyThumbprint, type JwtAlg, type AssertionClaims } from './jwt.ts';
export {
  RelayError,
  type RelayErrorCode,
  type AssertionRequest,
  type AssertionResponse,
  type ExchangeRequest,
  type RelayGrantType,
  type SealedResponse,
} from './types.ts';
