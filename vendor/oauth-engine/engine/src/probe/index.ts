/**
 * The conformance probe — public surface (C-1, C-18).
 *
 * Everything the CLI (`tools/probe.mjs`) and the engine need to MEASURE a provider and emit
 * `providers/<name>.json` + `<name>.evidence.json`. The probe touches zero engine internals
 * beyond the shared `redact`/`paths` primitives and the read-only `config` ladder; adding it
 * required no edits to any shared engine file.
 */

export { probe, deriveCustody } from './probe.ts';
export type { ProbeInput } from './probe.ts';
export { fetchDiscovery, mapMetadata, clientAuthFromMethods } from './discovery.ts';
export type { DiscoveryOutcome } from './discovery.ts';
export { classifyClientAuth } from './classify.ts';
export type { ClientAuthClassification } from './classify.ts';
export { probeRedirectTolerance, LOOPBACK_HOSTS } from './redirect.ts';
export type { RedirectToleranceResult, RedirectProbe, RedirectOutcome } from './redirect.ts';
export { observeTokenResponse, observeFirstRefresh } from './observe.ts';
export type { TokenShapeObservation, RotationObservation } from './observe.ts';
export { serialize } from './emit.ts';
export type { SerializedProbe } from './emit.ts';
export type { Receipt, ProbeEvidence, ProbeResult, ProbeHttp } from './types.ts';
