/**
 * C-3 — mix-up defense (RFC 9207 `iss` + `state` bound to the provider that minted it).
 *
 * The attack (RFC 9207 §1, the "mix-up attack"): a user has two connects in flight — an honest
 * provider A and a provider B the attacker controls or has compromised. The attacker causes
 * B's authorization response to be delivered into the client's pending flow for A. If the
 * client matches responses to flows on `state` alone, and the attacker has learned or replayed
 * A's `state`, the client can be tricked into sending A's authorization code to B — or into
 * accepting B's code as if A had issued it. `state` proves "this response answers a request I
 * started"; it does NOT prove "this response came from the provider I started it WITH."
 *
 * Two independent bindings close that gap, and this module owns both:
 *
 *   1. `state` → provider. Every state we mint is registered here against the provider it was
 *      minted for. A callback is matched to a pending flow only if the flow that state belongs
 *      to is the provider whose listener received it. Provider A's response can therefore never
 *      satisfy a flow that was started for provider B, even if the states somehow collide or an
 *      attacker replays one across listeners.
 *   2. RFC 9207 `iss`. When the provider publishes an issuer identifier (profile field
 *      `issuer`), the callback MUST carry an `iss` equal to it. If the provider is known to send
 *      `iss` at all (`iss_required`, from its `authorization_response_iss_parameter_supported`
 *      metadata), a response WITHOUT `iss` is refused — a mix-up response from a different AS
 *      cannot forge the honest AS's issuer, and cannot omit it either.
 *
 * The registry is a parallel store to state.ts on purpose: state.ts is a shared, frozen file
 * that keys value → expiry only, and binding a provider + issuer to it belongs with the defense
 * that reads them, not bolted onto the CSRF nonce. Both stores are process-local, in-memory,
 * and TTL-swept — a binding is meaningful only while its flow is live.
 *
 * A failed check is `state_mismatch`: the frozen copy-deck code whose page loopback already
 * shows, and whose meaning ("that sign-in did not match what we started") is exactly right.
 */

import { STATE_TTL_MS } from './config.ts';
import { EngineError } from './errors.ts';

/** What a state is bound to for the life of one flow. */
interface FlowBinding {
  provider: string;
  /** RFC 9207 expected issuer, when the provider publishes one. Absent = cannot check `iss`. */
  issuer: string | undefined;
  /** The provider is known to always send `iss`, so a missing `iss` is itself an attack. */
  issRequired: boolean;
  /** Absolute expiry (epoch ms). A binding never outlives the state's own TTL. */
  expiresAt: number;
}

/** state value → what it is bound to. */
const bindings = new Map<string, FlowBinding>();

/** Options for one binding. Both `iss` inputs are optional: not every provider publishes them. */
export interface BindFlowOptions {
  /** RFC 9207 issuer identifier the callback's `iss` must equal, when the provider has one. */
  issuer?: string;
  /**
   * The provider is documented to always return `iss` (its metadata sets
   * `authorization_response_iss_parameter_supported: true`). A callback that then omits `iss`
   * is refused, per RFC 9207 §3.
   */
  issRequired?: boolean;
}

/** Drop everything already expired. Keeps a long-lived process bounded. */
function sweep(now: number): void {
  for (const [state, binding] of bindings) {
    if (binding.expiresAt <= now) bindings.delete(state);
  }
}

/**
 * Bind a freshly minted `state` to the provider (and, where known, the issuer) it was minted
 * for. Called at connect time, right after state.ts mints the state.
 *
 * The TTL matches STATE_TTL_MS so the binding and the state die together: a state that has
 * aged out of state.ts is unredeemable anyway, and a lingering binding would be dead weight.
 */
export function bindFlow(state: string, provider: string, options: BindFlowOptions = {}): void {
  const now = Date.now();
  sweep(now);
  bindings.set(state, {
    provider,
    issuer: options.issuer,
    issRequired: options.issRequired ?? false,
    expiresAt: now + STATE_TTL_MS,
  });
}

/** Forget one flow's binding. Called once its callback has been resolved terminally. */
export function clearFlow(state: string): void {
  bindings.delete(state);
}

/** Number of live flow bindings. Diagnostics and tests only. */
export function pendingFlows(): number {
  sweep(Date.now());
  return bindings.size;
}

/** Forget every binding (process shutdown, test isolation). */
export function clearFlows(): void {
  bindings.clear();
}

/** The reason a callback was refused. `ok` when it matched the flow it claims to. */
export type MixupVerdict =
  | { ok: true }
  | { ok: false; reason: 'unbound' | 'wrong_provider' | 'iss_mismatch' | 'iss_missing' };

/**
 * Does this callback belong to the flow it is being matched against?
 *
 * @param state          the `state` the callback carried (already length/replay-checked upstream)
 * @param expectedProvider the provider whose listener received the callback
 * @param receivedIss    RFC 9207 `iss` from the callback query, or null if absent
 *
 * Read-only: the binding is not consumed here. Single-use is state.ts's job (see
 * callbackState.ts); this answers a different question — is the response from the RIGHT
 * provider — and the caller clears the binding when the flow resolves.
 */
export function checkFlow(
  state: string,
  expectedProvider: string,
  receivedIss: string | null,
): MixupVerdict {
  const binding = bindings.get(state);
  if (binding === undefined || binding.expiresAt <= Date.now()) {
    // No live flow owns this state. It was never minted here, or it has expired — either way
    // it cannot be matched to a provider, so it cannot be trusted to answer one.
    return { ok: false, reason: 'unbound' };
  }
  if (binding.provider !== expectedProvider) {
    // The state belongs to a DIFFERENT provider's flow. Provider A's response arriving at
    // provider B's listener is the mix-up, refused outright.
    return { ok: false, reason: 'wrong_provider' };
  }
  if (binding.issuer !== undefined) {
    if (receivedIss === null) {
      // We know the honest AS's issuer; a response with no `iss` cannot prove it came from it.
      return { ok: false, reason: 'iss_missing' };
    }
    if (receivedIss !== binding.issuer) {
      // A different issuer answered — the defining signature of a mix-up.
      return { ok: false, reason: 'iss_mismatch' };
    }
  } else if (binding.issRequired && receivedIss === null) {
    // The provider is documented to always send `iss` (RFC 9207 §3): its absence is an attack,
    // even when we have no issuer string to compare against.
    return { ok: false, reason: 'iss_missing' };
  }
  return { ok: true };
}

/**
 * Throwing form for the exchange path: refuse a mismatched response before a code is ever sent
 * to a token endpoint. Belt-and-suspenders alongside the loopback-level `checkFlow` gate.
 *
 * @throws EngineError `state_mismatch` on any non-ok verdict. The message names the reason for
 *   the operator log; no `state`, `code`, `iss`, or token ever appears in it.
 */
export function assertFlow(state: string, expectedProvider: string, receivedIss: string | null): void {
  const verdict = checkFlow(state, expectedProvider, receivedIss);
  if (verdict.ok) return;
  const reasons: Record<'unbound' | 'wrong_provider' | 'iss_mismatch' | 'iss_missing', string> = {
    unbound: 'no live flow owns this callback — it was never started here or it expired',
    wrong_provider: 'the callback belongs to a different provider than the one it arrived for',
    iss_mismatch: 'RFC 9207 iss did not match the provider that started this flow (mix-up)',
    iss_missing: 'the provider always returns iss but this callback carried none (RFC 9207)',
  };
  throw new EngineError('state_mismatch', `${expectedProvider}: ${reasons[verdict.reason]}`, {
    hint: `Refused a callback that did not match the pending ${expectedProvider} flow. Say "connect" again to start a fresh request.`,
  });
}
