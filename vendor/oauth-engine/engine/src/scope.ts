/**
 * Incremental scope step-up (SPEC Part 4 §9).
 *
 * The standard approach — request every scope a provider might ever need at connect time —
 * is wrong twice: the consent screen reads like a demand for the user's whole account
 * (which suppresses connection), and it grants standing write access to an assistant that
 * mostly reads. §9 inverts it: connect asks for the minimum viable set, tools declare the
 * scopes each action requires, and the engine computes the delta *before dispatch* and
 * raises a step-up card naming exactly what is being added.
 *
 * This module is the pure core of that inversion. It holds no state, touches no network,
 * and imports nothing at runtime — every function is total over its inputs so it can be
 * unit-proven and reused by both the connect flow and the dispatch gate.
 *
 * Three details from §9 decide whether step-up actually works, and each is a function here:
 *
 *  1. **The union rule.** Not every provider supports incremental authorization. Where
 *     `scope_grant !== 'incremental'`, re-consenting with only the *new* scope silently
 *     drops the previously granted ones on several providers — "that single bug has broken
 *     a great many integrations." So the step-up request must be the UNION of already-granted
 *     and newly-needed scopes. Only a genuine `incremental` provider may request the delta
 *     alone. `unknown`/absent is treated conservatively as non-incremental → union.
 *
 *  2. **Granted is tracked, not assumed.** Deltas are computed against the scopes the
 *     provider *actually* granted (echoed in the token response / refreshed from the
 *     identity probe), never against what was requested — a provider may grant fewer scopes
 *     than asked for (a security-suite case in §13), and computing against the request would
 *     make the engine believe it holds a scope it does not. {@link trackGrantedScopes}
 *     encodes "reality, else what we already had; never the request."
 *
 *  3. **Step-up must be user-attributable.** A scope escalation triggered by content the
 *     assistant *read*, rather than by something the user *said or tapped*, is a
 *     privilege-escalation vector wearing a consent card. {@link planStepUp} refuses to
 *     escalate on an `assistant_content` trigger — the same provenance rule PREFLIGHT
 *     enforces on Tier-3 routing.
 */

/**
 * Whether granted scopes may differ from requested; `incremental` enables step-up (SPEC §1, §9).
 *
 * Defined locally rather than imported so this module is self-contained and needs no edit to
 * the shared `types.ts`. When the capability model lands the same union on `ProviderProfile`
 * as `ScopeGrant`, this can be swapped for `import type { ScopeGrant } from './types.ts'`
 * with no behavior change — the string values are identical.
 */
export type ScopeGrant = 'exact' | 'downgradeable' | 'incremental' | 'unknown';

/** The single field of a provider profile step-up reads — kept minimal to stay decoupled. */
export interface ScopeGrantCapability {
  scope_grant?: ScopeGrant;
}

/* ────────────────────────────── Tool scope annotation (§9) ────────────────────────────── */

/**
 * A tool's scope declaration, in the schema-annotation model PREFLIGHT uses for tiers and
 * provenance: `{ "name": "slack_send", "requires_scopes": ["chat:write"], "tier": 3 }`.
 * `requires_scopes` absent = the tool needs nothing beyond connect's minimum.
 */
export interface ToolScopeSpec {
  name: string;
  requires_scopes?: string[];
  tier?: number;
}

/* ─────────────────────────────── Step-up trigger provenance ─────────────────────────────── */

/**
 * Where a step-up escalation was initiated. `user_transcript` (the user said it) and
 * `user_tap` (the user tapped a control) are the only sources allowed to trigger an
 * escalation. `assistant_content` — the assistant decided a scope was needed after reading
 * some content — is refused: that is the privilege-escalation vector §9 names.
 */
export type StepUpAttribution = 'user_transcript' | 'user_tap' | 'assistant_content';

/**
 * The trigger record. `ref` is an opaque id (an utterance id, a tap event id) for the
 * credential-free auth-event log — never the content itself, which would defeat the point.
 */
export interface StepUpTrigger {
  attribution: StepUpAttribution;
  ref?: string;
}

const USER_ATTRIBUTABLE: ReadonlySet<StepUpAttribution> = new Set<StepUpAttribution>([
  'user_transcript',
  'user_tap',
]);

/** True iff this trigger traces to a user action, and so may drive a scope escalation. */
export function isUserAttributable(trigger: StepUpTrigger): boolean {
  return USER_ATTRIBUTABLE.has(trigger.attribution);
}

/* ─────────────────────────────────── Scope set algebra ─────────────────────────────────── */

/**
 * Canonical form of a scope list: trimmed, empties dropped, de-duplicated, lexicographically
 * sorted. Sorting is deliberate — two scope sets are equal iff their canonical forms are, and
 * the authorize URL should not change just because a tool listed its scopes in a new order.
 */
export function normalizeScopes(scopes: Iterable<string>): string[] {
  const out = new Set<string>();
  for (const raw of scopes) {
    if (typeof raw !== 'string') continue;
    const trimmed = raw.trim();
    if (trimmed.length > 0) out.add(trimmed);
  }
  return [...out].sort();
}

/** The union of every group, in canonical form. The heart of the union rule. */
export function unionScopes(...groups: Array<Iterable<string>>): string[] {
  const all: string[] = [];
  for (const group of groups) for (const s of group) all.push(s);
  return normalizeScopes(all);
}

/**
 * The scopes `required` needs that `granted` does not have, in canonical form. Empty means
 * every required scope is already held — no step-up. This is the "delta" §9 computes
 * *before dispatch*.
 */
export function computeScopeDelta(
  granted: Iterable<string>,
  required: Iterable<string>,
): string[] {
  const have = new Set(normalizeScopes(granted));
  const missing = new Set<string>();
  for (const raw of required) {
    if (typeof raw !== 'string') continue;
    const scope = raw.trim();
    if (scope.length > 0 && !have.has(scope)) missing.add(scope);
  }
  return [...missing].sort();
}

/** True iff every required scope is already granted (delta is empty). */
export function hasAllScopes(granted: Iterable<string>, required: Iterable<string>): boolean {
  return computeScopeDelta(granted, required).length === 0;
}

/** The union of `requires_scopes` across a batch of tools about to dispatch, canonical. */
export function requiredScopesForTools(tools: Iterable<ToolScopeSpec>): string[] {
  const all: string[] = [];
  for (const tool of tools) {
    for (const s of tool.requires_scopes ?? []) all.push(s);
  }
  return normalizeScopes(all);
}

/* ─────────────────────────────── Granted-scope tracking (§9) ─────────────────────────────── */

/**
 * Parse the scope set a provider *reported* it granted — the `scope`/`scopes` field a token
 * response or identity probe echoes back. Space- and comma-separated both appear live, so
 * both are split. Returns `undefined` (not `[]`) when the provider reported nothing at all,
 * so the caller can distinguish "granted zero scopes" from "did not tell us."
 */
export function parseGrantedScopes(
  reported: string | readonly string[] | null | undefined,
): string[] | undefined {
  if (reported === null || reported === undefined) return undefined;
  if (Array.isArray(reported)) return normalizeScopes(reported);
  if (typeof reported !== 'string') return undefined;
  if (reported.trim().length === 0) return undefined;
  return normalizeScopes(reported.split(/[\s,]+/));
}

/**
 * The actually-granted scope set to persist and to compute deltas against. The rule from §9,
 * verbatim: "Granted is tracked, not assumed" — prefer what the provider reported, fall back
 * to what we already held, and NEVER fall back to what was requested. Requested scopes are
 * deliberately not a parameter here: a provider that grants fewer scopes than asked (a §13
 * attack case) must leave `granted` at the smaller, real set, or the engine will believe it
 * holds a scope it does not and skip a step-up it needed.
 */
export function trackGrantedScopes(
  previousGranted: Iterable<string>,
  reported: string | readonly string[] | null | undefined,
): string[] {
  const fromProvider = parseGrantedScopes(reported);
  return fromProvider ?? normalizeScopes(previousGranted);
}

/* ─────────────────────────────────── Step-up planning ─────────────────────────────────── */

/** `incremental` = request the delta alone; `union` = re-request granted ∪ needed (the fix). */
export type StepUpMode = 'incremental' | 'union';

/**
 * The decision the dispatch gate acts on, computed BEFORE the tool call:
 *  - `satisfied`  every required scope is already granted → dispatch may proceed.
 *  - `refused`    scopes are missing but the trigger is not user-attributable → do NOT
 *                 escalate and do NOT dispatch (privilege-escalation guard).
 *  - `step_up`    scopes are missing and the escalation is legitimate → raise the card
 *                 requesting `requestScopes` (naming `addedScopes` to the user); block
 *                 dispatch until granted.
 */
export type StepUpDecision =
  | { kind: 'satisfied'; granted: string[] }
  | { kind: 'refused'; reason: 'not_user_attributable'; missing: string[] }
  | {
      kind: 'step_up';
      mode: StepUpMode;
      /** The exact scope set to send on the step-up authorize request. */
      requestScopes: string[];
      /** The scopes newly being added — what the consent card names to the user. */
      addedScopes: string[];
      /** The scope set already held, echoed for the auth-event log. */
      granted: string[];
    };

export interface StepUpRequest {
  /** `profile.scope_grant`. Absent/`unknown` is treated as non-incremental → union. */
  scopeGrant?: ScopeGrant;
  /** The ACTUALLY-granted scopes (from {@link trackGrantedScopes}), never the requested set. */
  grantedScopes: Iterable<string>;
  /** The scopes the tool(s) about to dispatch require (from {@link requiredScopesForTools}). */
  requiredScopes: Iterable<string>;
  /** Who initiated this escalation. Content-triggered escalations are refused. */
  trigger: StepUpTrigger;
}

/**
 * Compute the step-up decision for a dispatch, before the tool call runs.
 *
 * Order matters. The delta is checked first: if nothing is missing there is no escalation
 * to attribute, so an `assistant_content`-triggered call for scopes it already holds is
 * `satisfied`, not refused. Only when scopes are genuinely missing does the attribution gate
 * apply — a content trigger cannot mint new authority, a user trigger can.
 */
export function planStepUp(req: StepUpRequest): StepUpDecision {
  const granted = normalizeScopes(req.grantedScopes);
  const missing = computeScopeDelta(granted, req.requiredScopes);

  if (missing.length === 0) {
    return { kind: 'satisfied', granted };
  }

  if (!isUserAttributable(req.trigger)) {
    return { kind: 'refused', reason: 'not_user_attributable', missing };
  }

  // The union rule (§9): only a genuine `incremental` provider may request the delta alone.
  // Everything else — `exact`, `downgradeable`, `unknown`, absent — must re-request the union,
  // because re-consenting with only the new scope silently drops the old ones on several
  // providers. Conservative default is union: never drop a scope the user already granted.
  const mode: StepUpMode = req.scopeGrant === 'incremental' ? 'incremental' : 'union';
  const requestScopes = mode === 'incremental' ? missing : unionScopes(granted, req.requiredScopes);

  return { kind: 'step_up', mode, requestScopes, addedScopes: missing, granted };
}

/**
 * Convenience wrapper: plan a step-up straight from a provider profile and a batch of tools
 * about to dispatch. `granted` is the tracked, actually-granted set (e.g. the vaulted
 * `TokenRecord.scopes` passed through {@link trackGrantedScopes}).
 */
export function planStepUpForProfile(
  profile: ScopeGrantCapability,
  granted: Iterable<string>,
  tools: Iterable<ToolScopeSpec>,
  trigger: StepUpTrigger,
): StepUpDecision {
  return planStepUp({
    ...(profile.scope_grant === undefined ? {} : { scopeGrant: profile.scope_grant }),
    grantedScopes: granted,
    requiredScopes: requiredScopesForTools(tools),
    trigger,
  });
}

/** True iff the dispatch may proceed now — the single call the gate makes on a decision. */
export function mayDispatch(decision: StepUpDecision): boolean {
  return decision.kind === 'satisfied';
}
