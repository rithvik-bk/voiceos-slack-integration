/**
 * scope step-up tests (SPEC Part 4 §9).
 *
 * The three things §9 says decide whether step-up works are the three things proven hardest
 * here: the UNION rule (never drop a granted scope), the DELTA computed against reality, and
 * GRANTED tracked-not-assumed. The privilege-escalation guard (content cannot mint authority)
 * gets its own block because it is a security property, not a convenience.
 */

import { describe, expect, it } from 'vitest';

import {
  computeScopeDelta,
  hasAllScopes,
  isUserAttributable,
  mayDispatch,
  normalizeScopes,
  parseGrantedScopes,
  planStepUp,
  planStepUpForProfile,
  requiredScopesForTools,
  trackGrantedScopes,
  unionScopes,
  type StepUpTrigger,
} from '../src/scope.ts';

const USER: StepUpTrigger = { attribution: 'user_transcript', ref: 'utt-1' };
const CONTENT: StepUpTrigger = { attribution: 'assistant_content' };

describe('normalizeScopes', () => {
  it('trims, drops empties, de-dupes, and sorts', () => {
    expect(normalizeScopes(['chat:write', ' channels:read ', 'chat:write', ''])).toEqual([
      'channels:read',
      'chat:write',
    ]);
  });

  it('ignores non-string members without throwing', () => {
    expect(normalizeScopes(['a', undefined as unknown as string, 'b'])).toEqual(['a', 'b']);
  });
});

describe('computeScopeDelta', () => {
  it('returns only the scopes required-but-not-granted', () => {
    expect(computeScopeDelta(['channels:read'], ['channels:read', 'chat:write'])).toEqual([
      'chat:write',
    ]);
  });

  it('is empty when every required scope is already granted (superset ok)', () => {
    expect(computeScopeDelta(['a', 'b', 'c'], ['a', 'b'])).toEqual([]);
    expect(hasAllScopes(['a', 'b', 'c'], ['a', 'b'])).toBe(true);
  });

  it('is order- and duplicate-insensitive', () => {
    expect(computeScopeDelta(['b', 'a'], ['a', 'c', 'c', 'b'])).toEqual(['c']);
  });

  it('ignores whitespace and empty required entries', () => {
    expect(computeScopeDelta(['a'], [' a ', '', 'b'])).toEqual(['b']);
  });
});

describe('requiredScopesForTools', () => {
  it('unions requires_scopes across a batch of tools', () => {
    const tools = [
      { name: 'slack_search', requires_scopes: ['channels:read'] },
      { name: 'slack_send', requires_scopes: ['chat:write'], tier: 3 },
      { name: 'slack_noop' }, // no requires_scopes
    ];
    expect(requiredScopesForTools(tools)).toEqual(['channels:read', 'chat:write']);
  });

  it('is empty for tools that declare nothing', () => {
    expect(requiredScopesForTools([{ name: 'x' }, { name: 'y' }])).toEqual([]);
  });
});

describe('granted-vs-requested tracking', () => {
  it('parses a space- or comma-separated reported scope string', () => {
    expect(parseGrantedScopes('a b c')).toEqual(['a', 'b', 'c']);
    expect(parseGrantedScopes('a,b,c')).toEqual(['a', 'b', 'c']);
    expect(parseGrantedScopes(['b', 'a'])).toEqual(['a', 'b']);
  });

  it('distinguishes "reported nothing" (undefined) from "granted zero"', () => {
    expect(parseGrantedScopes(undefined)).toBeUndefined();
    expect(parseGrantedScopes(null)).toBeUndefined();
    expect(parseGrantedScopes('')).toBeUndefined();
    expect(parseGrantedScopes('   ')).toBeUndefined();
    // an explicit empty array IS a report — granted zero scopes
    expect(parseGrantedScopes([])).toEqual([]);
  });

  it('prefers the provider-reported set over what we previously held', () => {
    // provider actually granted FEWER than we had asked / thought → track the smaller reality
    expect(trackGrantedScopes(['a', 'b', 'c'], 'a b')).toEqual(['a', 'b']);
  });

  it('falls back to the previous set when the provider reports nothing', () => {
    expect(trackGrantedScopes(['a', 'b'], undefined)).toEqual(['a', 'b']);
  });

  it('NEVER assumes requested == granted: a scope-shy provider forces a step-up', () => {
    // Asked for chat:write, provider only granted channels:read and did echo it back.
    const granted = trackGrantedScopes([], 'channels:read');
    expect(granted).toEqual(['channels:read']);
    const decision = planStepUp({
      grantedScopes: granted,
      requiredScopes: ['chat:write'],
      trigger: USER,
    });
    expect(decision.kind).toBe('step_up');
  });
});

describe('the union rule (§9)', () => {
  it('unionScopes never drops a member of any group', () => {
    expect(unionScopes(['a', 'b'], ['b', 'c'])).toEqual(['a', 'b', 'c']);
  });

  it('non-incremental provider re-requests granted ∪ needed, never the delta alone', () => {
    const decision = planStepUp({
      scopeGrant: 'exact',
      grantedScopes: ['channels:read'],
      requiredScopes: ['chat:write'],
      trigger: USER,
    });
    expect(decision).toEqual({
      kind: 'step_up',
      mode: 'union',
      requestScopes: ['channels:read', 'chat:write'], // OLD scope carried, not dropped
      addedScopes: ['chat:write'],
      granted: ['channels:read'],
    });
  });

  it('treats absent/unknown scope_grant conservatively as union', () => {
    for (const scopeGrant of [undefined, 'unknown', 'downgradeable'] as const) {
      const decision = planStepUp({
        ...(scopeGrant === undefined ? {} : { scopeGrant }),
        grantedScopes: ['channels:read'],
        requiredScopes: ['chat:write'],
        trigger: USER,
      });
      expect(decision.kind).toBe('step_up');
      if (decision.kind === 'step_up') {
        expect(decision.mode).toBe('union');
        expect(decision.requestScopes).toEqual(['channels:read', 'chat:write']);
      }
    }
  });

  it('incremental provider requests the delta ALONE (the one case that may)', () => {
    const decision = planStepUp({
      scopeGrant: 'incremental',
      grantedScopes: ['channels:read'],
      requiredScopes: ['channels:read', 'chat:write'],
      trigger: USER,
    });
    expect(decision).toEqual({
      kind: 'step_up',
      mode: 'incremental',
      requestScopes: ['chat:write'], // delta only — provider merges it with existing grant
      addedScopes: ['chat:write'],
      granted: ['channels:read'],
    });
  });
});

describe('planStepUp — dispatch gate', () => {
  it('is satisfied (dispatch proceeds) when all required scopes are held', () => {
    const decision = planStepUp({
      scopeGrant: 'exact',
      grantedScopes: ['channels:read', 'chat:write'],
      requiredScopes: ['chat:write'],
      trigger: CONTENT, // even a content trigger is fine when no escalation is needed
    });
    expect(decision).toEqual({ kind: 'satisfied', granted: ['channels:read', 'chat:write'] });
    expect(mayDispatch(decision)).toBe(true);
  });

  it('mayDispatch is false for step_up and refused', () => {
    const stepUp = planStepUp({ grantedScopes: [], requiredScopes: ['x'], trigger: USER });
    const refused = planStepUp({ grantedScopes: [], requiredScopes: ['x'], trigger: CONTENT });
    expect(mayDispatch(stepUp)).toBe(false);
    expect(mayDispatch(refused)).toBe(false);
  });
});

describe('step-up must be user-attributable (§9 privilege-escalation guard)', () => {
  it('classifies triggers', () => {
    expect(isUserAttributable({ attribution: 'user_transcript' })).toBe(true);
    expect(isUserAttributable({ attribution: 'user_tap' })).toBe(true);
    expect(isUserAttributable({ attribution: 'assistant_content' })).toBe(false);
  });

  it('REFUSES a content-triggered escalation for a missing scope', () => {
    const decision = planStepUp({
      scopeGrant: 'exact',
      grantedScopes: ['channels:read'],
      requiredScopes: ['chat:write'],
      trigger: CONTENT,
    });
    expect(decision).toEqual({
      kind: 'refused',
      reason: 'not_user_attributable',
      missing: ['chat:write'],
    });
  });

  it('a content trigger does NOT refuse when scopes are already held (nothing to escalate)', () => {
    const decision = planStepUp({
      grantedScopes: ['chat:write'],
      requiredScopes: ['chat:write'],
      trigger: CONTENT,
    });
    expect(decision.kind).toBe('satisfied');
  });
});

describe('planStepUpForProfile', () => {
  it('drives the whole decision from a profile + tools + trigger', () => {
    const profile = { scope_grant: 'exact' as const };
    const tools = [
      { name: 'slack_search', requires_scopes: ['channels:read'] },
      { name: 'slack_send', requires_scopes: ['chat:write'], tier: 3 },
    ];
    const decision = planStepUpForProfile(profile, ['channels:read'], tools, USER);
    expect(decision).toEqual({
      kind: 'step_up',
      mode: 'union',
      requestScopes: ['channels:read', 'chat:write'],
      addedScopes: ['chat:write'],
      granted: ['channels:read'],
    });
  });

  it('is satisfied when the granted set already covers every tool', () => {
    const decision = planStepUpForProfile(
      { scope_grant: 'incremental' },
      ['channels:read', 'chat:write'],
      [{ name: 'slack_send', requires_scopes: ['chat:write'] }],
      USER,
    );
    expect(decision.kind).toBe('satisfied');
  });
});
