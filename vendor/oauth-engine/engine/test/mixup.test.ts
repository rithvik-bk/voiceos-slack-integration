/**
 * C-3 tests — mix-up defense. The theorem under test: a response from provider A can never
 * satisfy a pending flow for provider B, by state-binding OR by RFC 9207 `iss`.
 *
 * Time is faked so the binding TTL is proven without a real wait.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { STATE_TTL_MS } from '../src/config.ts';
import { EngineError } from '../src/errors.ts';
import { assertFlow, bindFlow, checkFlow, clearFlow, clearFlows, pendingFlows } from '../src/mixup.ts';

beforeEach(() => {
  clearFlows();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  clearFlows();
});

const SLACK_ISS = 'https://slack.com';
const EVIL_ISS = 'https://attacker.example';

describe('state-bound-to-provider', () => {
  it('accepts a callback whose state belongs to the provider it arrived for', () => {
    bindFlow('state-A', 'slack');
    expect(checkFlow('state-A', 'slack', null)).toEqual({ ok: true });
  });

  it('refuses provider A\'s state arriving on provider B\'s listener (the mix-up)', () => {
    bindFlow('state-A', 'slack');
    bindFlow('state-B', 'zoom');
    // Slack's state, echoed at Zoom's listener: state matched *something*, but not this flow.
    expect(checkFlow('state-A', 'zoom', null)).toEqual({ ok: false, reason: 'wrong_provider' });
    // And the reverse.
    expect(checkFlow('state-B', 'slack', null)).toEqual({ ok: false, reason: 'wrong_provider' });
    // Each still satisfies its own flow.
    expect(checkFlow('state-A', 'slack', null)).toEqual({ ok: true });
    expect(checkFlow('state-B', 'zoom', null)).toEqual({ ok: true });
  });

  it('refuses a state no live flow owns', () => {
    expect(checkFlow('never-minted', 'slack', null)).toEqual({ ok: false, reason: 'unbound' });
  });

  it('refuses a binding that has aged past its TTL', () => {
    bindFlow('state-A', 'slack');
    expect(pendingFlows()).toBe(1);
    vi.advanceTimersByTime(STATE_TTL_MS + 1);
    expect(checkFlow('state-A', 'slack', null)).toEqual({ ok: false, reason: 'unbound' });
    expect(pendingFlows()).toBe(0);
  });
});

describe('RFC 9207 iss validation', () => {
  it('accepts a matching iss when the provider publishes an issuer', () => {
    bindFlow('state-A', 'slack', { issuer: SLACK_ISS, issRequired: true });
    expect(checkFlow('state-A', 'slack', SLACK_ISS)).toEqual({ ok: true });
  });

  it('refuses a different issuer even when state and provider line up (mix-up signature)', () => {
    bindFlow('state-A', 'slack', { issuer: SLACK_ISS, issRequired: true });
    // Attacker replayed Slack's state to Slack's listener but the response is from their AS.
    expect(checkFlow('state-A', 'slack', EVIL_ISS)).toEqual({ ok: false, reason: 'iss_mismatch' });
  });

  it('refuses a missing iss when the issuer is known', () => {
    bindFlow('state-A', 'slack', { issuer: SLACK_ISS, issRequired: true });
    expect(checkFlow('state-A', 'slack', null)).toEqual({ ok: false, reason: 'iss_missing' });
  });

  it('refuses a missing iss when the provider is documented to always send one', () => {
    // Issuer string not configured, but metadata says iss is always present: absence is attack.
    bindFlow('state-A', 'slack', { issRequired: true });
    expect(checkFlow('state-A', 'slack', null)).toEqual({ ok: false, reason: 'iss_missing' });
    // A present iss is accepted here (nothing to compare it against; state-binding still held).
    expect(checkFlow('state-A', 'slack', SLACK_ISS)).toEqual({ ok: true });
  });

  it('does not require iss for a provider that publishes neither issuer nor support flag', () => {
    // Reddit-style: no RFC 9207. State-binding alone governs; a stray iss is ignored.
    bindFlow('state-A', 'reddit');
    expect(checkFlow('state-A', 'reddit', null)).toEqual({ ok: true });
    expect(checkFlow('state-A', 'reddit', EVIL_ISS)).toEqual({ ok: true });
  });
});

describe('assertFlow (throwing form for the exchange path)', () => {
  it('returns silently on a clean match', () => {
    bindFlow('state-A', 'slack', { issuer: SLACK_ISS, issRequired: true });
    expect(() => assertFlow('state-A', 'slack', SLACK_ISS)).not.toThrow();
  });

  it('throws EngineError state_mismatch, carrying no secrets, on a mix-up', () => {
    bindFlow('state-A', 'slack', { issuer: SLACK_ISS, issRequired: true });
    try {
      assertFlow('state-A', 'slack', EVIL_ISS);
      expect.unreachable('assertFlow should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(EngineError);
      const engineError = error as EngineError;
      expect(engineError.code).toBe('state_mismatch');
      // Never leak the state, the iss value, or a code into the operator-facing strings.
      const emitted = `${engineError.message} ${engineError.hint}`;
      expect(emitted).not.toContain('state-A');
      expect(emitted).not.toContain(EVIL_ISS);
    }
  });

  it('throws on a wrong-provider callback', () => {
    bindFlow('state-A', 'slack');
    expect(() => assertFlow('state-A', 'zoom', null)).toThrow(EngineError);
  });

  it('throws on an unbound state', () => {
    expect(() => assertFlow('ghost', 'slack', null)).toThrow(EngineError);
  });
});

describe('lifecycle', () => {
  it('clearFlow forgets exactly one binding', () => {
    bindFlow('state-A', 'slack');
    bindFlow('state-B', 'zoom');
    clearFlow('state-A');
    expect(checkFlow('state-A', 'slack', null)).toEqual({ ok: false, reason: 'unbound' });
    expect(checkFlow('state-B', 'zoom', null)).toEqual({ ok: true });
  });
});
