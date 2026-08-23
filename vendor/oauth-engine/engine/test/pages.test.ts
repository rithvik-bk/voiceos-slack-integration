/**
 * G5 — the five terminal callback pages, brought to final quality (SPEC §25/§28).
 *
 * This is the surface judged first: the browser page the user lands on after consent.
 * These tests pin the four things §25/§28 make hard requirements rather than a later
 * pass — each state DESIGNED (its own tone/glyph/copy), THEME-AWARE (light + dark),
 * ACCESSIBLE (reduced-motion, focus, contrast affordances), and PLAIN (one action, no
 * dead-end tab, no raw code/state/token/stack-trace in the user's face).
 *
 * They assert the DESIGNED TREATMENT of each state, not just that a string appears —
 * a page that renders the wrong tone band or drops the dark palette fails here.
 */

import { describe, expect, it } from 'vitest';

import { clip, esc, renderPage } from '../src/ui/pages.ts';
import type { PageState } from '../src/ui/pages.ts';

const STATES: PageState[] = ['success', 'denied', 'mismatch', 'timeout', 'provider_error'];

/** The tone band each state is designed to wear. The whole point is they differ. */
const TONE: Record<PageState, 'ok' | 'warn' | 'bad'> = {
  success: 'ok',
  denied: 'warn',
  timeout: 'warn',
  mismatch: 'bad',
  provider_error: 'bad',
};

describe('every terminal state renders its own designed treatment', () => {
  for (const state of STATES) {
    it(`${state}: branded, correct tone band, its own headline + one action`, () => {
      const html = renderPage(state);

      // Branded as VoiceOS, titled for this state, wearing the VoiceOS mark.
      expect(html).toContain('<b>VoiceOS</b>');
      expect(html).toMatch(/<title>[^<]+&middot; VoiceOS<\/title>/);

      // The DESIGNED tone band for this state — not defaulted, not shared with a
      // state of a different severity.
      expect(html).toContain(`class="card tone-${TONE[state]}"`);

      // ONE action available, and it is never a dead-end "close only" tab (§25):
      // there is always a primary button that hands back to the app.
      expect(html).toContain('class="btn"');
      expect(html).toContain(`voiceos://integrations/callback?status=${state}`);
      // Close stays as the honest secondary, as a real focusable button.
      expect(html).toContain('<button class="close" type="button"');
    });
  }

  it('gives success the app+provider handoff hero and its own return label', () => {
    const html = renderPage('success', { provider: 'Slack' });
    expect(html).toContain('Slack is connected.');
    expect(html).toContain('>Open VoiceOS<');
    // The success hero is the confirming green check glyph…
    expect(html).toContain('class="glyph"');
  });

  it('promotes success to the two-tile handoff when a provider mark is supplied', () => {
    const icon = 'data:image/png;base64,iVBORw0KGgoAAA==';
    const html = renderPage('success', { provider: 'Slack', providerIcon: icon });
    expect(html).toContain('class="tiles"');
    expect(html).toContain(icon);
  });

  it('labels every non-success return "Back to VoiceOS", never a bare close', () => {
    for (const state of STATES) {
      if (state === 'success') continue;
      expect(renderPage(state)).toContain('>Back to VoiceOS<');
    }
  });

  it('writes each state its own words — no state borrows another\'s copy', () => {
    const bodies = STATES.map((s) => renderPage(s));
    const unique = new Set(bodies);
    expect(unique.size).toBe(STATES.length);
    // The specific live confusion these pages once had.
    expect(renderPage('mismatch')).not.toEqual(renderPage('provider_error'));
  });
});

describe('theme-aware: light AND dark are shipped, not one committed look', () => {
  const html = renderPage('success');

  it('declares color-scheme so form UI and scrollbars follow the machine', () => {
    expect(html).toContain('<meta name="color-scheme" content="light dark">');
    expect(html).toContain('color-scheme:light dark');
  });

  it('carries a real dark palette behind prefers-color-scheme, not just light', () => {
    expect(html).toContain('@media (prefers-color-scheme:dark)');
    // The palette is tokenised and re-defined for dark — the card background flips.
    expect(html).toContain('--card:#FFFFFF'); // light
    expect(html).toContain('--card:#161619'); // dark override
  });

  it('drives every surface colour from a token, so the theme actually switches', () => {
    // If a colour were hard-coded it would ignore the dark override. Spot-check the
    // load-bearing surfaces resolve through vars.
    expect(html).toContain('background:var(--bg)');
    expect(html).toContain('background:var(--card)');
    expect(html).toContain('color:var(--ink)');
    expect(html).toContain('color:var(--ink-soft)');
  });
});

describe('accessible: not a later pass (SPEC §28)', () => {
  const html = renderPage('provider_error', { provider: 'Slack' });

  it('honours reduced motion by dropping the entrance animation', () => {
    expect(html).toContain('@media (prefers-reduced-motion:reduce)');
    expect(html).toMatch(/prefers-reduced-motion:reduce\)\{\.card\{animation:none\}/);
  });

  it('gives keyboard users a visible focus ring on both controls', () => {
    expect(html).toContain('.btn:focus-visible{outline:');
    expect(html).toContain('.close:focus-visible{outline:');
  });

  it('announces the outcome to assistive tech as a live status region', () => {
    expect(html).toContain('role="status"');
    expect(html).toContain('aria-live="polite"');
    expect(html).toContain('lang="en"');
  });

  it('marks the decorative hero aria-hidden so it is not read as content', () => {
    expect(html).toContain('aria-hidden="true"');
  });
});

describe('plain: never a stack trace, code, state or token in the user\'s face', () => {
  it('renders the provider\'s own human sentence, escaped and clipped', () => {
    const html = renderPage('provider_error', {
      provider: 'Slack',
      providerMessage: 'The workspace admin has restricted this app.',
    });
    expect(html).toContain('class="detail"');
    expect(html).toContain('The workspace admin has restricted this app.');
  });

  it('escapes a hostile provider name — no injected markup reaches the DOM', () => {
    const html = renderPage('provider_error', {
      provider: '<img src=x onerror=alert(1)>',
      providerMessage: 'code=4/abc state=xyz token=sk_live_123',
    });
    expect(html).not.toContain('<img');
    expect(html).toContain('&lt;img');
    // The provider string is shown only as escaped text, never as live markup.
    expect(html).not.toContain('onerror=alert(1)>');
  });

  it('clips a runaway provider blob so it can never blow the page open', () => {
    const huge = 'x'.repeat(5000);
    const html = renderPage('provider_error', { provider: 'Slack', providerMessage: huge });
    expect(html).not.toContain(huge);
    expect(html).toContain('…');
    expect(clip(huge).length).toBeLessThanOrEqual(200);
  });

  it('is fully self-contained — no external request of any kind', () => {
    for (const state of STATES) {
      const html = renderPage(state, {
        provider: 'Slack',
        providerIcon: 'data:image/png;base64,iVBORw0KGgoAAA==',
      });
      expect(html).not.toMatch(/https?:\/\//);
      expect(html).not.toContain('<link');
      expect(html).not.toMatch(/src=["'](?!data:)/);
    }
  });
});

describe('escaping/clip helpers hold their contract', () => {
  it('esc neutralises every HTML-significant character', () => {
    expect(esc(`<>&"'`)).toBe('&lt;&gt;&amp;&quot;&#39;');
  });
  it('clip is a no-op under budget and truncates over it', () => {
    expect(clip('short')).toBe('short');
    expect(clip('ab', 5)).toBe('ab');
    expect(clip('abcdef', 4)).toBe('abc…');
  });
});
