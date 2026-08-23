/**
 * Writes every branded callback page to engine/assets/callback/ so Team J can
 * eyeball them in a browser without running the engine.
 *
 *   node --experimental-strip-types engine/scripts/render-callback-previews.mts
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderPage, type PageState } from '../src/ui/pages.ts';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..', 'assets', 'callback');
mkdirSync(out, { recursive: true });

const cases: Array<[PageState, Parameters<typeof renderPage>[1]]> = [
  ['success', { provider: 'Slack' }],
  ['denied', {}],
  ['mismatch', {}],
  [
    'provider_error',
    { provider: 'Slack', providerMessage: 'pkce_not_allowed: The app is not allowed to use the PKCE flow.' },
  ],
  ['timeout', {}],
];

for (const [state, opts] of cases) {
  const html = renderPage(state, opts);
  writeFileSync(join(out, `${state}.html`), html, 'utf8');
  console.log(`${state}.html  ${html.length} bytes`);
}
