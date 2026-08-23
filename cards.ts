/**
 * THE CARD LAYER — the visual-parity gate.
 *
 * Every tool result this integration returns carries a rendered card, because users judge
 * by eye and a bare JSON string is what "unfinished" looks like. The bar is not "clean
 * text": it is *Slack, rendered natively inside VoiceOS*.
 *
 * Three rules hold this file honest:
 *
 *  1. **The kit renders, we compose.** `widgetKit.ts` is vendored verbatim from the app's own
 *     reference integrations (see the header of that file). It owns heights, the 128KB cap,
 *     the theme, the accent repair and the confirm-button reserve. Nothing here hand-rolls
 *     markup, and `renderCustom` is deliberately not used.
 *  2. **No sentence is written here.** Prose comes from the frozen deck (`copy.ts DECK`) —
 *     the card shows the words the user is hearing — and chrome comes from `copy.ts CARD`.
 *     `engine/test/slack-integration.test.ts` fails on an inline sentence in this file.
 *  3. **A card can never break a tool.** `glance()` catches everything and returns `null`;
 *     the server then sends the same result as plain text. A missing card is a worse demo;
 *     a thrown card is a dead tool.
 *
 * Nothing in a card is ever a credential: cards are rendered from the ToolResult, which is
 * the same object that already goes over the wire, and the read path's own test proves no
 * token reaches it.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  CARD,
  COMPOSER_CHROME,
  DECK,
  SCARD,
  SDECK,
  moreLine,
  notFoundLine,
  providerErrorLine,
  signedOutLine,
} from './copy.ts';
import * as COPY from './copy.ts';
import type { SurfaceState } from './copy.ts';
import {
  clip,
  esc,
  renderCustom,
  renderWidget,
  setIntegrationMark,
  textEms,
  vEmpty,
  vHeader,
  vHero,
  vKeyValue,
  vList,
  vNote,
} from './widgetKit.ts';
import type { Block, CardMode, RenderedWidget, RowItem, ThemeMode } from './widgetKit.ts';

/** Slack aubergine. The one hue this integration picks (UI bar §Mechanics). */
export const SLACK_ACCENT = '#4A154B';

/**
 * Phase-D chrome that `copy.ts` gains in its own lane (DESIGN-SPEC §4.4: `scheduled`,
 * `replying_to`, `needs_check`, `which_time`, `neutral_channel`, plus the `EMOJI_GLYPHS`
 * table). Read tolerantly: until those keys exist this file degrades to the nearest
 * already-ratified word (`kind_channel`, `needs_detail`) or omits the label entirely — it
 * never mints a word of its own, and it picks the new copy up the moment it ships.
 */
const PHASE_D_COPY = COPY as unknown as {
  EMOJI_GLYPHS?: Readonly<Record<string, string>>;
  SCARD: typeof SCARD &
    Partial<Record<'scheduled' | 'replying_to' | 'needs_check' | 'which_time' | 'neutral_channel', string>>;
};
const EMOJI_GLYPHS: Readonly<Record<string, string>> = PHASE_D_COPY.EMOJI_GLYPHS ?? {};
/** The neutral channel word (§4.5/M13): a specific `#general` guess would be a fabrication. */
const NEUTRAL_CHANNEL: string = PHASE_D_COPY.SCARD.neutral_channel ?? SCARD.kind_channel;
const NEEDS_CHECK: string = PHASE_D_COPY.SCARD.needs_check ?? SCARD.needs_detail;
const WHICH_TIME: string = PHASE_D_COPY.SCARD.which_time ?? SCARD.needs_detail;
const SCHEDULED_WORD: string | undefined = PHASE_D_COPY.SCARD.scheduled;
const REPLYING_TO_WORD: string | undefined = PHASE_D_COPY.SCARD.replying_to;

/**
 * A raw Slack machine id (`C0BQ4Q340AK`, `U…`, `D…`, `G…`, `W…`): uppercase, digit-bearing,
 * never a thing a human should read. The digit requirement keeps an all-caps display name
 * from tripping the guard. Definition-of-done rule 1: zero of these on any visible surface.
 */
const RAW_SLACK_ID = /^[CDGUW][A-Z0-9]{7,}$/;

function isRawId(value: string): boolean {
  return RAW_SLACK_ID.test(value) && /\d/.test(value);
}

/** A name field that turns out to be a machine id renders as no name at all — never the id. */
function guardName(name: string | undefined): string | undefined {
  return name !== undefined && isRawId(name) ? undefined : name;
}

/** A channel label that is only an id renders the neutral channel word — never the id. */
function guardChannel(label: string): string {
  return isRawId(label) ? NEUTRAL_CHANNEL : label;
}

const HERE = dirname(fileURLToPath(import.meta.url));

/* ───────────────────────────────── the integration mark ───────────────────────────────── */

let markLoaded = false;

/**
 * The logo slot, loaded once from the same `icon.png` the manifest and the consent screen
 * use — one artwork, three surfaces. The card sandbox has no network, so it ships inline as
 * a data URI; the kit caps it and silently draws the accent dot if anything is off.
 */
function ensureMark(): void {
  if (markLoaded) return;
  markLoaded = true;
  try {
    const png = readFileSync(join(HERE, 'icon.png'));
    setIntegrationMark(`data:image/png;base64,${png.toString('base64')}`);
  } catch {
    /* no mark — the kit falls back to the accent dot, which is a designed state */
  }
}

/* ────────────────────────────────── what a card knows ────────────────────────────────── */

/**
 * The workspace name, remembered from the last identity Slack itself reported in this
 * process. The read path never asks Slack "what workspace is this" — that would be a second
 * round trip on the read path's fastest beat — so the label appears once the connect or the
 * status probe has named it, and is simply absent before that. It is never guessed.
 */
let knownWorkspace: string | undefined;

/** Only ever fed from an identity the provider returned. */
export function rememberWorkspace(workspace: unknown): void {
  if (typeof workspace === 'string' && workspace !== '') knownWorkspace = workspace;
}

/** Test seam: forget what this process learned. */
export function forgetWorkspace(): void {
  knownWorkspace = undefined;
}

/**
 * The connected handle, remembered the same way the workspace is (§4.1): fed only from an
 * identity Slack itself reported, used only as the send preview's author fallback so the
 * pre-fire card shows the person who is actually about to send. Never guessed.
 */
let knownIdentity: string | undefined;

/** Only ever fed from an identity the provider returned. */
export function rememberIdentity(handle: unknown): void {
  if (typeof handle === 'string' && handle !== '' && !isRawId(handle)) knownIdentity = handle;
}

/** Test seam: forget everything this process learned about who and where it is. */
export function resetChrome(): void {
  knownWorkspace = undefined;
  knownIdentity = undefined;
}

/** The subset of a ToolResult a card is allowed to read. */
interface CardInput {
  state?: unknown;
  identity?: unknown;
  author?: unknown;
  text?: unknown;
  ts?: unknown;
  provider_message?: unknown;
  channel?: unknown;
  connect_id?: unknown;
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

function identityOf(result: CardInput): { handle?: string; workspace?: string } {
  const identity = result.identity;
  if (typeof identity !== 'object' || identity === null) return {};
  const shaped = identity as { handle?: unknown; workspace?: unknown };
  const handle = str(shaped.handle);
  const workspace = str(shaped.workspace);
  return {
    ...(handle === undefined ? {} : { handle }),
    ...(workspace === undefined ? {} : { workspace }),
  };
}

/**
 * `1755300000.000100` → `2:20 PM`. Slack timestamps are seconds-with-microseconds, and the
 * card shows the same wall-clock time the real Slack client shows. Unparseable → no stamp,
 * never a fabricated one.
 */
function slackTime(ts: unknown): string | undefined {
  const seconds = Number.parseFloat(String(ts ?? ''));
  if (!Number.isFinite(seconds) || seconds <= 0) return undefined;
  return new Date(seconds * 1000).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
}

/* ─────────────────────────────────── the card designs ─────────────────────────────────── */

/** Header trailing per state — the small right-aligned word that says where the flow is. */
const TRAILING: Record<SurfaceState, string> = {
  // Neutral word, not CARD.channel: a hard-coded "#general" on a card about some other
  // channel is a fabrication (§4.5 / GAP rank 10).
  message: NEUTRAL_CHANNEL,
  empty_channel: NEUTRAL_CHANNEL,
  connected: CARD.connected,
  needs_connect: CARD.not_connected,
  opening_browser: CARD.connecting,
  awaiting_consent: CARD.waiting,
  exchanging: CARD.verifying,
  denied_by_user: CARD.declined,
  expired_or_revoked: CARD.expired,
  port_blocked: CARD.blocked,
  state_mismatch: CARD.discarded,
  timeout: CARD.timed_out,
  provider_error: CARD.refused,
  browser_open_failed: CARD.unavailable,
  internal_fault: CARD.unavailable,
};

function header(state: SurfaceState, subtitle?: string): Block {
  return vHeader({
    title: CARD.title,
    trailing: TRAILING[state],
    ...(subtitle === undefined ? {} : { subtitle }),
  });
}

/**
 * The read card: the visual twin of the real Slack message.
 * Header = the workspace and the `#general` chip; body = the Slack message row (sender bold,
 * time small and right) with the message text underneath.
 */
function messageCard(result: CardInput, spoken: string): Block[] {
  const author = str(result.author);
  const text = str(result.text) ?? spoken;
  const time = slackTime(result.ts);
  return [
    header('message', knownWorkspace),
    vList([
      {
        title: author ?? CARD.title,
        ...(time === undefined ? {} : { trailing: time }),
      },
    ]),
    vNote(text),
  ];
}

/** The trust moment. Icon, "Slack connected", the handle, the workspace, the vault line. */
function connectedCard(result: CardInput): Block[] {
  const { handle, workspace } = identityOf(result);
  const shown = workspace ?? knownWorkspace;
  return [
    // No eyebrow: the kit already prepends the integration mark, and "Slack" above
    // "Slack connected" is the word twice.
    vHero({
      title: CARD.connected_heading,
      ...(handle === undefined ? {} : { subtitle: handle }),
    }),
    ...(shown === undefined ? [] : [vKeyValue([{ label: CARD.workspace_label, value: shown }])]),
    vNote(CARD.vault_note),
  ];
}

/** The profile strip: "Connected as @handle", the workspace, a green presence chip. */
function statusCard(result: CardInput, spoken: string): Block[] {
  const { handle, workspace } = identityOf(result);
  const shown = workspace ?? knownWorkspace;
  if (handle === undefined) return [header('connected', shown), vNote(spoken)];
  // The workspace is the header's subtitle, so the row carries the identity alone — Slack's
  // own profile strip does not print the workspace twice either.
  return [
    header('connected', shown),
    vList([{ title: handle, badge: { text: CARD.presence, tone: 'good' } }]),
  ];
}

/** Every non-happy state: the spoken sentence, plus the provider's own words when it spoke. */
function statefulCard(state: SurfaceState, result: CardInput, spoken: string): Block[] {
  const reason = str(result.provider_message);
  const blocks: Block[] = [header(state), vNote(spoken)];
  if (state === 'provider_error' && reason !== undefined) {
    blocks.push(vKeyValue([{ label: CARD.reason_label, value: reason, tone: 'bad' }]));
  }
  return blocks;
}

function blocksFor(state: SurfaceState, result: CardInput, spoken: string): Block[] {
  switch (state) {
    case 'message':
      return messageCard(result, spoken);
    case 'empty_channel':
      return [header('empty_channel', knownWorkspace), vEmpty({ title: CARD.empty_title, hint: spoken })];
    case 'connected':
      // The flow that just landed (it still carries its connect_id) gets the trust card;
      // a plain "am I connected" probe gets the profile strip.
      return str(result.connect_id) === undefined
        ? statusCard(result, spoken)
        : connectedCard(result);
    default:
      return statefulCard(state, result, spoken);
  }
}

/* ───────────────────────────────────── the entry point ───────────────────────────────────── */

/** A tool result, as much of it as a card is allowed to see. */
export interface Glanceable {
  spoken: string;
  [key: string]: unknown;
}

function isSurfaceState(value: unknown): value is SurfaceState {
  return typeof value === 'string' && (value === 'message' || value in DECK);
}

/**
 * Render the card for a tool result, or `null` when there is nothing designed to show.
 *
 * Never throws: the server falls back to the plain result, so the worst a broken card can
 * cost is the card. `providerErrorLine` is referenced so this module fails to compile if the
 * deck's one quoting row is ever renamed out from under the reason line above.
 */
export function glance(result: Glanceable, options: { theme?: ThemeMode } = {}): RenderedWidget | null {
  try {
    const state = result['state'];
    if (!isSurfaceState(state)) return null;
    const seen = identityOf(result as CardInput);
    rememberWorkspace(seen.workspace);
    rememberIdentity(seen.handle);
    ensureMark();
    const spoken = typeof result.spoken === 'string' ? result.spoken : providerErrorLine('unknown_error');
    return renderWidget({
      blocks: blocksFor(state, result as CardInput, spoken),
      accent: SLACK_ACCENT,
      label: CARD.title,
      // Omitted in production on purpose: the host decides the surface over `voiceos:init`.
      // Forced only by the preview sheet, so both surfaces can be judged before the room.
      ...(options.theme === undefined ? {} : { theme: options.theme }),
    });
  } catch {
    return null;
  }
}

/** The `_voiceos_glance` wire shape, verbatim from the app's own reference integrations. */
export function withCard(result: Glanceable): Record<string, unknown> {
  const card = glance(result);
  if (card === null) return { ...result };
  return {
    ...result,
    _voiceos_glance: { blocks: [{ type: 'widget', html: card.html, height: card.height }] },
  };
}

/* ═══════════════════════════════════════════════════════════════════════════════════════
 * PHASE S — THE SLACK REPLICA LAYER (B4, SLACK-UI-SPEC.md is law)
 *
 * The eleven frozen exports (`build-system/briefs/phaseS-common.md`):
 *   messageRow · digest · sendConfirm · connectedSuccess · notConnected · connectProgress ·
 *   errorCard · disconnected · searchResults · statusSet · emptyChannel
 *
 * ## The payload string (what every one of the eleven returns)
 * `JSON.stringify({ blocks: [{ type: 'widget', html, height }] })` — the exact value the
 * server spreads into the result as `_voiceos_glance` (`JSON.parse(card)`), the same wire
 * shape Phase 1 shipped and `cards.test.ts` pins. A card function NEVER throws: composition
 * failure degrades to a structured kit card, and if even that fails, to `''` (B2/B3's
 * `safeCard` treats `''` as "no card"), because a dead tool is worse than a missing card.
 *
 * ## Where the pixels come from
 * The five crown surfaces (messageRow, digest, sendConfirm, connectedSuccess,
 * searchResults) are `renderCustom` documents: a neutral `#1B1D21` Slack message pane (aubergine is chrome,
 * never content — UI-SPEC §2's #1 trap), 36px rounded-square colored-initial avatars,
 * 700-weight names sharing a baseline with `5:31 PM` timestamps, date-divider pills,
 * reaction chips, the raspberry unread badge, and the official 4-color Slack pinwheel in
 * the header. Everything else rides `renderWidget` blocks — robustness over theater in
 * failure paths (UI-SPEC §4).
 *
 * ## Honesty rules (same as Phase 1, enforced by engine/test/slack-cards-s.test.ts)
 * Every provider string passes `esc()` + `clip()`. No name, timestamp, or message is ever
 * fabricated: a missing author renders a neutral avatar and no name line; a missing ts
 * renders no stamp; a missing workspace renders no workspace. No sentence is written here —
 * prose comes from `copy.ts` (`SDECK`/`DECK`), chrome words from `SCARD`/`CARD`.
 * ═══════════════════════════════════════════════════════════════════════════════════════ */

/* ───────────────────────────── palette + replica stylesheet ───────────────────────────── */

/**
 * Slack default-avatar family (UI-SPEC §4.2, R2 §2.1). Deterministic per name — the same
 * person is the same color on every card of every session. Each hue carries a precomputed
 * 8%-darker bottom stop for the 2-stop vertical gradient (frozen pairs, CARDS-SPEC-R2).
 */
const AVATAR_PALETTE: ReadonlyArray<readonly [top: string, bottom: string]> = [
  ['#E01E5A', '#CE1C53'],
  ['#36C5F0', '#32B5DD'],
  ['#2EB67D', '#2AA773'],
  ['#ECB22E', '#D9A42A'],
  ['#611F69', '#591D61'],
  ['#1264A3', '#115C96'],
  ['#E8912D', '#D58529'],
  ['#7C2852', '#72254B'],
] as const;

/**
 * The replica tokens (UI-SPEC §1.2/§1.3), dark-first with the light overrides riding
 * `html[data-k-theme=light]` exactly like the kit's own variables — theme is bridge-driven,
 * never `prefers-color-scheme`. Values sampled from the VoiceOS HQ screenshots.
 */
const SK_CSS = `
:root{--sk-pane:#1B1D21;--sk-ink:#D1D2D3;--sk-name:#FFFFFF;--sk-time:#9B9C9E;--sk-line:#35373B;--sk-link:#1D9BD1;--sk-badge:#E01E5A;--sk-green:#2BAC76;--sk-sel:#5D3B63;--sk-mention:rgba(29,155,209,.1);--sk-hover:rgba(255,255,255,.03);--sk-chip:#222529}
html[data-k-theme=light]{--sk-pane:#FFFFFF;--sk-ink:#1D1C1D;--sk-name:#1D1C1D;--sk-time:#616061;--sk-line:#DDDDDD;--sk-link:#1264A3;--sk-hover:rgba(0,0,0,.04);--sk-mention:rgba(18,100,163,.1);--sk-chip:#F8F8F8}
.sk-wrap{padding:12px 14px 14px;display:flex;flex-direction:column;gap:6px;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","Helvetica Neue","Segoe UI",sans-serif}
.sk-hd{display:flex;align-items:center;gap:7px;min-width:0}
.sk-logo{width:16px;height:16px;display:block;flex:none}
.sk-hd-t{font-size:13px;font-weight:700;color:var(--sk-name);flex:none}
.sk-hd-r{margin-left:auto;display:flex;align-items:center;gap:6px;min-width:0}
.sk-hd-ch{display:inline-flex;align-items:center;font-size:11.5px;font-weight:600;color:var(--sk-link);background:var(--sk-mention);border-radius:4px;padding:1px 7px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:160px;flex:none}
.sk-hd-ch .sk-h{opacity:.7;margin-right:1px}
.sk-hd-ws{font-size:11px;color:var(--sk-time);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
.sk-pane{background:transparent;border-radius:12px;padding:6px 11px 6px 0;display:flex;flex-direction:column;border:1px solid transparent}
html[data-k-theme=light] .sk-pane{border-color:transparent}
.sk-div{display:flex;align-items:center;margin:0 0 3px}
.sk-div:before,.sk-div:after{content:"";flex:1;height:1px;background:var(--sk-line)}
.sk-pill{font-size:12px;font-weight:700;color:var(--sk-name);border:1px solid var(--sk-line);border-radius:999px;padding:2px 10px;margin:0 8px;background:transparent;white-space:nowrap;flex:none}
.sk-pill i{font-style:normal;font-size:9px;opacity:.7;margin-left:3px}
.sk-row{display:flex;gap:8px;padding:4px 6px;margin:0 -6px;border-radius:6px;align-items:flex-start}
.sk-row:hover{background:var(--sk-hover)}
.sk-av{width:36px;height:36px;border-radius:6px;flex:none;position:relative;margin-top:2px}
.sk-av img{width:100%;height:100%;border-radius:6px;display:block}
.sk-av i{position:absolute;right:-3px;bottom:-3px;width:8px;height:8px;border-radius:50%;background:var(--sk-green);border:2px solid var(--sk-pane)}
.sk-m{min-width:0;flex:1}
.sk-nl{display:flex;align-items:baseline;gap:8px;min-width:0}
.sk-n{font-size:15px;font-weight:700;color:var(--sk-name);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sk-t{font-size:12px;color:var(--sk-time);flex:none}
.sk-b{font-size:15px;line-height:1.46;color:var(--sk-ink);overflow:hidden;display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:3;overflow-wrap:anywhere}
.sk-b2{-webkit-line-clamp:2}
.sk-b4{-webkit-line-clamp:4}
.sk-lnk{color:var(--sk-link)}
.sk-men{color:var(--sk-link);background:var(--sk-mention);border-radius:3px;padding:0 2px}
.sk-h{opacity:.7}
.sk-code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:87%;color:var(--sk-badge);background:var(--sk-chip);border:1px solid var(--sk-line);border-radius:3px;padding:0 3px}
.sk-rx{display:flex;gap:4px;margin-top:5px;flex-wrap:wrap}
.sk-rxc{display:inline-flex;align-items:center;gap:4px;font-size:12px;color:var(--sk-ink);background:var(--sk-chip);border:1px solid var(--sk-line);border-radius:999px;padding:1px 8px}
.sk-rxc.sk-me{border-color:rgba(29,155,209,.4)}
.sk-g{display:flex;flex-direction:column}
.sk-gh{display:flex;align-items:center;gap:8px;padding:3px 6px;margin:0 -6px;border-radius:6px;cursor:pointer}
.sk-gh:hover{background:var(--sk-hover)}
.sk-gt{font-size:14px;font-weight:700;color:var(--sk-name);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sk-bd{margin-left:auto;min-width:17px;text-align:center;font-size:11px;font-weight:700;color:#fff;background:var(--sk-badge);border-radius:999px;padding:1px 6px;flex:none}
.sk-g:not(.sk-open) .sk-gb{display:none}
.sk-sm .sk-av{width:28px;height:28px}
.sk-sm .sk-av i{width:7px;height:7px;right:-2px;bottom:-2px}
.sk-sm .sk-n{font-size:14px}
.sk-sm .sk-b{font-size:14px;-webkit-line-clamp:2}
.sk-more{font-size:12px;color:var(--sk-time);padding-top:3px;text-align:right}
.sk-ctx{display:flex;align-items:baseline;gap:8px;font-size:12px;color:var(--sk-time);padding:3px 6px 0;margin:0 -6px}
.sk-ctx-t{margin-left:auto;flex:none}
.sk-q{font-size:13px;color:var(--sk-time);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sk-to{display:flex;align-items:center;gap:6px}
.sk-to-w{font-size:12px;color:var(--sk-time);flex:none}
.sk-to-ch{display:inline-flex;align-items:center;font-size:13px;font-weight:700;color:var(--sk-link);background:var(--sk-mention);border-radius:4px;padding:3px 10px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sk-to-ch .sk-h{opacity:.7;margin-right:1px}
.sk-to-p{display:inline-flex;align-items:center;gap:6px;font-size:13px;font-weight:700;color:var(--sk-name);background:var(--sk-chip);border:1px solid var(--sk-line);border-radius:999px;padding:2px 10px 2px 3px;min-width:0}
.sk-to-p img{width:20px;height:20px;border-radius:5px;flex:none}
.sk-id2{font-size:12.5px;color:var(--sk-time);margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sk-sched{display:inline-flex;align-items:center;gap:5px;align-self:flex-start;font-size:12px;font-weight:600;color:var(--sk-time);border:1px solid var(--sk-line);border-radius:999px;padding:2px 10px;white-space:nowrap}
.sk-att{display:inline-flex;align-items:center;gap:5px;align-self:flex-start;font-size:12.5px;color:var(--sk-ink);background:var(--sk-chip);border:1px solid var(--sk-line);border-radius:6px;padding:3px 9px;margin:0 0 4px;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sk-quote{font-size:12.5px;color:var(--sk-time);border-left:2px solid var(--sk-line);padding:1px 0 1px 8px;margin:0 0 4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sk-ok{margin-left:auto;font-size:12px;font-weight:600;color:var(--sk-green);flex:none;padding-left:8px}
.sk-note{font-size:12.5px;line-height:1.4;color:var(--ink-3)}
`;

/**
 * The official Slack pinwheel, inlined (UI-SPEC checklist: the real mark, small, in the
 * header). Wrapped in the kit's `data-k-mk` anchor so `renderCustom` never floats a second
 * mark and the host swap still has its slot.
 */
const SLACK_LOGO_SVG =
  `<span class="k-mk" data-k-mk><svg class="sk-logo" viewBox="0 0 122.8 122.8" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">` +
  `<path d="M25.8 77.6c0 7.1-5.8 12.9-12.9 12.9S0 84.7 0 77.6s5.8-12.9 12.9-12.9h12.9v12.9zm6.5 0c0-7.1 5.8-12.9 12.9-12.9s12.9 5.8 12.9 12.9v32.3c0 7.1-5.8 12.9-12.9 12.9s-12.9-5.8-12.9-12.9V77.6z" fill="#E01E5A"/>` +
  `<path d="M45.2 25.8c-7.1 0-12.9-5.8-12.9-12.9S38.1 0 45.2 0s12.9 5.8 12.9 12.9v12.9H45.2zm0 6.5c7.1 0 12.9 5.8 12.9 12.9s-5.8 12.9-12.9 12.9H12.9C5.8 58.1 0 52.3 0 45.2s5.8-12.9 12.9-12.9h32.3z" fill="#36C5F0"/>` +
  `<path d="M97 45.2c0-7.1 5.8-12.9 12.9-12.9s12.9 5.8 12.9 12.9-5.8 12.9-12.9 12.9H97V45.2zm-6.5 0c0 7.1-5.8 12.9-12.9 12.9s-12.9-5.8-12.9-12.9V12.9C64.7 5.8 70.5 0 77.6 0s12.9 5.8 12.9 12.9v32.3z" fill="#2EB67D"/>` +
  `<path d="M77.6 97c7.1 0 12.9 5.8 12.9 12.9s-5.8 12.9-12.9 12.9-12.9-5.8-12.9-12.9V97h12.9zm0-6.5c-7.1 0-12.9-5.8-12.9-12.9s5.8-12.9 12.9-12.9h32.3c7.1 0 12.9 5.8 12.9 12.9s-5.8 12.9-12.9 12.9H77.6z" fill="#ECB22E"/>` +
  `</svg></span>`;

/* ─────────────────────────────── deterministic little pieces ─────────────────────────────── */

function hashName(name: string): number {
  let hash = 0;
  for (const char of name) hash = (hash * 31 + (char.codePointAt(0) ?? 0)) >>> 0;
  return hash;
}

/**
 * Intentional-looking initials (R2 §2.1): multi-word name → first char of first word +
 * first char of last word, both upper ("Rithvik Kumar" → "RK"); single-word name → first
 * char upper + second char lower ("Rithvik" → "Ri"). Empty after the guard → '' — the
 * caller renders the placeholder square; initials are never fabricated.
 */
function initialsOf(name: string): string {
  const words = name
    .trim()
    .split(/\s+/)
    .filter((word) => word !== '');
  if (words.length === 0) return '';
  if (words.length > 1) {
    const first = [...(words[0] as string)][0] ?? '';
    const last = [...(words[words.length - 1] as string)][0] ?? '';
    return (first + last).toUpperCase();
  }
  const chars = [...(words[0] as string)];
  const first = (chars[0] ?? '').toUpperCase();
  const second = (chars[1] ?? '').toLowerCase();
  return first + second;
}

/**
 * Colored-initial rounded-square avatar as an inline SVG data URI (~350B — R2 §2.1):
 * Slack's rounding (`rx="16"` on the 72-unit box → reads right at 36px) over a 2-stop
 * vertical gradient. Placeholders pass the same hue twice — a flat square, same geometry.
 */
function avatarSquareUri(top: string, bottom: string, glyph: string): string {
  const svg =
    `<svg xmlns='http://www.w3.org/2000/svg' width='72' height='72'>` +
    `<defs><linearGradient id='g' x1='0' y1='0' x2='0' y2='1'>` +
    `<stop offset='0' stop-color='${top}'/><stop offset='1' stop-color='${bottom}'/>` +
    `</linearGradient></defs>` +
    `<rect width='72' height='72' rx='16' fill='url(#g)'/>` +
    `<text x='36' y='${glyph.length > 1 ? 46 : 47}' font-size='${glyph.length > 1 ? 27 : 32}' font-weight='700' font-family='-apple-system,sans-serif' fill='%23fff' text-anchor='middle'>${glyph}</text>` +
    `</svg>`;
  return `data:image/svg+xml,${svg.replaceAll('#', '%23')}`;
}

/**
 * The nameless placeholder comes in two tones: the quiet grey dot for read surfaces, and —
 * `accent: true`, used only by sendConfirm and connectedSuccess (§4.1) — the Slack-accent
 * square with a white `@`. Both are visibly not a person: initials are never fabricated.
 * A named avatar hashes the DISPLAY label (post-guard) into the frozen 8-pair palette.
 */
function avatarUri(name: string | undefined, options: { accent?: boolean } = {}): string {
  const label = guardName(name) ?? '';
  const glyph = label === '' ? '' : initialsOf(label);
  if (glyph === '') {
    return options.accent === true
      ? avatarSquareUri(SLACK_ACCENT, SLACK_ACCENT, '@')
      : avatarSquareUri('#616061', '#616061', '•');
  }
  const pair = AVATAR_PALETTE[hashName(label) % AVATAR_PALETTE.length] ?? AVATAR_PALETTE[0];
  const [top, bottom] = pair as readonly [string, string];
  return avatarSquareUri(top, bottom, glyph);
}

/** The channel chip (§4.6/M17): accent-tinted rounded square, white `#`, avatar geometry. */
function hashChipUri(): string {
  return avatarSquareUri(SLACK_ACCENT, SLACK_ACCENT, '#');
}

/** `5:31 PM` — 12-hour, no leading zero, space before AM/PM, locale pinned (UI-SPEC §1.4). */
function skTime(ts: unknown): string | undefined {
  const seconds = Number.parseFloat(String(ts ?? ''));
  if (!Number.isFinite(seconds) || seconds <= 0) return undefined;
  return new Date(seconds * 1000).toLocaleTimeString('en-US', {
    hour: 'numeric',
    minute: '2-digit',
  });
}

function sameDay(a: Date, b: Date): boolean {
  return (
    a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate()
  );
}

/** Date-pill word: nothing for today, `Yesterday`, else `Aug 16` — never an invented date. */
function dayLabel(ts: unknown, now: number = Date.now()): string | undefined {
  const seconds = Number.parseFloat(String(ts ?? ''));
  if (!Number.isFinite(seconds) || seconds <= 0) return undefined;
  const then = new Date(seconds * 1000);
  if (sameDay(then, new Date(now))) return undefined;
  if (sameDay(then, new Date(now - 86_400_000))) return SCARD.yesterday;
  return then.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

/** Search-row stamp: today → `5:31 PM`; this week → `Mon`; older → `Aug 12` (UI-SPEC §3.9). */
function dayOrTime(ts: unknown, now: number = Date.now()): string | undefined {
  const seconds = Number.parseFloat(String(ts ?? ''));
  if (!Number.isFinite(seconds) || seconds <= 0) return undefined;
  const then = new Date(seconds * 1000);
  if (sameDay(then, new Date(now))) return skTime(ts);
  if (now - seconds * 1000 < 6 * 86_400_000)
    return then.toLocaleDateString('en-US', { weekday: 'short' });
  return then.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

/** `#general` → `# general` with a thin space, `#` slightly muted where HTML is available. */
function channelText(rawLabel: string): string {
  // A label that is only a machine id renders the neutral channel word, never the id.
  const label = guardChannel(rawLabel);
  return label.startsWith('#') ? `# ${label.slice(1)}` : label;
}

function channelHtml(label: string): string {
  const safe = esc(clip(guardChannel(label), 60));
  return safe.startsWith('#')
    ? `<span class="sk-h">#</span> ${safe.slice(1)}`
    : safe;
}

/** Pill interior: `#`-leading labels render the muted `#` glyph, everything else plain. */
function pillLabelHtml(label: string, max: number): string {
  const safe = esc(clip(guardChannel(label), max));
  return safe.startsWith('#') ? `<span class="sk-h">#</span>${safe.slice(1)}` : safe;
}

/**
 * Safe minimal mrkdwn (R2 §2.3): a single-pass token walk over an ALREADY-`esc()`-ed body.
 * It may emit ONLY compile-time literal tags — `<b>`, `<i>`, `<s>`,
 * `<code class="sk-code">`, `<span class="sk-lnk">`, `<span class="sk-men">` — so no
 * provider byte can ever smuggle markup. Code spans first (their content is exempt from
 * further replacement); then `*bold*` / `_italic_` / `~strike~` with boundary rules (a
 * marker opens only after start/whitespace/`(` and before non-space, closes only after
 * non-space, never crosses a newline; unmatched markers render verbatim); then mention,
 * channel and URL decoration outside code spans. Nothing is added, removed, or reworded.
 */
const MRKDWN_MARKS: ReadonlyArray<readonly [RegExp, string]> = [
  [/(^|[\s(])\*([^\s*\n](?:[^*\n]*[^\s*\n])?)\*/g, 'b'],
  [/(^|[\s(])_([^\s_\n](?:[^_\n]*[^\s_\n])?)_/g, 'i'],
  [/(^|[\s(])~([^\s~\n](?:[^~\n]*[^\s~\n])?)~/g, 's'],
] as const;

function decorate(escaped: string): string {
  const stash: string[] = [];
  let text = escaped.replace(/`([^`\n]+)`/g, (_whole, code: string) => {
    stash.push(`<code class="sk-code">${code}</code>`);
    return `\x00${stash.length - 1}\x00`;
  });
  for (const [pattern, tag] of MRKDWN_MARKS) {
    text = text.replace(pattern, (_whole, lead: string, inner: string) =>
      tag === 'b'
        ? `${lead}<b>${inner}</b>`
        : tag === 'i'
          ? `${lead}<i>${inner}</i>`
          : `${lead}<s>${inner}</s>`,
    );
  }
  text = text
    .replace(/https?:\/\/[^\s\x00]+/g, (url) => `<span class="sk-lnk">${url}</span>`)
    .replace(/(^|[\s(])(@[\w][\w.\-]*)/g, (_whole, lead: string, tag: string) => `${lead}<span class="sk-men">${tag}</span>`)
    .replace(/(^|[\s(])(#[\w][\w\-]*)/g, (_whole, lead: string, tag: string) => `${lead}<span class="sk-men">${tag}</span>`);
  return text.replace(/\x00(\d+)\x00/g, (_whole, index: string) => stash[Number(index)] ?? '');
}

/* ─────────────────────────────── the message-row template ─────────────────────────────── */

/** One message, as loosely as a tool may hand it over. Everything optional, nothing trusted. */
export interface SkMessage {
  author?: string | undefined;
  author_id?: string | undefined;
  text?: string | undefined;
  ts?: string | number | undefined;
  /** Both producer shapes are legal (§4.2): `emoji ?? name`, `me ?? reacted`. */
  reactions?:
    | Array<{ emoji?: string; name?: string; count?: number; me?: boolean; reacted?: boolean }>
    | undefined;
}

const BODY_CLIP = 600;
/** ems per line at 15px on the ~292px text column (420 notch − chrome − avatar). */
const EMS_MD = 19;
const EMS_SM = 21;

function bodyLines(text: string, perLine: number, maxLines: number): number {
  return Math.max(1, Math.min(maxLines, Math.ceil(textEms(text) / perLine)));
}

/**
 * A reaction, whichever producer shape it arrived in (§4.2): the glyph from `EMOJI_GLYPHS`
 * when the name is known, the honest compact `:name:` when it is not, the character itself
 * when the producer already sent a glyph.
 */
function reactionGlyph(raw: string): string {
  const key = raw.replace(/^:+|:+$/g, '');
  const glyph = EMOJI_GLYPHS[key];
  if (glyph !== undefined) return glyph;
  if (/^[A-Za-z0-9_+-]+$/.test(key)) return `:${key}:`;
  return raw;
}

function reactionEmoji(entry: { emoji?: string; name?: string } | undefined): string | undefined {
  const raw = str(entry?.emoji) ?? str(entry?.name);
  return raw === undefined ? undefined : raw;
}

function reactionChips(message: SkMessage): string {
  const entries = (Array.isArray(message.reactions) ? message.reactions : [])
    .filter((entry) => reactionEmoji(entry) !== undefined)
    .slice(0, 6);
  if (entries.length === 0) return '';
  const chips = entries
    .map((entry) => {
      const count = typeof entry.count === 'number' && entry.count > 0 ? entry.count : 1;
      const mine = entry.me ?? entry.reacted;
      const shown = reactionGlyph(reactionEmoji(entry) as string);
      return `<span class="sk-rxc${mine === true ? ' sk-me' : ''}">${esc(clip(shown, 24))} ${count}</span>`;
    })
    .join('');
  return `<div class="sk-rx">${chips}</div>`;
}

/**
 * The literal Slack row: 36px rounded-square avatar, 700 name + gray `5:31 PM` on one
 * baseline, body under the name at the 44px column (UI-SPEC §1.4). `small` is the digest
 * density (28px avatar, 14px body, 2-line clamp). Missing author → placeholder avatar and
 * no name line; missing ts → no stamp. `presence` draws the green dot (identity rows only).
 */
function rowHtml(
  message: SkMessage,
  options: {
    small?: boolean;
    presence?: boolean;
    clampLines?: number;
    accentAvatar?: boolean;
    /** Small muted word trailing the name line (find() rows: the candidate kind). */
    trailingWord?: string;
  } = {},
): string {
  const author = guardName(str(message.author));
  const time = skTime(message.ts);
  const text = typeof message.text === 'string' ? clip(message.text, BODY_CLIP) : '';
  const clampClass = options.clampLines === 4 ? ' sk-b4' : options.clampLines === 2 ? ' sk-b2' : '';
  const nameBits: string[] = [];
  if (author !== undefined) nameBits.push(`<span class="sk-n">${esc(clip(author, 40))}</span>`);
  if (time !== undefined) nameBits.push(`<span class="sk-t">${esc(time)}</span>`);
  if (options.trailingWord !== undefined)
    nameBits.push(`<span class="sk-t">${esc(clip(options.trailingWord, 16))}</span>`);
  const nameLine = nameBits.length > 0 ? `<div class="sk-nl">${nameBits.join('')}</div>` : '';
  const body = text === '' ? '' : `<div class="sk-b${clampClass}">${decorate(esc(text))}</div>`;
  const avatar = avatarUri(author, { accent: options.accentAvatar === true });
  return (
    `<div class="sk-row${options.small === true ? ' sk-sm' : ''}">` +
    `<span class="sk-av"><img src="${avatar}" alt=""/>${options.presence === true ? '<i></i>' : ''}</span>` +
    `<div class="sk-m">${nameLine}${body}${reactionChips(message)}</div>` +
    `</div>`
  );
}

function rowHeight(message: SkMessage, small: boolean, clampLines?: number): number {
  const text = typeof message.text === 'string' ? clip(message.text, BODY_CLIP) : '';
  const perLine = small ? EMS_SM : EMS_MD;
  const maxLines = clampLines ?? (small ? 2 : 3);
  const lines = text === '' ? 0 : bodyLines(text, perLine, maxLines);
  const lineHeight = small ? 19 : 22;
  const nameLine = 20;
  const reactions =
    Array.isArray(message.reactions) && message.reactions.some((entry) => reactionEmoji(entry) !== undefined)
      ? 27
      : 0;
  return Math.max(small ? 34 : 42, nameLine + lines * lineHeight + reactions) + 8;
}

function datePillHtml(ts: unknown): string {
  const label = dayLabel(ts);
  if (label === undefined) return '';
  return `<div class="sk-div"><span class="sk-pill">${esc(label)}<i>▾</i></span></div>`;
}

/* ─────────────────────────────── composition + the payload ─────────────────────────────── */

const HEADER_H = 26;
const WRAP_V = 26;
const PANE_V = 14;
const GAP = 6;

/**
 * The shared header band (R2 §1): colored pinwheel + proper-case "Slack" wordmark on the
 * left; on the right, TWO independent elements — the conversation as a blue-tint pill (or a
 * muted non-conversation word) and the workspace, muted, clipped independently. Never one
 * joined string, never both `conversation` and `word`.
 */
function skHeader(scope: {
  /** Conversation label: '#general', 'Maya', group-DM name. Renders the pill. */
  conversation?: string | undefined;
  /** Muted word for non-conversation surfaces: 'Confirm send', 'Connected', 'Results'. */
  word?: string | undefined;
  /** Workspace name, muted, clipped independently. */
  workspace?: string | undefined;
}): string {
  const conversation = str(scope.conversation);
  const word = str(scope.word);
  const workspace = str(scope.workspace);
  const right: string[] = [];
  if (conversation !== undefined) {
    // The render-layer net: a raw machine id never reaches the pill — it degrades to the
    // neutral channel word, styled as a word, because a pill saying "Channel" would read
    // as a channel literally named Channel.
    if (isRawId(conversation)) {
      right.push(`<span class="sk-hd-ws">${esc(clip(NEUTRAL_CHANNEL, 24))}</span>`);
    } else {
      right.push(`<span class="sk-hd-ch">${pillLabelHtml(conversation, 24)}</span>`);
    }
  } else if (word !== undefined) {
    right.push(`<span class="sk-hd-ws">${esc(clip(word, 24))}</span>`);
  }
  if (workspace !== undefined) right.push(`<span class="sk-hd-ws">${esc(clip(workspace, 20))}</span>`);
  return (
    `<div class="sk-hd">${SLACK_LOGO_SVG}<span class="sk-hd-t">${esc(CARD.title)}</span>` +
    `<span class="sk-hd-r">${right.join('')}</span></div>`
  );
}

function pack(widget: RenderedWidget): string {
  return JSON.stringify({ blocks: [{ type: 'widget', html: widget.html, height: widget.height }] });
}

function packBlocks(blocks: Block[]): string {
  return pack(renderWidget({ blocks, accent: SLACK_ACCENT, label: CARD.title }));
}

function packCustom(body: string, height: number, mode?: CardMode): string {
  return pack(
    renderCustom({
      body: `<div class="sk-wrap">${body}</div>`,
      css: SK_CSS,
      accent: SLACK_ACCENT,
      label: CARD.title,
      height,
      ...(mode === undefined ? {} : { mode }),
    }),
  );
}

/**
 * Never let a card break a tool (kit rule 7): bespoke composition that throws degrades to a
 * structured kit card; a structured card that throws degrades to no card at all (`''` —
 * the callers' `safeCard` shape for "render nothing").
 */
function guarded(compose: () => string, fallbackTrailing: string): string {
  try {
    /** Before any block is built, so the very first widget card already carries the mark. */
    ensureMark();
    return compose();
  } catch {
    try {
      return packBlocks([vHeader({ title: CARD.title, trailing: fallbackTrailing })]);
    } catch {
      return '';
    }
  }
}

function rec(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
}

/* ═══════════════════════════════ the eleven frozen exports ═══════════════════════════════ */

/** UI-SPEC §3.2 — the hero read surface: one verbatim Slack message row. */
export interface MessageRowData extends SkMessage {
  channel?: string | undefined;
  workspace?: string | undefined;
}

export function messageRow(data: MessageRowData): string {
  return guarded(() => {
    const input = rec(data) as MessageRowData;
    const pill = datePillHtml(input.ts);
    const row = rowHtml(input);
    const body =
      skHeader({
        conversation: str(input.channel),
        workspace: str(input.workspace) ?? knownWorkspace,
      }) +
      `<div class="sk-pane">${pill}${row}</div>`;
    const height =
      WRAP_V + HEADER_H + GAP + PANE_V + (pill === '' ? 0 : 24) + rowHeight(input, false);
    return packCustom(body, height);
  }, NEUTRAL_CHANNEL);
}

/** UI-SPEC §3.3 — the catch-up digest: channel groups, date pills, dense rows, unread badges. */
export interface DigestGroup {
  channel?: string | undefined;
  kind?: string | undefined;
  count?: number | undefined;
  mentions?: number | undefined;
  messages?: SkMessage[] | undefined;
}

export interface DigestData {
  workspace?: string | undefined;
  groups?: DigestGroup[] | undefined;
  more?: { messages?: number; conversations?: number } | undefined;
}

const DIGEST_GROUPS_OPEN = 2;
const DIGEST_GROUPS_MAX = 4;
const DIGEST_ROWS = 3;

/**
 * Accordion (the one sanctioned interaction): tap a channel header to swap which group is
 * open. Tapping the already-open group is a no-op — the card can never reach a zero-open
 * state, because a digest with every group collapsed is an empty card.
 */
const DIGEST_JS =
  `<script>document.addEventListener("click",function(e){` +
  `var t=e.target;while(t&&t!==document.body&&!(t.classList&&t.classList.contains("sk-gh")))t=t.parentNode;` +
  `if(!t||t===document.body)return;var g=t.parentNode;if(g.classList.contains("sk-open"))return;` +
  `var all=document.querySelectorAll(".sk-g");for(var i=0;i<all.length;i++)all[i].classList.remove("sk-open");` +
  `g.classList.add("sk-open");})</script>`;

export function digest(data: DigestData): string {
  return guarded(() => {
    const input = rec(data) as DigestData;
    const groups = (Array.isArray(input.groups) ? input.groups : []).slice(0, DIGEST_GROUPS_MAX);
    const shownMessages = (group: DigestGroup): SkMessage[] =>
      (Array.isArray(group.messages) ? group.messages : []).slice(-DIGEST_ROWS);

    let height = WRAP_V + HEADER_H + GAP + PANE_V;
    const rendered = groups
      .map((group, index) => {
        const open = index < DIGEST_GROUPS_OPEN;
        const label = str(group.channel) ?? '';
        const messages = shownMessages(group);
        const badge =
          typeof group.count === 'number' && group.count > 0
            ? `<span class="sk-bd">${Math.min(group.count, 99)}</span>`
            : '';
        const newest = messages[messages.length - 1];
        const pill = open ? datePillHtml(newest?.ts) : '';
        const rows = messages.map((message) => rowHtml(message, { small: true })).join('');
        height += 26;
        if (open) {
          height += (pill === '' ? 0 : 24) + messages.reduce((sum, m) => sum + rowHeight(m, true), 0);
        }
        return (
          `<div class="sk-g${open ? ' sk-open' : ''}">` +
          `<div class="sk-gh"><span class="sk-gt">${channelHtml(label)}</span>${badge}</div>` +
          `<div class="sk-gb">${pill}${rows}</div>` +
          `</div>`
        );
      })
      .join('');

    const more = rec(input.more);
    const hidden = typeof more['messages'] === 'number' ? more['messages'] : 0;
    const extraConversations =
      (typeof more['conversations'] === 'number' ? more['conversations'] : 0) +
      Math.max(0, (Array.isArray(input.groups) ? input.groups.length : 0) - DIGEST_GROUPS_MAX);
    const moreHtml =
      hidden > 0 ? `<div class="sk-more">${esc(moreLine(hidden, extraConversations))}</div>` : '';
    if (moreHtml !== '') height += 22;

    const empty = groups.length === 0;
    if (empty) {
      return packBlocks([
        vHeader({ title: CARD.title, trailing: SCARD.catch_up }),
        vEmpty({ title: CARD.empty_title }),
      ]);
    }

    const body =
      skHeader({ word: SCARD.catch_up, workspace: str(input.workspace) ?? knownWorkspace }) +
      `<div class="sk-pane">${rendered}${moreHtml}</div>` +
      (groups.length > 1 ? DIGEST_JS : '');
    return packCustom(body, Math.min(height, 420));
  }, SCARD.catch_up);
}

/** UI-SPEC §3.4 — the pre-fire preview: destination pill + the message AS IT WILL LAND. */
export interface SendConfirmData extends SkMessage {
  destination?: string | undefined;
  kind?: string | undefined;
  workspace?: string | undefined;
  /** Unix seconds a scheduled send will land (§4.1) — renders the schedule chip, never a fake row stamp. */
  scheduled_ts?: string | number | undefined;
  /** Upload attachment name + size (§4.1) — the raw path never renders. */
  filename?: string | undefined;
  bytes?: number | undefined;
  /** Thread-reply context (§4.1) — one muted quote line above the reply. */
  thread_root_author?: string | undefined;
  thread_root_text?: string | undefined;
}

/** `2.1 MB` — B, KB, MB with one decimal, capped at GB. Nothing renders for a nonsense size. */
function formatBytes(bytes: number): string | undefined {
  if (!Number.isFinite(bytes) || bytes <= 0) return undefined;
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
}

export function sendConfirm(data: SendConfirmData): string {
  return guarded(() => {
    const input = rec(data) as SendConfirmData;
    const rawDestination = str(input.destination) ?? '';
    const destIsId = rawDestination !== '' && isRawId(rawDestination);
    const destination = destIsId ? NEUTRAL_CHANNEL : rawDestination;
    const isDm = (input.kind === 'dm' || input.kind === 'person') && !destIsId;
    const workspace = str(input.workspace) ?? knownWorkspace;
    /**
     * Destination (R2 §3.3): muted "To" word + the header's blue-tint pill language one
     * size up for channels, or the neutral person chip (20px avatar + name) for DMs. The
     * aubergine destination pill and its `▸` glyph are retired; workspace moved to the header.
     */
    const destHtml = isDm
      ? `<span class="sk-to-p"><img src="${avatarUri(destination)}" alt=""/>${esc(clip(destination, 32))}</span>`
      : `<span class="sk-to-ch">${pillLabelHtml(destination, 32)}</span>`;
    const toRow = `<div class="sk-to"><span class="sk-to-w">${esc(COMPOSER_CHROME.to)}</span>${destHtml}</div>`;

    /**
     * Timestamp honesty (§4.1): a landed send shows its provider ts; a scheduled send shows
     * the schedule chip and NO row stamp; anything else shows no stamp at all. The old
     * `Date.now()` fallback was a fabricated timestamp and is gone.
     */
    const landed = skTime(input.ts) !== undefined;
    const schedStamp = landed ? undefined : dayOrTime(input.scheduled_ts);
    const schedChip =
      schedStamp === undefined
        ? ''
        : `<span class="sk-sched">⏱ ${
            SCHEDULED_WORD === undefined ? '' : `${esc(SCHEDULED_WORD)} · `
          }${esc(schedStamp)}</span>`;

    /** Attachment chip (§4.1): name + size, never the path. */
    const filename = str(input.filename);
    const size = typeof input.bytes === 'number' ? formatBytes(input.bytes) : undefined;
    const attachChip =
      filename === undefined
        ? ''
        : `<div class="sk-att">📎 ${esc(clip(filename, 44))}${
            size === undefined ? '' : ` · ${esc(size)}`
          }</div>`;

    /** Thread context (§4.1): one muted clamped quote line above the reply. */
    const rootText = str(input.thread_root_text);
    const rootAuthor = guardName(str(input.thread_root_author));
    const quote =
      rootText === undefined
        ? ''
        : `<div class="sk-quote">${
            REPLYING_TO_WORD === undefined ? '' : `${esc(REPLYING_TO_WORD)} `
          }${esc(clip(rootAuthor === undefined ? rootText : `${rootAuthor}: ${rootText}`, 80))}</div>`;

    /** Author fallback chain (§4.1): the tool's author, else the connected identity, else the accent placeholder. */
    const author = guardName(str(input.author)) ?? knownIdentity;
    const message: SkMessage = { ...input, author, ...(landed ? {} : { ts: undefined }) };
    const row = rowHtml(message, { clampLines: 4, accentAvatar: true });
    const body =
      skHeader({ word: SCARD.confirm_send, workspace }) +
      toRow +
      schedChip +
      `<div class="sk-pane">${attachChip}${quote}${row}</div>`;
    /** Manual confirm reserve: mode:"confirm" pads the bottom 52px and the bottom-right 164×44 stays empty. */
    const height =
      WRAP_V +
      HEADER_H +
      GAP +
      26 +
      (schedChip === '' ? 0 : 24 + GAP) +
      GAP +
      PANE_V +
      (attachChip === '' ? 0 : 26) +
      (quote === '' ? 0 : 20) +
      rowHeight(message, false, 4) +
      52;
    return packCustom(body, height, 'confirm');
  }, SCARD.confirm_send);
}

/** UI-SPEC §3.1 — the trust moment: a real Slack identity row + the vault line. */
export interface ConnectedSuccessData {
  handle?: string | undefined;
  workspace?: string | undefined;
  /** Slack's own presence word. The green dot renders ONLY when this is `'active'` (P1-11). */
  presence?: string | undefined;
  state?: string | undefined;
  spoken?: string | undefined;
}

export function connectedSuccess(data: ConnectedSuccessData): string {
  return guarded(() => {
    const input = rec(data) as ConnectedSuccessData;
    const handle = guardName(str(input.handle));
    const workspace = str(input.workspace) ?? knownWorkspace;
    rememberWorkspace(workspace);
    rememberIdentity(handle);
    const name = handle ?? CARD.connected_heading;
    const second = workspace === undefined ? '' : `<div class="sk-id2">${esc(clip(workspace, 40))}</div>`;
    const dot = str(input.presence) === 'active' ? '<i></i>' : '';
    const row =
      `<div class="sk-row">` +
      `<span class="sk-av"><img src="${avatarUri(handle, { accent: true })}" alt=""/>${dot}</span>` +
      `<div class="sk-m"><div class="sk-nl"><span class="sk-n">${esc(clip(name, 40))}</span>` +
      `<span class="sk-ok">✓ ${esc(CARD.connected)}</span></div>${second}</div>` +
      `</div>`;
    const body =
      skHeader({ word: CARD.connected, workspace }) +
      `<div class="sk-pane">${row}</div>` +
      `<div class="sk-note">${esc(CARD.vault_note)}</div>`;
    const height = WRAP_V + HEADER_H + GAP + PANE_V + 50 + GAP + 18;
    return packCustom(body, height);
  }, CARD.connected);
}

/** UI-SPEC §3.5 — no Slack content exists yet, so the honest structured empty state. */
export function notConnected(_data?: unknown): string {
  return guarded(
    () =>
      packBlocks([
        vHeader({ title: CARD.title, trailing: CARD.not_connected }),
        vEmpty({ title: SDECK.not_connected, hint: SDECK.not_connected_hint }),
      ]),
    CARD.not_connected,
  );
}

/** UI-SPEC §3.6 — transient connect states, straight onto Phase-1 chrome words. */
export interface ConnectProgressData {
  state?: string | undefined;
  spoken?: string | undefined;
  workspace?: string | undefined;
}

export function connectProgress(data: ConnectProgressData): string {
  return guarded(() => {
    const input = rec(data) as ConnectProgressData;
    const state = str(input.state);
    const trailing =
      state === 'awaiting_consent'
        ? CARD.waiting
        : state === 'exchanging'
          ? CARD.verifying
          : CARD.connecting;
    const workspace = str(input.workspace);
    return packBlocks([
      vHeader({ title: CARD.title, trailing }),
      vNote(str(input.spoken) ?? SDECK.approve_hint),
      ...(workspace === undefined
        ? []
        : [vKeyValue([{ label: CARD.workspace_label, value: workspace }])]),
    ]);
  }, CARD.connecting);
}

/**
 * UI-SPEC §3.7 — one template, tuned per failure. Reads either B2/B3's `kind` rows
 * (`rate_limited` / `provider_error` / `missing_parameter` / `target_not_found` /
 * `ambiguous_target`) or a lifecycle `state`, and always shows the provider's own words
 * when it spoke. Disambiguation candidates render as say-able rows, never a silent guess.
 */
export interface ErrorCardData {
  kind?: string | undefined;
  state?: string | undefined;
  spoken?: string | undefined;
  reason?: string | undefined;
  parameter?: string | undefined;
  query?: string | undefined;
  retry_after?: number | undefined;
  /** Widened (§4.4): T2's plain `string[]` candidates are legal and render as say-able rows. */
  candidates?: Array<{ label?: string; kind?: string } | string> | undefined;
}

/** Preflight kinds that share the neutral "needs a check" template (§4.4) — never "Refused". */
const NEEDS_CHECK_KINDS = new Set([
  'invalid_emoji',
  'ungrounded_message',
  'file_not_found',
  'not_in_channel',
  'preflight',
]);

const KIND_WORDS: Record<string, string> = {
  channel: SCARD.kind_channel,
  person: SCARD.kind_person,
  dm: SCARD.kind_dm,
  group_dm: SCARD.kind_group_dm,
};

export function errorCard(data: ErrorCardData): string {
  return guarded(() => {
    const input = rec(data) as ErrorCardData;
    const rawKind = str(input.kind) ?? str(input.state) ?? 'provider_error';
    /** Preflight misses route to the not-found template (§4.4) — a resolver miss is not a refusal. */
    const kind =
      rawKind === 'channel_not_found' || rawKind === 'user_not_found' ? 'target_not_found' : rawKind;
    const spoken = str(input.spoken);

    if (kind === 'rate_limited' || kind === 'ratelimited') {
      const retry = typeof input.retry_after === 'number' && input.retry_after > 0 ? input.retry_after : undefined;
      return packBlocks([
        vHeader({ title: CARD.title, trailing: SCARD.rate_limited }),
        vNote(spoken ?? SDECK.slow_down),
        ...(retry === undefined
          ? []
          : [vKeyValue([{ label: SCARD.try_again_label, value: `${Math.round(retry)}s` }])]),
      ]);
    }

    if (kind === 'missing_parameter') {
      return packBlocks([
        vHeader({ title: CARD.title, trailing: SCARD.needs_detail }),
        vNote(spoken ?? SDECK.missing_detail),
        ...(str(input.parameter) === undefined
          ? []
          : [vKeyValue([{ label: SCARD.missing_label, value: str(input.parameter) as string }])]),
      ]);
    }

    if (kind === 'target_not_found' || kind === 'ambiguous_target') {
      const query = str(input.query) ?? '';
      const candidates = (Array.isArray(input.candidates) ? input.candidates : [])
        .map((candidate) =>
          typeof candidate === 'string'
            ? { label: candidate, kind: '' }
            : {
                label: str(rec(candidate)['label']) ?? '',
                kind: str(rec(candidate)['kind']) ?? '',
              },
        )
        .filter((candidate) => candidate.label !== '');
      const rows: RowItem[] = candidates.map((candidate) => ({
        title: channelText(candidate.label),
        image: avatarUri(candidate.label.startsWith('#') ? undefined : candidate.label),
        ...(KIND_WORDS[candidate.kind] === undefined
          ? {}
          : { badge: { text: KIND_WORDS[candidate.kind] as string } }),
      }));
      return packBlocks([
        vHeader({
          title: CARD.title,
          trailing: kind === 'target_not_found' ? SCARD.not_found : SCARD.choose,
        }),
        vNote(kind === 'target_not_found' ? notFoundLine(channelText(query)) : SDECK.which_one),
        ...(rows.length === 0 ? [] : [vList(rows)]),
      ]);
    }

    if (kind === 'ambiguous_time') {
      /** The schedule's time phrase did not parse (§4.4): ask which time, never "Refused". */
      const phrase = str(input.query) ?? str(input.parameter);
      return packBlocks([
        vHeader({ title: CARD.title, trailing: WHICH_TIME }),
        vNote(spoken ?? SDECK.missing_detail),
        ...(phrase === undefined
          ? []
          : [vKeyValue([{ label: WHICH_TIME, value: clip(guardChannel(phrase), 60) }])]),
      ]);
    }

    if (NEEDS_CHECK_KINDS.has(kind)) {
      /** Shared preflight template (§4.4): neutral trailing, the spoken line, the offending value. */
      const offending = str(input.query) ?? str(input.parameter) ?? str(input.reason);
      return packBlocks([
        vHeader({ title: CARD.title, trailing: NEEDS_CHECK }),
        vNote(spoken ?? SDECK.missing_detail),
        ...(offending === undefined
          ? []
          : [vKeyValue([{ label: NEEDS_CHECK, value: clip(guardChannel(offending), 60) }])]),
      ]);
    }

    if (kind === 'expired_or_revoked') {
      return packBlocks([
        vHeader({ title: CARD.title, trailing: CARD.expired }),
        vNote(spoken ?? DECK.expired_or_revoked),
      ]);
    }

    if (kind === 'browser_open_failed') {
      return packBlocks([
        vHeader({ title: CARD.title, trailing: CARD.unavailable }),
        vNote(spoken ?? DECK.browser_open_failed),
      ]);
    }

    /** provider_error and anything unrecognized: the refusal, quoting Slack verbatim. */
    const reason = str(input.reason);
    return packBlocks([
      vHeader({ title: CARD.title, trailing: CARD.refused }),
      vNote(spoken ?? SDECK.refused_short),
      ...(reason === undefined
        ? []
        : [vKeyValue([{ label: CARD.reason_label, value: reason, tone: 'bad' }])]),
    ]);
  }, CARD.refused);
}

/** UI-SPEC §3.8 — calm, neutral, honest about the vault. Disconnecting is not an error. */
export interface DisconnectedData {
  workspace?: string | undefined;
  /** Resolved display name of the identity that just signed out (P2-13) — never an id. */
  handle?: string | undefined;
  spoken?: string | undefined;
}

export function disconnected(data?: DisconnectedData): string {
  return guarded(() => {
    const input = rec(data) as DisconnectedData;
    const workspace = str(input.workspace) ?? knownWorkspace;
    const handle = guardName(str(input.handle));
    /** Signed-out line: `@Rithvik · VoiceOS HQ` when the handle exists (middot join, P2-13). */
    const who =
      handle === undefined
        ? undefined
        : `@${clip(handle, 32)}${workspace === undefined ? '' : ` · ${clip(workspace, 28)}`}`;
    return packBlocks([
      vHeader({ title: CARD.title, trailing: SCARD.disconnected }),
      vNote(who ?? str(input.spoken) ?? signedOutLine(workspace)),
      vNote(SDECK.tokens_deleted),
    ]);
  }, SCARD.disconnected);
}

/**
 * R2 §3.5 — search + find results, rebuilt on the activity-feed anatomy (`renderCustom`):
 * each message hit is a muted context line — `in #channel` left, relative time right —
 * above a real 36px message row (2-line clamp). The author is the row's bold name, the
 * channel lives ONLY in the context line, the time ONLY in `.sk-ctx-t`; no joined titles,
 * no dash separators of any kind. `find()` person rows are atom rows without a context
 * line, the kind word small and muted on the name line; `find()` channel rows are the
 * hash-chip avatar with `#name` as the bold title. 5-row cap + the `+N more` line kept;
 * an empty result set stays the honest kit empty state.
 */
export interface SearchResultsData {
  query?: string | undefined;
  workspace?: string | undefined;
  results?:
    | Array<{
        author?: string;
        channel?: string;
        text?: string;
        ts?: string | number;
        kind?: string;
      }>
    | undefined;
  more?: number | undefined;
}

export function searchResults(data: SearchResultsData): string {
  return guarded(() => {
    const input = rec(data) as SearchResultsData;
    const query = str(input.query) ?? '';
    const results = (Array.isArray(input.results) ? input.results : []).slice(0, 5);

    if (results.length === 0) {
      return packBlocks([
        vHeader({
          title: CARD.title,
          trailing: SCARD.results,
          ...(query === '' ? {} : { subtitle: `“${clip(query, 56)}”` }),
        }),
        vEmpty({ title: CARD.empty_title }),
      ]);
    }

    let height = WRAP_V + HEADER_H + GAP + PANE_V;
    const sub = query === '' ? '' : `<div class="sk-q">“${esc(clip(query, 56))}”</div>`;
    if (sub !== '') height += 20 + GAP;

    const rows = results
      .map((entry) => {
        const item = rec(entry);
        const author = guardName(str(item['author']));
        const channel = str(item['channel']);
        const text = str(item['text']);
        const rowKind = str(item['kind']) ?? '';
        const kindWord = KIND_WORDS[rowKind];
        const isChannelRow =
          rowKind === 'channel' ||
          (author === undefined && channel !== undefined && channelText(channel).startsWith('#'));

        if (isChannelRow) {
          /**
           * find() channel row: hash chip + `#name` bold title (§4.6/M17). The label rides
           * whichever field the producer used — search hits carry `channel`, find()
           * candidates carry the label in `author` (`candidateSummary.name`), so the title
           * takes the first one present rather than rendering a nameless chip.
           */
          const label = channel ?? str(item['author']) ?? '';
          const stamp = dayOrTime(item['ts']);
          height += 50;
          return (
            `<div class="sk-row">` +
            `<span class="sk-av"><img src="${hashChipUri()}" alt=""/></span>` +
            `<div class="sk-m"><div class="sk-nl"><span class="sk-n">${pillLabelHtml(label, 40)}</span>` +
            `${stamp === undefined ? '' : `<span class="sk-t">${esc(stamp)}</span>`}</div></div>` +
            `</div>`
          );
        }

        if (kindWord !== undefined) {
          /** find() person/DM row: plain atom row, the kind word muted on the name line. */
          const message: SkMessage = {
            author: author ?? guardName(channel),
            ...(text === undefined ? {} : { text }),
            ts: item['ts'] as string | number | undefined,
          };
          height += rowHeight(message, false, 2);
          return rowHtml(message, { clampLines: 2, trailingWord: kindWord });
        }

        /** Message hit: context line above the atom row; time lives only in the context line. */
        const stamp = dayOrTime(item['ts']);
        const ctxBits: string[] = [];
        if (channel !== undefined && channel !== '') {
          ctxBits.push(`<span class="sk-ctx-l">in ${pillLabelHtml(channel, 24)}</span>`);
        }
        if (stamp !== undefined) ctxBits.push(`<span class="sk-ctx-t">${esc(stamp)}</span>`);
        const ctx = ctxBits.length === 0 ? '' : `<div class="sk-ctx">${ctxBits.join('')}</div>`;
        const message: SkMessage = {
          author,
          ...(text === undefined ? {} : { text }),
          ts: undefined,
        };
        height += (ctx === '' ? 0 : 18) + rowHeight(message, false, 2);
        return ctx + rowHtml(message, { clampLines: 2 });
      })
      .join('');

    const more = typeof input.more === 'number' && input.more > 0 ? input.more : 0;
    const moreHtml = more > 0 ? `<div class="sk-more">${esc(moreLine(more, 0))}</div>` : '';
    if (moreHtml !== '') height += 22;

    const body =
      skHeader({ word: SCARD.results, workspace: str(input.workspace) ?? knownWorkspace }) +
      sub +
      `<div class="sk-pane">${rows}${moreHtml}</div>`;
    return packCustom(body, Math.min(height, 420));
  }, SCARD.results);
}

/** UI-SPEC §3.10 — status the way Slack renders it: emoji first, expiry trailing. */
export interface StatusSetData {
  /** `'reminder'` branches to the reminder surface (R2 §3.6); anything else is status/DND. */
  kind?: string | undefined;
  text?: string | undefined;
  status?: string | undefined;
  emoji?: string | undefined;
  until?: string | undefined;
  expiration?: number | undefined;
  /** Alias producers use for `expiration` (§4.3), unix seconds. */
  expires_at?: number | undefined;
  snooze_minutes?: number | undefined;
  /** DND end as unix seconds (§4.3) — renders `until 3:45 PM` via skTime. */
  snooze_until?: number | undefined;
  spoken?: string | undefined;
}

/**
 * The status emoji for the title (§4.3): the character itself passes through, a known name
 * becomes its glyph, an unknown name is omitted entirely — a raw `:code:` never leads the title.
 */
function statusGlyph(emoji: string | undefined): string | undefined {
  if (emoji === undefined) return undefined;
  const key = emoji.replace(/^:+|:+$/g, '');
  if (/^[A-Za-z0-9_+-]+$/.test(key)) return EMOJI_GLYPHS[key];
  return emoji;
}

export function statusSet(data: StatusSetData): string {
  return guarded(() => {
    const input = rec(data) as StatusSetData;
    if (str(input.kind) === 'reminder') {
      /** Reminder surface (R2 §3.6): the reminder text as the row, `⏰` + when it fires. */
      const reminderText = str(input.text) ?? '';
      const when =
        typeof input.expires_at === 'number' && input.expires_at > 0
          ? dayOrTime(input.expires_at)
          : undefined;
      return packBlocks([
        vHeader({ title: CARD.title, trailing: SCARD.reminder }),
        ...(reminderText === ''
          ? [vNote(str(input.spoken) ?? SDECK.missing_detail)]
          : [
              vList([
                {
                  title: reminderText,
                  ...(when === undefined ? {} : { trailing: `⏰ ${when}` }),
                },
              ]),
            ]),
      ]);
    }
    const text = str(input.text) ?? str(input.status) ?? '';
    const emoji = statusGlyph(str(input.emoji));
    const title = [emoji, text].filter((part) => part !== undefined && part !== '').join(' ');
    const expiry =
      typeof input.expiration === 'number' && input.expiration > 0
        ? input.expiration
        : typeof input.expires_at === 'number' && input.expires_at > 0
          ? input.expires_at
          : undefined;
    const until = str(input.until) ?? (expiry === undefined ? undefined : skTime(expiry));
    const snooze =
      typeof input.snooze_minutes === 'number' && input.snooze_minutes > 0
        ? Math.round(input.snooze_minutes)
        : undefined;
    const snoozeUntil =
      snooze === undefined && typeof input.snooze_until === 'number' && input.snooze_until > 0
        ? skTime(input.snooze_until)
        : undefined;
    const rows: RowItem[] = [];
    if (title !== '') {
      rows.push({ title, ...(until === undefined ? {} : { trailing: `${SCARD.until} ${until}` }) });
    }
    if (snooze !== undefined) {
      rows.push({ title: SCARD.dnd_label, trailing: `${snooze} ${SCARD.minutes_suffix}` });
    } else if (snoozeUntil !== undefined) {
      rows.push({ title: SCARD.dnd_label, trailing: `${SCARD.until} ${snoozeUntil}` });
    }
    return packBlocks([
      vHeader({ title: CARD.title, trailing: SCARD.status }),
      ...(rows.length === 0
        ? [vNote(str(input.spoken) ?? SDECK.missing_detail)]
        : [vList(rows)]),
    ]);
  }, SCARD.status);
}

/** UI-SPEC §3.11 — an empty channel is a designed state, never an error (Phase-1 rule kept). */
export interface EmptyChannelData {
  channel?: string | undefined;
  workspace?: string | undefined;
  spoken?: string | undefined;
}

export function emptyChannel(data: EmptyChannelData): string {
  return guarded(() => {
    const input = rec(data) as EmptyChannelData;
    /** Channel and workspace as separate words joined by a middot — never an em dash (R2 §3.8). */
    const channel = str(input.channel);
    const workspace = str(input.workspace) ?? knownWorkspace;
    const scope = [
      ...(channel === undefined ? [] : [channelText(clip(channel, 32))]),
      ...(workspace === undefined ? [] : [clip(workspace, 28)]),
    ].join(' · ');
    const hint = str(input.spoken);
    return packBlocks([
      vHeader({
        title: CARD.title,
        ...(scope === '' ? {} : { trailing: scope }),
      }),
      vEmpty({ title: CARD.empty_title, ...(hint === undefined ? {} : { hint }) }),
    ]);
  }, NEUTRAL_CHANNEL);
}
