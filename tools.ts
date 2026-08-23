/**
 * THE REGISTRY (Phase S, builder B5) — one list of tools, one dispatcher, one manifest.
 *
 * Four builders produced tools in parallel; this file is the only place they meet. It exists
 * so that `server.ts` stays what it has always been — JSON-RPC in, JSON-RPC out — and so the
 * three things that silently drift in a multi-file integration cannot:
 *
 *  1. **The registry is the single source of the tool list.** `TOOLS` is the spread of
 *     lifecycle (B1) + T1 (B2) + T2 (B3) plus the one tool assembly itself owns
 *     (`slack_status`, below). Nothing else may declare a tool.
 *  2. **The manifest is DERIVED from the registry** (`buildManifest()`), not hand-kept beside
 *     it. `voiceos.integration.json` is what their agent routes on; a name, a description or
 *     an `inputSchema` that disagrees with the code is a tool the model calls and the server
 *     rejects. `tools/build-manifest.mjs` writes the file, `slack-integration.test.ts`
 *     regenerates it and diffs — so drift is a red test, not a stage surprise.
 *  3. **`confirm: true` ⇔ a manifest `confirmation` card, exactly.** Their contract (§1.4-1.5)
 *     has no `readOnly` flag: the PRESENCE of a `confirmation` object is what makes a tool an
 *     action tool, and its absence is what makes one instant. The mirror is generated here and
 *     asserted in the test, in both directions.
 *
 * ── THE THREE WIRING SEAMS, all of them one line, none of them optional ──────────────────
 *   C2  `useTokenGate(requireToken)`   — a tool called with no token opens the consent page
 *                                        under B1's cooldown guard instead of just refusing.
 *   §5  `groundFromToolResult(content)`— every read result registers its `channel+ts` pairs,
 *                                        so a later `slack_react` / `slack_thread_reply` has
 *                                        provenance for the timestamp it was handed.
 *   C1  `scheduleStartupAutoConnect()` — lives in `server.ts` (it is a startup act, not a
 *                                        registry act) and is asserted by the manifest test.
 */

import { getConnectStatus } from './engine/index.ts';
import type { ConnectStatus, ProviderProfile } from './engine/index.ts';

import * as cards from './cards.ts';
import { replyComposerHtml, sendComposerHtml, SLACK_ICON } from './composer.ts';
import * as copy from './copy.ts';
import { COMPOSER_CHROME, connectedLine, internalFaultLine } from './copy.ts';
import { PROVIDER, lifecycleTools } from './lifecycle.ts';
import { getDirectory, labelForUser } from './resolve.ts';
import { createToolCtx, requireToken } from './toolkit.ts';
import type { CardsModule, ToolCtx, ToolDef } from './toolkit.ts';
import { T1_TOOLS, useTokenGate } from './tools-t1.ts';
import { T2_TOOLS, groundFromToolResult } from './tools-t2.ts';

/* ───────────────────────────────── C2 — the consent seam ─────────────────────────────────
 *
 * T1 ships with a deliberately side-effect-free default gate so its own tests never spawn a
 * browser. Production wants the other one: B1's `requireToken`, which opens the approval page
 * under the same cooldown + in-process latch that stops six tools firing at a disconnected
 * Slack from becoming six tabs. This is that swap, and it must happen at module load — before
 * any handler can run — which is why it is here and not inside `callTool`.
 */
useTokenGate(requireToken);

/* ─────────────────────────── the one tool assembly owns: slack_status ───────────────────────────
 *
 * COMMAND-SPEC §2 T1 #2 keeps `slack_status` from Phase 1, and it is not decoration: the
 * connect flow is TWO-PHASE (D4). `slack_connect` returns in ≲1s with a `connect_id` because a
 * tool call may never block on a human clicking Allow — and something has to answer "did they
 * click it yet?". B3's `slack_health` absorbed the *identity* half of Phase-1 `slack_status`
 * (`auth.test` → handle + workspace) but not the *polling* half, so without this tool the two-
 * phase connect has no second phase and the connect flow would end on "opening your browser…"
 * forever. Found at assembly; this is the seam, not a rewrite of anyone's logic.
 *
 * With `connect_id` → poll the engine. Without → delegate, verbatim, to `slack_health`'s
 * handler, so there is exactly ONE implementation of "am I connected, and as whom".
 */
const healthTool = T2_TOOLS.find((tool) => tool.name === 'slack_health');

/** Which card a live connect status deserves. Mirrors lifecycle's own three-way split. */
function statusCard(ctx: ToolCtx, status: ConnectStatus): string {
  if (status.phase === 'connected') {
    return ctx.cards.connectedSuccess({
      state: 'connected',
      spoken: status.spoken,
      handle: status.identity?.handle,
      workspace: status.identity?.workspace,
    });
  }
  if (status.error !== undefined) {
    return ctx.cards.errorCard({ state: status.error.code, spoken: status.spoken });
  }
  const state =
    status.phase === 'awaiting-consent'
      ? 'awaiting_consent'
      : status.phase === 'exchanging'
        ? 'exchanging'
        : 'opening_browser';
  return ctx.cards.connectProgress({ state, spoken: status.spoken });
}

/**
 * NAME-RULE L4, the connect-flow half: the engine's identity probe reads `auth.test`'s `user`,
 * which is Slack's LEGACY handle ("icynd2777"). Before that identity reaches a card or the
 * spoken "Connected as …" line, the directory ladder names the account ("Rithvik"). Best
 * effort: a directory failure keeps the legacy handle, the ladder's own last resort.
 */
async function resolvedIdentity(
  ctx: ToolCtx,
  identity: { handle: string; workspace?: string },
): Promise<{ handle: string; workspace?: string }> {
  try {
    const directory = await getDirectory(ctx);
    const display = labelForUser(directory, directory.me.user_id);
    return display === undefined ? identity : { ...identity, handle: display };
  } catch {
    return identity;
  }
}

const slackStatusTool: ToolDef = {
  name: 'slack_status',
  description:
    'Report whether Slack is connected on this Mac and as whom, or, given the connect_id ' +
    'returned by slack_connect, how far along an approval that is still in flight has got. ' +
    'Use right after slack_connect to find out whether the user has hit Allow yet. Read-only.',
  inputSchema: {
    type: 'object',
    properties: {
      connect_id: {
        type: 'string',
        description: 'The id slack_connect returned, to poll an approval that is still open.',
      },
    },
    additionalProperties: false,
  },
  confirm: false,

  async handler(args: { connect_id?: string } | undefined, ctx: ToolCtx) {
    const connectId = typeof args?.connect_id === 'string' ? args.connect_id.trim() : '';

    /** The identity question: not a poll, so ask Slack rather than a stored token. */
    const askSlack = async () => {
      if (healthTool === undefined) {
        const spoken = internalFaultLine('not_implemented');
        return {
          content: { error: 'not_implemented', tool: 'slack_status', spoken },
          card: ctx.cards.errorCard({ kind: 'internal_fault', spoken, reason: 'not_implemented' }),
        };
      }
      return healthTool.handler({}, ctx);
    };

    if (connectId === '') return askSlack();

    try {
      const status = await getConnectStatus(connectId);
      const identity =
        status.phase === 'connected' && status.identity !== undefined
          ? await resolvedIdentity(ctx, status.identity)
          : status.identity;
      const shown: ConnectStatus =
        identity === undefined || identity === status.identity ? status : { ...status, identity };
      return {
        content: {
          provider: PROVIDER,
          phase: status.phase,
          connect_id: status.connect_id,
          connected: status.phase === 'connected',
          ...(identity === undefined ? {} : { identity }),
          ...(status.error === undefined ? {} : { error: status.error.code }),
          spoken:
            status.phase === 'connected' && identity !== undefined
              ? connectedLine(identity.handle, identity.workspace)
              : status.spoken,
        },
        card: statusCard(ctx, shown),
      };
    } catch {
      // The engine keeps the last 50 connect ids OF THIS PROCESS, so an id it does not know is
      // the ordinary consequence of a restart, not a fault — and there is no honest card for
      // "I lost track of that approval": every existing surface would either blame Slack for a
      // local bookkeeping fact or claim a connection state nobody checked. So don't guess —
      // ask Slack the question underneath ("am I connected, and as whom") and answer THAT.
      return askSlack();
    }
  },
};

/* ──────────────────────────────────────── the registry ──────────────────────────────────────── */

/**
 * Every tool this integration has, in the order the manifest declares them: lifecycle first
 * (nothing below works without it), then T1 in COMMAND-SPEC §2 order, then T2.
 */
export const TOOLS: ToolDef[] = [...lifecycleTools, slackStatusTool, ...T1_TOOLS, ...T2_TOOLS];

export const TOOL_NAMES: readonly string[] = TOOLS.map((tool) => tool.name);

/** Exactly the tools whose manifest entry carries a `confirmation` card (their §1.4 rule). */
export const CONFIRM_TOOLS: readonly string[] = TOOLS.filter((tool) => tool.confirm).map((tool) => tool.name);

export function findTool(name: string): ToolDef | undefined {
  return TOOLS.find((tool) => tool.name === name);
}

/* ──────────────────────────────────────── the dispatcher ──────────────────────────────────────── */

export interface ToolOutput {
  content: unknown;
  card: string;
}

/**
 * Build the context every handler receives. One assembly point, so a test can build the same
 * object with a stub fetch and a stub token and drive the real handlers.
 *
 * Note what is NOT here: no PKCE, no port, no state, no refresh, no retry-on-401. The token
 * arrives from the engine already valid. That claim has to be literally true in the file a reviewer opens first.
 */
export function createSlackCtx(profile: ProviderProfile, overrides: Partial<Parameters<typeof createToolCtx>[0]> = {}): ToolCtx {
  return createToolCtx({
    profile,
    cards: cards as unknown as CardsModule,
    copy,
    ...overrides,
  });
}

/**
 * The single entry point `server.ts` wires to `tools/call`. It never throws.
 *
 * Handlers are already individually guarded (B2's `guard`, B3's `guarded`), so the try/catch
 * here is the third net, not the first: what it actually buys is that a defect in the REGISTRY
 * — a tool that isn't there, a handler that isn't a function — still comes back as a card
 * instead of a JSON-RPC error the user sees as ninety seconds of silence.
 */
export async function callTool(name: string, args: Record<string, unknown>, ctx: ToolCtx): Promise<ToolOutput> {
  const tool = findTool(name);
  if (tool === undefined) {
    const spoken = internalFaultLine('unknown_tool');
    return {
      content: { error: 'unknown_tool', tool: name, spoken },
      card: safeCard(ctx, { kind: 'internal_fault', spoken, reason: 'unknown_tool' }),
    };
  }

  let output: ToolOutput;
  try {
    output = await tool.handler(args, ctx);
  } catch (error) {
    const code = typeof (error as { code?: unknown })?.code === 'string' ? (error as { code: string }).code : 'unavailable';
    const spoken = internalFaultLine(code);
    return {
      content: { error: 'internal_fault', tool: name, reason: code, spoken },
      card: safeCard(ctx, { kind: 'internal_fault', spoken, reason: code }),
    };
  }

  // COMMAND-SPEC §5, the provenance seam: what a read returned becomes what a write is allowed
  // to refer to. Without this line every `slack_react` on a message the user just heard pays an
  // extra verification round trip — and under the strict `session` policy it would be refused.
  try {
    groundFromToolResult(output?.content);
  } catch {
    /* grounding is an optimisation; it may never be the reason a tool fails */
  }

  return { content: output?.content ?? null, card: typeof output?.card === 'string' ? output.card : '' };
}

/** A card may never be the reason a tool fails — the facts go out with or without one. */
function safeCard(ctx: ToolCtx, data: Record<string, unknown>): string {
  try {
    const rendered = ctx.cards?.errorCard?.(data);
    return typeof rendered === 'string' ? rendered : '';
  } catch {
    return '';
  }
}

/**
 * Tool output → the JSON payload on the wire.
 *
 * The card rides INSIDE the same object under `_voiceos_glance` — the shape their own
 * reference integrations use — rather than as a second content part, so the result contract
 * is unchanged and a card that failed to render is simply absent. `card` is already a
 * serialized `{blocks:[…]}` document (B4's cards return strings), so it is parsed once here;
 * if it is not parseable it is dropped, because half a card is worse than none.
 */
export function toWirePayload(output: ToolOutput): Record<string, unknown> {
  const content = output.content;
  const base: Record<string, unknown> =
    typeof content === 'object' && content !== null && !Array.isArray(content)
      ? { ...(content as Record<string, unknown>) }
      : { result: content };

  if (output.card === '') return base;
  try {
    const parsed: unknown = JSON.parse(output.card);
    if (typeof parsed === 'object' && parsed !== null) base['_voiceos_glance'] = parsed;
  } catch {
    /* an unparseable card is no card */
  }
  return base;
}

/* ──────────────────────────────────────── the manifest ──────────────────────────────────────── */

/**
 * The parts of the manifest that are not a tool: identity, runtime, publisher.
 *
 * `id` is FROZEN (`com.voiceos.generated.slack-connect`) — it is the key VoiceOS stores the
 * integration under, so changing it orphans an installed copy rather than updating it.
 *
 * There is no `auth` block, and its absence is a decision, not an omission: a full trace of
 * the v0.1.22 bundles found that `auth.kind:"oauth2"` in a custom integration's manifest is
 * dead code that REMOVES the setup box (PHASE-1.5-SHIP-LIST §1). Declaring it would advertise
 * a native Connect button this platform will never render for a custom integration. The
 * connect affordance is C1/C2/C3 instead, and the scopes live in `provider.json`, which is
 * the file the engine actually sends to Slack — one source, not two that can disagree.
 */
export const MANIFEST_HEADER = {
  schemaVersion: 1,
  id: 'com.voiceos.generated.slack-connect',
  version: '1.1.0',
  name: 'Slack',
  summary: 'Read and send messages',
  description:
    'Do real Slack work by voice: a cross-channel catch-up digest, read any channel or DM, ' +
    'search with Slack’s own search, send and schedule messages, react, reply in thread, set ' +
    'your status and Do Not Disturb. Connecting is one tap on Slack’s own approval page. No ' +
    'API key is ever pasted, no secret ships with this integration, and the token is stored ' +
    'encrypted in the login Keychain rather than in any file on disk.',
  categories: ['Productivity', 'Communication'],
  publisher: { id: 'pub_user', name: 'Rithvik' },
  runtime: { kind: 'local-mcp', command: '/bin/zsh', args: ['run.sh'] },
  icon: 'icon.png',
} as const;

/**
 * What the registry cannot know: the human `title` VoiceOS shows, and the `confirmation` card
 * an action tool is gated by. Dialect B (the terse Stripe dialect, contract §1.5) throughout —
 * `{{arg}}` binds the tool's own argument names, and the values the user EDITS on that card
 * are the values that execute, which is precisely why every gated argument appears on it.
 *
 * The rule this table is held to (asserted in both directions by the manifest test): a tool
 * with `confirm: true` has a `confirmation` here, a tool with `confirm: false` has none.
 */
interface ManifestExtra {
  title: string;
  confirmation?: Record<string, unknown>;
}

/**
 * One DESIGN-SPEC §1 confirmation card. Pure Dialect B — `schemaVersion:1/root` card with a
 * static title, typed children and a footer actions row of exactly one cancel + one accent
 * confirm — because the home-grown `{card:{children:[...]}}` shape from the first build made
 * the notch re-emit agent-voice-confirmation in a loop. Context renders as keyValue display
 * rows whose `{{arg}}` values are already human (`#general`, `Maya`, `tomorrow at 9:00 AM`):
 * the resolver humanizes the ARG, so the card never needs a raw id. The Slack pinwheel icon
 * now lives in `composer.ts` (one constant shared with the widget builders).
 *
 * `confirmColor`: `'success'` on the constructive tools (schedule, upload — they put content
 * in front of other people), `'accent'` otherwise. COMPOSER-SPEC §0: the renderer IGNORES
 * `color` on the confirm pill (always liquid glass, DIALECT-VERIFIED §4), so today this is
 * semantic and future-proof only — do not re-promise anyone a green pill.
 */
function confirmCard(
  title: string,
  children: unknown[],
  confirmLabel: string,
  confirmColor: 'accent' | 'success' = 'accent',
): Record<string, unknown> {
  return {
    schemaVersion: 1,
    root: {
      type: 'card',
      title,
      icon: SLACK_ICON,
      children,
      footer: [
        {
          type: 'actions',
          items: [
            { label: 'Cancel', role: 'cancel' },
            { label: confirmLabel, role: 'confirm', color: confirmColor },
          ],
        },
      ],
    },
  };
}

/* ───────────────────────── Phase D2 — the Path W composer confirmations ─────────────────────────
 *
 * COMPOSER-SPEC §1: for `slack_send_message` and `slack_thread_reply` the confirmation is a
 * bare root card (no title, no icon — the widget draws its own Slack header) wrapping exactly
 * ONE `widget` block, no footer. The host floats the only confirm control (the glass pill,
 * relabeled via `confirmLabel`); the widget textarea writes the `text` arg back through the
 * verified `voiceos:updateInput` bridge, so what the user edits is what executes.
 */

/** A COMPOSER-SPEC §1.1 widget confirmation: bare card, one widget, host pill relabeled. */
function widgetCard(html: string, height: number, confirmLabel: string): Record<string, unknown> {
  return {
    schemaVersion: 1,
    root: {
      type: 'card',
      children: [{ type: 'widget', html, height, confirmLabel }],
    },
  };
}

/**
 * The flip-back switch (COMPOSER-SPEC §4.3). Read ONCE at manifest build:
 * `VOICEOS_SLACK_COMPOSER=D node tools/build-manifest.mjs` ships the Dialect-B cards for
 * send + reply instead of the widget composers — zero code edits, zero effect on the five
 * tools that are Path D on both settings. Default (unset, or anything but 'D') = W.
 */
export const COMPOSER_PATH: 'W' | 'D' = process.env['VOICEOS_SLACK_COMPOSER'] === 'D' ? 'D' : 'W';

/**
 * BOTH shapes for the two composer tools stay generatable forever — the W widget payloads and
 * the D cards (exactly what shipped before this round, verbatim) — so the fallback cannot rot
 * while W is live. The manifest test asserts both.
 */
export const COMPOSER_CONFIRMATIONS: Record<
  'slack_send_message' | 'slack_thread_reply',
  Record<'W' | 'D', Record<string, unknown>>
> = {
  slack_send_message: {
    W: widgetCard(sendComposerHtml(), 230, COMPOSER_CHROME.send),
    D: confirmCard(
      'New Slack message',
      [
        { type: 'keyValue', rows: [{ label: 'To', value: '{{target}}', color: 'accent' }] },
        { type: 'divider' },
        { type: 'textField', bind: '{{text}}', label: 'Message', required: true, multiline: true },
      ],
      'Send',
    ),
  },
  slack_thread_reply: {
    W: widgetCard(replyComposerHtml(), 270, COMPOSER_CHROME.reply),
    D: confirmCard(
      'Reply in thread',
      [
        {
          type: 'keyValue',
          visibleIf: 'replying_to',
          rows: [{ label: 'Replying to', value: '{{replying_to}}', color: 'muted' }],
        },
        { type: 'keyValue', rows: [{ label: 'In', value: '{{channel}}', color: 'accent' }] },
        { type: 'divider' },
        { type: 'textField', bind: '{{text}}', label: 'Reply', required: true, multiline: true },
      ],
      'Reply',
    ),
  },
};

const EXTRAS: Record<string, ManifestExtra> = {
  slack_connect: { title: 'Connect Slack' },
  slack_status: { title: 'Slack connection status' },
  slack_catch_up: { title: 'Catch me up' },
  slack_read_channel: { title: 'Read a channel' },
  slack_read_dm: { title: 'Read a DM' },
  // Path W by default (COMPOSER-SPEC §1): the Slack-look widget composer with live writeback.
  // VOICEOS_SLACK_COMPOSER=D at manifest build flips it back to the Dialect-B card.
  slack_send_message: {
    title: 'Send a message',
    confirmation: COMPOSER_CONFIRMATIONS.slack_send_message[COMPOSER_PATH],
  },
  slack_search: { title: 'Search Slack' },
  slack_find: { title: 'Find a channel or person' },
  slack_react: {
    title: 'React to a message',
    confirmation: confirmCard(
      'Add a reaction',
      [
        { type: 'keyValue', rows: [{ label: 'Reaction', value: '{{emoji}}', color: 'accent' }] },
        { type: 'keyValue', visibleIf: 'message', rows: [{ label: 'Message', value: '{{message}}', color: 'muted' }] },
        { type: 'keyValue', rows: [{ label: 'In', value: '{{channel}}' }] },
      ],
      'React',
    ),
  },
  slack_schedule_message: {
    title: 'Schedule a message',
    confirmation: confirmCard(
      'Schedule a message',
      [
        { type: 'keyValue', visibleIf: 'channel', rows: [{ label: 'To', value: '{{channel}}', color: 'accent' }] },
        { type: 'keyValue', visibleIf: 'user', rows: [{ label: 'To', value: '{{user}}', color: 'accent' }] },
        { type: 'textField', bind: '{{when}}', label: 'At', required: true },
        { type: 'divider' },
        { type: 'textField', bind: '{{text}}', label: 'Message', required: true, multiline: true },
      ],
      'Schedule',
      'success',
    ),
  },
  slack_set_reminder: {
    title: 'Set a reminder',
    confirmation: confirmCard(
      'Set a reminder',
      [
        { type: 'textField', bind: '{{text}}', label: 'Remind me about', required: true, multiline: true },
        { type: 'textField', bind: '{{time}}', label: 'When', required: true },
      ],
      'Remind me',
    ),
  },
  slack_upload_file: {
    title: 'Upload a file',
    confirmation: confirmCard(
      'Upload a file',
      [
        { type: 'keyValue', visibleIf: 'filename', rows: [{ label: 'File', value: '{{filename}}' }] },
        { type: 'keyValue', visibleIf: 'channel', rows: [{ label: 'To', value: '{{channel}}', color: 'accent' }] },
        { type: 'keyValue', visibleIf: 'user', rows: [{ label: 'To', value: '{{user}}', color: 'accent' }] },
        { type: 'divider' },
        { type: 'textField', bind: '{{initial_comment}}', label: 'Message', multiline: true },
      ],
      'Upload',
      'success',
    ),
  },
  slack_thread_reply: {
    title: 'Reply in thread',
    confirmation: COMPOSER_CONFIRMATIONS.slack_thread_reply[COMPOSER_PATH],
  },
  slack_set_status: {
    title: 'Set status and Do Not Disturb',
    confirmation: confirmCard(
      'Set your status',
      [
        { type: 'textField', bind: '{{text}}', label: 'Status', required: true },
        { type: 'keyValue', visibleIf: 'emoji', rows: [{ label: 'Emoji', value: '{{emoji}}' }] },
        { type: 'keyValue', visibleIf: 'duration_minutes', rows: [{ label: 'For', value: '{{duration_minutes}} minutes' }] },
      ],
      'Set status',
    ),
  },
  // Disconnect is a toggle-grade action (reconnect takes ten seconds and their own
  // integrations gate nothing equivalent), and the renderer's card wants bindable fields
  // this tool does not have. Ungated by design, matching the official apps.
  slack_disconnect: { title: 'Disconnect Slack' },
  slack_health: { title: 'Slack health check' },
};

export interface ManifestTool {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  confirmation?: Record<string, unknown>;
}

/**
 * The manifest, derived. `tools/build-manifest.mjs` writes this to
 * `voiceos.integration.json`; the manifest test regenerates it and diffs against the file on
 * disk, so the declaration their agent routes on and the code that answers can never drift.
 */
export function buildManifest(): Record<string, unknown> {
  const tools: ManifestTool[] = TOOLS.map((tool) => {
    const extra = EXTRAS[tool.name];
    if (extra === undefined) throw new Error(`no manifest title for tool ${tool.name}`);
    if (tool.confirm !== (extra.confirmation !== undefined)) {
      throw new Error(`confirm/confirmation mismatch for ${tool.name}`);
    }
    return {
      name: tool.name,
      title: extra.title,
      description: tool.description,
      inputSchema: tool.inputSchema,
      ...(extra.confirmation === undefined ? {} : { confirmation: extra.confirmation }),
    };
  });
  return { ...MANIFEST_HEADER, tools };
}
