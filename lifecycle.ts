/**
 * LIFECYCLE — the three connect triggers (Phase S, B1 · PHASE-1.5-SHIP-LIST §1).
 *
 * The finding this file exists for: a custom VoiceOS integration can NEVER get the native
 * "Connect" button — `auth.kind:"oauth2"` in the manifest is dead code and actually REMOVES
 * the setup box. So the affordance has to come from somewhere else, and there are exactly
 * three places it can:
 *
 *   C1  toggle-on / app-launch  → the enable toggle spawns this process; if the vault has no
 *                                 usable token we open the approval page ourselves.
 *   C2  first command           → any tool called without a token opens it (`requireToken`
 *                                 in `toolkit.ts` calls into this file's guard).
 *   C3  spoken                  → `slack_connect`, "connect my Slack" / "switch accounts".
 *
 * TWO GUARDS, BOTH NON-NEGOTIABLE, because the failure mode here is user-hostile in a way a
 * test suite does not feel: VoiceOS relaunches (or six tools firing at a disconnected Slack)
 * must never turn into six browser tabs.
 *
 *   G1 token   — open ONLY when the vault cannot produce a usable token. `hasUsableToken`
 *                asks the engine for a *fresh* token, so "expired but refreshable" is
 *                connected (silent refresh) and "expired with no refresh" is not.
 *   G2 cooldown— a stamp file (`.connect-cooldown`, 120s) in the integration directory,
 *                written BEFORE the browser is opened, so even a crash mid-connect still
 *                suppresses the next attempt. Plus an in-process promise latch, because two
 *                tool calls in the same second race past a file check.
 *
 * AND THE STARTUP RULE: C1 never blocks startup. Their client gives `listTools()` 30s and a
 * tool call 60s; the auto-open is scheduled off the boot path with an unref'd timer and its
 * result is never awaited by anything on the critical path.
 *
 * ── WIRING (B5, `server.ts`) ──────────────────────────────────────────────────────────
 *   import { lifecycleTools, scheduleStartupAutoConnect } from './lifecycle.ts';
 *   scheduleStartupAutoConnect();      // ONE line, at the bottom of module setup, NOT awaited
 * Without that line C1 does not exist and the connect experience falls back to C2/C3 only.
 * `lifecycleTools` is what the registry spreads (`[...lifecycleTools, ...t1, ...t2]`).
 */

import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { connect as engineConnect, getToken as engineGetToken, resolveProviderProfile } from './engine/index.ts';
import type { ConnectStatus } from './engine/index.ts';
import type { ToolCtx, ToolDef } from './toolkit.ts';

/** The provider name in the vault, the registry and `provider.json`. One string, one place. */
export const PROVIDER = 'slack';

/** 120s. Long enough that an app relaunch loop cannot spam tabs; short enough to retry by hand. */
export const CONNECT_COOLDOWN_MS = 120_000;

/**
 * The stamp file. It lives beside the integration (repo *or* installed folder — resolved
 * from `import.meta.url`, never `.pathname`, because the installed home is
 * `~/Library/Application Support/…` and a percent-encoded space is a path that does not
 * exist). It holds a millisecond timestamp and a trigger name and NOTHING else: no token,
 * no code, no verifier ever reaches disk from this file.
 */
export const COOLDOWN_FILENAME = '.connect-cooldown';

export function cooldownPath(): string {
  return fileURLToPath(new URL(`./${COOLDOWN_FILENAME}`, import.meta.url));
}

/* ────────────────────────────────── injectable seams ────────────────────────────────── */

export type ConsentTrigger = 'startup' | 'first-command' | 'spoken';

export interface ConsentOutcome {
  opened: boolean;
  reason: 'opened' | 'cooldown' | 'open_failed';
  /**
   * The engine's first status, when one was produced. `phase: 'connected'` here means the
   * vault already held a live record and NO browser tab was opened — the engine short-
   * circuits before the loopback binds, which is why "already connected" needs no separate
   * code path in this file.
   */
  status?: ConnectStatus;
}

export interface StartupOutcome {
  opened: boolean;
  reason: 'opened' | 'cooldown' | 'open_failed' | 'already_connected';
  connect_id?: string;
}

/**
 * Everything this module does to the machine. Injectable for one reason: a test that opens
 * a real browser, writes a real file into the repo and asks a real Keychain for a real token
 * is a test nobody runs twice.
 */
export interface LifecycleHooks {
  now(): number;
  /** The G1 guard. `true` ⇒ the engine can produce a token valid right now. */
  hasUsableToken(): Promise<boolean>;
  /** Last consent attempt, ms epoch, or null when there has never been one. */
  readStamp(): Promise<number | null>;
  writeStamp(at: number, trigger: ConsentTrigger): Promise<void>;
  /** Binds the loopback, builds the authorize URL, hands it to the browser. Returns in ≲1s. */
  startConsent(force: boolean): Promise<ConnectStatus>;
  /** stderr only, and never a token, code or verifier — VoiceOS writes MCP stderr to disk. */
  log(line: string): void;
}

const DEFAULT_HOOKS: LifecycleHooks = {
  now: () => Date.now(),

  hasUsableToken: async () => {
    try {
      const token = await engineGetToken(PROVIDER);
      return typeof token === 'string' && token !== '';
    } catch {
      // not_connected / expired_or_revoked / refresh_failed / vault_unavailable all mean the
      // same thing to the connect affordance: this Mac cannot talk to Slack right now.
      return false;
    }
  },

  readStamp: async () => {
    try {
      const parsed: unknown = JSON.parse(await readFile(cooldownPath(), 'utf8'));
      if (typeof parsed !== 'object' || parsed === null) return null;
      const value = (parsed as Record<string, unknown>)['last_attempt_ms'];
      return typeof value === 'number' && Number.isFinite(value) ? value : null;
    } catch {
      return null; // never written, unreadable, or corrupt — all "no cooldown in effect"
    }
  },

  writeStamp: async (at, trigger) => {
    await writeFile(cooldownPath(), `${JSON.stringify({ last_attempt_ms: at, trigger })}\n`, {
      encoding: 'utf8',
      mode: 0o600,
    });
  },

  startConsent: async (force) => {
    const profile = await resolveProviderProfile(PROVIDER);
    return engineConnect(profile, force ? { force: true } : {});
  },

  log: (line) => process.stderr.write(`[slack-lifecycle] ${line}\n`),
};

let hooks: LifecycleHooks = { ...DEFAULT_HOOKS };

/** Test seam. Production never calls this. */
export function setLifecycleHooks(overrides: Partial<LifecycleHooks>): void {
  hooks = { ...hooks, ...overrides };
}

/** Test seam. Restores the real filesystem/engine behaviour. */
export function resetLifecycleHooks(): void {
  hooks = { ...DEFAULT_HOOKS };
  pendingConsent = null;
}

/* ──────────────────────────────── the guarded opener ──────────────────────────────── */

/**
 * The in-process half of G2. The file stamp stops the NEXT process; this stops the second
 * caller inside THIS one — `slack_catch_up` and `slack_search` fired half a second apart at
 * a disconnected Slack are two `requireToken` calls that would both read a stamp that is not
 * written yet.
 */
let pendingConsent: Promise<ConsentOutcome> | null = null;

/** Exposed for the tests and for whoever debugs a "why didn't it open" report. */
export async function cooldownRemainingMs(): Promise<number> {
  const stamp = await hooks.readStamp();
  if (stamp === null) return 0;
  const elapsed = hooks.now() - stamp;
  if (elapsed < 0) return 0; // clock moved backwards; treat as expired rather than lock out
  return elapsed >= CONNECT_COOLDOWN_MS ? 0 : CONNECT_COOLDOWN_MS - elapsed;
}

/**
 * Open the Slack approval page, under G2 (never under G1 — the caller owns that check,
 * because C1 and C2 learn "there is no token" in different ways).
 *
 * Fire-and-forget by design: it returns as soon as the browser has the URL. The exchange,
 * the vault write and the identity probe finish out of band on the engine's status board.
 */
export function openConsentUnderGuard(
  trigger: ConsentTrigger,
  options: {
    /** Slack's "switch accounts" path — a fresh consent even if a token is vaulted. */
    force?: boolean;
    /** A human who just SAID "connect Slack" is not the spam this guard exists to stop. */
    bypassCooldown?: boolean;
  } = {},
): Promise<ConsentOutcome> {
  if (pendingConsent !== null) return pendingConsent;
  const force = options.force === true;

  const attempt = (async (): Promise<ConsentOutcome> => {
    if (options.bypassCooldown !== true) {
      const remaining = await cooldownRemainingMs();
      if (remaining > 0) {
        hooks.log(`consent suppressed (${trigger}): cooldown ${Math.ceil(remaining / 1000)}s remaining`);
        return { opened: false, reason: 'cooldown' };
      }
    }

    // Stamp BEFORE opening: a crash between here and the browser must still cool down, or a
    // crash-loop becomes a tab-loop.
    await hooks.writeStamp(hooks.now(), trigger).catch((error: unknown) => {
      hooks.log(`cooldown stamp not written: ${error instanceof Error ? error.name : 'unknown'}`);
    });

    try {
      const status = await hooks.startConsent(force);
      hooks.log(`consent opened (${trigger}): phase=${status.phase}`);
      return { opened: true, reason: 'opened', status };
    } catch (error) {
      hooks.log(`consent could not start (${trigger}): ${error instanceof Error ? error.name : 'unknown'}`);
      return { opened: false, reason: 'open_failed' };
    }
  })();

  pendingConsent = attempt;
  return attempt.finally(() => {
    if (pendingConsent === attempt) pendingConsent = null;
  });
}

/* ─────────────────────────────── C1 — toggle-spawn auto-open ─────────────────────────────── */

/**
 * C1. Called by `server.ts` at startup — never awaited by it.
 *
 * G1 first: an already-connected user must not see a browser tab because they relaunched
 * the app. Only then G2.
 */
export async function autoConnectOnStartup(): Promise<StartupOutcome> {
  if (await hooks.hasUsableToken()) {
    hooks.log('startup: token present, no consent needed');
    return { opened: false, reason: 'already_connected' };
  }
  const outcome = await openConsentUnderGuard('startup');
  const connectId = outcome.status?.connect_id;
  return connectId === undefined
    ? { opened: outcome.opened, reason: outcome.reason }
    : { opened: outcome.opened, reason: outcome.reason, connect_id: connectId };
}

/**
 * The call `server.ts` makes. Deliberately returns `void` and schedules off the boot path:
 *
 *  - `setTimeout(…, 0)` so `initialize`/`tools/list` are answered before we touch Keychain
 *    or the network (their 30s connect gate is not a budget to spend on ourselves), and
 *  - `.unref()` so this timer can never be the reason a short-lived process stays alive.
 */
export function scheduleStartupAutoConnect(): void {
  const timer = setTimeout(() => {
    void autoConnectOnStartup().catch((error: unknown) => {
      hooks.log(`startup auto-connect failed: ${error instanceof Error ? error.name : 'unknown'}`);
    });
  }, 0);
  timer.unref?.();
}

/* ─────────────────────────────── C3 — the spoken connect ─────────────────────────────── */

/**
 * C3 — `slack_connect`. Not confirmation-gated: the consent screen IS the confirmation, and
 * a card asking permission to ask permission is the second approval D3 spends its whole
 * budget avoiding.
 *
 * Two-phase, exactly as Phase 1 proved in the real app: this returns in ≲1s with either
 * `connectedSuccess` (already vaulted — no tab, no re-approval) or `connectProgress` plus
 * the `connect_id` the client polls. A tool call may never block on a human clicking Allow.
 */
export const slackConnectTool: ToolDef = {
  name: 'slack_connect',
  description:
    'Connect (or reconnect) Slack for this Mac. Opens Slack’s approval page in the browser and finishes in the background; call again with switch:true to sign in as a different account or workspace. Tokens are stored in the macOS Keychain on this device — never on a server.',
  inputSchema: {
    type: 'object',
    properties: {
      switch: {
        type: 'boolean',
        description:
          'Force a fresh approval even if Slack is already connected — the "switch accounts" / "use my other workspace" path.',
      },
    },
    additionalProperties: false,
  },
  confirm: false,

  async handler(args: { switch?: boolean } | undefined, ctx: ToolCtx) {
    const force = args?.switch === true;

    // A spoken connect is an explicit human act, so it skips the anti-spam cooldown — but it
    // still WRITES the stamp, which is what stops the next app relaunch from opening a second
    // tab on top of the one the user is already looking at.
    const outcome = await openConsentUnderGuard('spoken', { force, bypassCooldown: true });
    const status = outcome.status;

    // Already connected: the engine short-circuits on a live vault record and never opens a
    // browser. Re-approving a working connection is the one thing "connect my Slack" must
    // not do to someone who is already connected.
    if (status !== undefined && status.phase === 'connected') {
      const identity = status.identity;
      return {
        content: {
          status: 'connected',
          provider: PROVIDER,
          phase: status.phase,
          connect_id: status.connect_id,
          ...(identity === undefined ? {} : { identity }),
          spoken: status.spoken,
        },
        card: ctx.cards.connectedSuccess({
          state: 'connected',
          spoken: status.spoken,
          handle: identity?.handle,
          workspace: identity?.workspace,
        }),
      };
    }

    if (!outcome.opened) {
      const spoken = ctx.copy.DECK.browser_open_failed;
      return {
        content: { status: 'auth_required', provider: PROVIDER, phase: 'error', reason: outcome.reason, spoken },
        card: ctx.cards.errorCard({ state: 'browser_open_failed', spoken }),
      };
    }

    const spoken = status?.spoken ?? ctx.copy.DECK.opening_browser;
    return {
      content: {
        status: 'auth_required',
        provider: PROVIDER,
        phase: status?.phase ?? 'launching-browser',
        ...(status === undefined ? {} : { connect_id: status.connect_id }),
        spoken,
      },
      card: ctx.cards.connectProgress({ state: 'opening_browser', spoken }),
    };
  },
};

/** What B5's registry spreads. Lifecycle owns exactly one tool; disconnect is B3's. */
export const lifecycleTools: ToolDef[] = [slackConnectTool];
