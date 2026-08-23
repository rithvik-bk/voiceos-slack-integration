/**
 * P1-I3 — the loopback listener. One socket, one mailbox, one delivery.
 *
 * This is the only part of the engine a stranger's browser can talk to, so it is written
 * defensively rather than conveniently:
 *
 *  - ONE `::` socket with `ipv6Only:false` (§A3). `localhost`, `127.0.0.1` and `[::1]` are
 *    three names for the same mailbox, so "which stack did Chrome pick today" stops being a
 *    variable. `EAFNOSUPPORT`-class failures fall back to a v4-only bind with a loud warning.
 *  - A FIXED ladder from config.ts, walked in order, first free rung wins. Ephemeral ports
 *    are illegal here: Reddit registers exactly one URI and matches it byte-for-byte
 *    (docs/registration/PORT-STRATEGY.md). Ladder exhausted → EngineError('port_blocked'),
 *    which is a copy-deck state with a spoken line, not a crash.
 *  - The `state` check comes BEFORE anything else is believed, and a wrong `state` does not
 *    kill the listener. Anyone on this machine can hit :33418/callback; if a bad guess could
 *    tear down the mailbox, the real callback arriving 200ms later would find nothing
 *    listening and the demo would die with no error anywhere. Wrong state → the mismatch
 *    page, and we keep waiting for the real one.
 *  - The code is delivered exactly once. Every later hit — a refresh of the success tab, a
 *    replay, a callback that lost the race — is answered with the page for the outcome that
 *    already happened, and never re-resolves the promise.
 *  - Nothing sensitive is logged, ever: no `code`, no `state`, no query string, not even at
 *    error level. VoiceOS writes MCP stderr to disk (Dr. M's redaction rule), and the pages
 *    themselves are screen-shared, so nothing sensitive is interpolated into HTML either.
 *
 * Everything the browser sees comes from engine/src/ui/pages.ts. This file renders no copy
 * of its own.
 */

import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import type { Socket } from 'node:net';

import { evaluateCallbackState } from './callbackState.ts';
import {
  CALLBACK_PATH,
  IP_REDIRECT_URIS,
  LOOPBACK_IP_HOST,
  PORT_LADDER,
  REDIRECT_HOST,
  REDIRECT_URIS,
} from './config.ts';
import { EngineError } from './index.ts';
import { checkFlow } from './mixup.ts';
import { reclaimPort, removeLock, writeLock } from './port-reclaim.ts';
import { renderPage } from './ui/pages.ts';
import type { PageOptions, PageState } from './ui/pages.ts';

/** The frozen P1-I3 handle. `openLoopback()` is the only way to get one. */
export interface Loopback {
  /** The ladder rung we actually bound. */
  port: number;
  /** The exact string to send in BOTH authorize and token requests (§A8). */
  redirectUri: string;
  /**
   * Wait for the one callback that matches `expectedState`.
   *
   * Resolves once, with the authorization code. Rejects with an `EngineError` whose code is
   * a copy-deck `ConnectErrorCode`: `denied_by_user`, `provider_error` or `timeout`.
   */
  waitForCallback(expectedState: string, timeoutMs: number): Promise<{ code: string }>;
  /** Idempotent. Frees the port immediately — open sockets included. */
  close(): Promise<void>;
}

export interface LoopbackOptions {
  /**
   * Display name for the branded pages, e.g. `Slack`. Optional: without it the pages use
   * their provider-neutral copy, which is also from the deck.
   */
  provider?: string;
  /** Provider brand mark data URI for the success page. Cosmetic only. */
  providerIcon?: string;
  /**
   * Which registered spelling of the host to hand back in `redirectUri`. `localhost` for
   * Slack/Reddit (the default), `127.0.0.1` for Zoom, whose form rejects the literal word
   * `localhost` (C-ZM-24). The socket is identical either way — this picks the *string*,
   * and both strings are sanctioned in config.ts.
   */
  host?: string;
  /** Stable profile.name, for the C-3 mix-up binding lookup. Absent = mix-up check skipped. */
  providerName?: string;
}

/* ────────────────────────────── small, boring helpers ────────────────────────────── */

/** Length-safe constant-time compare. A `state` check must not be a timing oracle. */
function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/** The ladder is the sole source of both spellings — no redirect string is written here. */
function resolveRedirectUri(port: number, host: string): string {
  const rung = PORT_LADDER.indexOf(port);
  const uri = host === LOOPBACK_IP_HOST ? IP_REDIRECT_URIS[rung] : REDIRECT_URIS[rung];
  if (uri === undefined) {
    throw new EngineError('config_invalid', 'bound a port that is not on the ladder', {
      hint: 'PORT_LADDER in engine/src/config.ts is the sole source of bindable ports.',
    });
  }
  return uri;
}

function sendPage(res: ServerResponse, state: PageState, opts: PageOptions): void {
  const body = renderPage(state, opts);
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'content-length': String(Buffer.byteLength(body)),
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    connection: 'close',
  });
  res.end(body);
}

function sendPlain(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, {
    'content-type': 'text/plain; charset=utf-8',
    'content-length': String(Buffer.byteLength(body)),
    'cache-control': 'no-store',
    connection: 'close',
  });
  res.end(body);
}

function listen(server: Server, port: number, host: string): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const onError = (err: Error): void => {
      server.removeListener('listening', onListening);
      reject(err);
    };
    const onListening = (): void => {
      server.removeListener('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    // ipv6Only:false is the whole trick: one socket answering both stacks (§A3).
    server.listen({ port, host, ipv6Only: false });
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise<void>((resolve) => {
    if (!server.listening) {
      server.close(() => resolve());
      resolve();
      return;
    }
    server.close(() => resolve());
  });
}

function errnoOf(err: unknown): string {
  return typeof err === 'object' && err !== null && 'code' in err
    ? String((err as NodeJS.ErrnoException).code)
    : '';
}

/** Node reports "this machine has no IPv6" in more than one dialect. */
const NO_IPV6 = new Set(['EAFNOSUPPORT', 'EADDRNOTAVAIL', 'EINVAL', 'EPROTONOSUPPORT']);

/**
 * Does this request look like the browser NAVIGATING here, rather than some page fetching us?
 *
 * Closes the one hole a `state` check cannot: an error callback that carries no `state` at
 * all. RFC 6749 §4.1.2.1 makes `state` REQUIRED on the error redirect when the request sent
 * one, but Slack's docs never say what their Cancel button emits (checked live 2026-08-16:
 * docs.slack.dev/authentication/installing-with-oauth/ documents only the success path), and
 * the deliberate Cancel beat is IN the demo script — so refusing state-less errors outright
 * would risk the demo on an undocumented provider behaviour.
 *
 * Fetch metadata settles it without needing the answer. Every current browser labels a
 * top-level redirect `Sec-Fetch-Dest: document` + `Sec-Fetch-Mode: navigate`, while the
 * attack — a web page firing a no-preflight `GET` at our callback path carrying
 * `error=access_denied`, to cancel an in-flight connect — is labelled `image`, `empty`,
 * `no-cors` etc. by that same browser, and a page cannot forge those headers.
 *
 * Absent headers are ACCEPTED on purpose (a pre-2020 browser, or curl in our own tests):
 * this hardens the remote drive-by without adding a new way for the live demo to fail. A
 * local process can still send whatever it likes — see docs/THREAT-MODEL.md W11.
 */
function looksLikeNavigation(req: IncomingMessage): boolean {
  const dest = req.headers['sec-fetch-dest'];
  const mode = req.headers['sec-fetch-mode'];
  if (typeof dest === 'string' && dest !== 'document') return false;
  if (typeof mode === 'string' && mode !== 'navigate') return false;
  return true;
}

/* ─────────────────────────────────── the listener ─────────────────────────────────── */

/**
 * Bind the first free rung of the ladder and start serving the callback.
 *
 * Binding happens BEFORE the browser is ever launched — a consent screen whose redirect
 * lands on a dead port is a failure with no error message anywhere.
 *
 * @throws EngineError `port_blocked` when every rung is occupied.
 */
export async function openLoopback(options: LoopbackOptions = {}): Promise<Loopback> {
  const host = options.host ?? REDIRECT_HOST;
  if (host !== REDIRECT_HOST && host !== LOOPBACK_IP_HOST) {
    throw new EngineError('config_invalid', 'unsanctioned loopback host spelling', {
      hint: 'Only the two spellings in engine/src/config.ts are registered with providers.',
    });
  }

  const pageOptions: PageOptions = {
    ...(options.provider === undefined ? {} : { provider: options.provider }),
    ...(options.providerIcon === undefined ? {} : { providerIcon: options.providerIcon }),
  };

  /** C-3: when set, the callback's iss + state must match the flow this provider started. */
  const providerName = options.providerName;

  type Waiter = {
    expectedState: string;
    resolve: (value: { code: string }) => void;
    reject: (reason: EngineError) => void;
    timer: NodeJS.Timeout;
  };

  let waiter: Waiter | null = null;
  /** The outcome that already happened. Late hits are answered with its page, forever. */
  let terminal: PageState | null = null;
  let closed = false;
  /** Callbacks that beat `waitForCallback()` to the socket. Drained, never dropped. */
  const parked: Array<{ params: URLSearchParams; res: ServerResponse; navigation: boolean }> = [];
  const sockets = new Set<Socket>();

  function settle(page: PageState, finish: (w: Waiter) => void): void {
    const w = waiter;
    terminal = page;
    waiter = null;
    if (w === null) return;
    clearTimeout(w.timer);
    finish(w);
  }

  /**
   * The whole security surface, in order. Anything that is not certainly the real callback
   * gets a page and leaves the mailbox open.
   */
  function handleCallback(params: URLSearchParams, res: ServerResponse, navigation: boolean): void {
    if (terminal !== null) {
      // Refresh of the success tab, a replay, or a callback that lost the race. Show what
      // actually happened; never deliver a second code.
      sendPage(res, terminal, pageOptions);
      return;
    }
    if (waiter === null) {
      // The navigation verdict is parked WITH the hit: it is a property of the request that
      // arrived, and it must not be re-derived (or lost) when the queue is drained later.
      parked.push({ params, res, navigation });
      return;
    }

    // Ownership gate (non-consuming): a state that is not this listener's — a blind guess or a
    // sibling flow's — is foreign. Show the mismatch page and KEEP LISTENING, and never touch the
    // single-use store, so a wrong guess can neither be redeemed here nor invalidate the rightful
    // flow's one-shot state. Redemption (single-use + TTL, C-2) is deferred to the code-delivery
    // path below via evaluateCallbackState, so a callback we reject on any other ground (provider
    // error, mix-up) never burns the state the real callback still needs.
    const state = params.get('state');
    if (state !== null && !constantTimeEqual(state, waiter.expectedState)) {
      sendPage(res, 'mismatch', pageOptions);
      return;
    }

    const error = params.get('error');
    if (error !== null) {
      // Providers SHOULD echo `state` on errors (RFC 6749 §4.1.2.1), and when they do the
      // check above has already authenticated this hit. A bare error with no state at all is
      // still honored — some providers drop it on cancel and the deliberate Cancel beat is
      // in the script — but only from a real top-level navigation, so a drive-by page cannot
      // cancel an in-flight connect. Anything else: the mismatch page, and KEEP LISTENING.
      if (state === null && !navigation) {
        sendPage(res, 'mismatch', pageOptions);
        return;
      }
      const providerMessage = params.get('error_description') ?? error;
      if (error === 'access_denied') {
        settle('denied', (w) => {
          w.reject(
            new EngineError('denied_by_user', 'the user declined the consent screen', {
              hint: 'Say "connect" again to retry.',
              providerMessage,
            }),
          );
        });
        sendPage(res, 'denied', pageOptions);
        return;
      }
      settle('provider_error', (w) => {
        w.reject(
          new EngineError('provider_error', 'the provider turned down the authorize request', {
            hint: 'The provider rejected the request; its own words are in providerMessage.',
            providerMessage,
          }),
        );
      });
      sendPage(res, 'provider_error', { ...pageOptions, providerMessage });
      return;
    }

    // From here a code is being offered. It is only ever accepted with a matching state.
    if (state === null) {
      sendPage(res, 'mismatch', pageOptions);
      return;
    }
    const code = params.get('code');
    if (code === null || code === '') {
      sendPage(res, 'mismatch', pageOptions);
      return;
    }

    // C-3 mix-up defense: the response must come from the provider this flow was started with.
    // `state` is guaranteed non-null here (checked above). Skipped when no providerName was
    // supplied (e.g. a bare loopback with no engine-level flow binding).
    const iss = params.get('iss');
    if (providerName !== undefined && !checkFlow(state, providerName, iss).ok) {
      sendPage(res, 'mismatch', pageOptions);
      return; // KEEP LISTENING for the real callback.
    }

    // C-2 — redeem the state HERE, the one path that hands a code back. Ownership was already
    // proven by the constant-time gate above; evaluateCallbackState re-confirms it and CONSUMES
    // it, enforcing single-use across the whole process and the TTL at redemption. A replay
    // (browser back button, a copied callback URL, an attacker resending a captured callback) or
    // a callback honored past STATE_TTL_MS is refused even though its bytes still match — and,
    // because it was not consumed on any of the reject paths above, the real callback can still
    // arrive and complete. `state` is guaranteed non-null here (checked above).
    if (evaluateCallbackState(state, waiter.expectedState) !== 'accept') {
      sendPage(res, 'mismatch', pageOptions);
      return; // replayed or expired — KEEP LISTENING for the real one.
    }

    settle('success', (w) => w.resolve({ code }));
    sendPage(res, 'success', pageOptions);
  }

  function onRequest(req: IncomingMessage, res: ServerResponse): void {
    // Base is a placeholder authority: we only ever read pathname + query from it.
    const url = new URL(req.url ?? '/', 'http://loopback.invalid');
    if (url.pathname !== CALLBACK_PATH) {
      sendPlain(res, 404, 'not found');
      return;
    }
    if (req.method !== 'GET') {
      res.setHeader('allow', 'GET');
      sendPlain(res, 405, 'method not allowed');
      return;
    }
    handleCallback(url.searchParams, res, looksLikeNavigation(req));
  }

  /* ── ladder walk (C-15: reclaim our own orphan, never touch anyone else) ── */

  /**
   * Bind one rung. Returns the live server, `'in-use'` when the rung is held (either stack), or
   * throws `EngineError` on a hard bind failure. The §A3 dual-stack→IPv4 fallback lives here so
   * the walk below stays a plain "bound / occupied / retry" decision.
   */
  const attemptListen = async (candidate: number): Promise<Server | 'in-use'> => {
    const server = createServer(onRequest);
    try {
      await listen(server, candidate, '::');
      return server;
    } catch (err) {
      await closeServer(server);
      const errno = errnoOf(err);
      if (errno === 'EADDRINUSE') return 'in-use';
      if (!NO_IPV6.has(errno)) {
        throw new EngineError('port_blocked', 'could not bind the loopback callback port', {
          hint: `Binding ${REDIRECT_HOST} failed with ${errno || 'an unknown error'}. Free the port and retry.`,
          cause: err,
        });
      }
      // §A3 fallback: this machine cannot do dual-stack. v4 only, and say so out loud.
      const v4 = createServer(onRequest);
      try {
        await listen(v4, candidate, LOOPBACK_IP_HOST);
        process.stderr.write(
          `[voiceos-connect] WARNING: dual-stack bind failed (${errno}); listening on IPv4 only. ` +
            'A browser that resolves the callback host to ::1 will not reach it.\n',
        );
        return v4;
      } catch (err2) {
        await closeServer(v4);
        if (errnoOf(err2) === 'EADDRINUSE') return 'in-use';
        throw new EngineError('port_blocked', 'could not bind the loopback callback port', {
          hint: `IPv4 fallback failed with ${errnoOf(err2) || 'an unknown error'}.`,
          cause: err2,
        });
      }
    }
  };

  let bound: { server: Server; port: number } | null = null;
  /** Why each rung we could not take is busy — surfaced only if the whole ladder is occupied. */
  const occupied: string[] = [];

  for (const candidate of PORT_LADDER) {
    let result = await attemptListen(candidate);
    if (result === 'in-use') {
      // C-15 layer 3: the rung is held. Reclaim it ONLY if it is provably our own orphan — a
      // crashed earlier flow of ours, proven by the PID + executable recorded in the lockfile we
      // wrote — then retry the bind once. Anything else is reported and left strictly alone
      // (INV-REDIR-4): an authorization flow that terminates unrelated software on the user's
      // machine is a worse bug than the busy port it is working around.
      const reclaim = reclaimPort(candidate);
      if (reclaim.outcome === 'reclaimed' || reclaim.outcome === 'free') {
        result = await attemptListen(candidate);
      } else if (reclaim.outcome === 'held-by-other') {
        occupied.push(`:${candidate} is held by ${reclaim.holderName} (pid ${reclaim.holderPid})`);
      } else {
        occupied.push(`:${candidate} is in use (holder could not be identified)`);
      }
    }
    if (result !== 'in-use') {
      bound = { server: result, port: candidate };
      break;
    }
  }

  if (bound === null) {
    throw new EngineError('port_blocked', 'every port on the callback ladder is in use', {
      hint:
        occupied.length > 0
          ? `${occupied.join('; ')}. Free one of ${PORT_LADDER.join(', ')} and try again.`
          : `Something else is using ${PORT_LADDER.join(', ')}. Close it (lsof -i :${PORT_LADDER[0]}) and try again.`,
    });
  }

  // C-15: record ownership of the rung we took, so a future run that finds this port still held by
  // a crashed instance of ours can recognize its own orphan and reclaim it. The lockfile lives in
  // tmpdir and carries only a PID, an executable path, a non-credential flow nonce, and a
  // timestamp — never the OAuth state or the PKCE verifier — so it neither leaks a secret nor
  // writes anything to the working tree.
  writeLock(bound.port, randomBytes(16).toString('hex'));

  const { server, port } = bound;
  server.on('connection', (socket: Socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  // Keep-alive would hold the port after close(); the demo may need to rebind immediately.
  server.keepAliveTimeout = 1;

  return {
    port,
    redirectUri: resolveRedirectUri(port, host),

    waitForCallback(expectedState: string, timeoutMs: number): Promise<{ code: string }> {
      if (closed) {
        return Promise.reject(
          new EngineError('timeout', 'the loopback listener is already closed', {
            hint: 'Open a new loopback before waiting for a callback.',
          }),
        );
      }
      if (waiter !== null || terminal !== null) {
        return Promise.reject(
          new EngineError('config_invalid', 'this loopback has already been used', {
            hint: 'One loopback delivers exactly one callback. Open a new one per connect.',
          }),
        );
      }
      if (expectedState === '') {
        return Promise.reject(
          new EngineError('config_invalid', 'expectedState must not be empty', {
            hint: 'Mint a state with state.ts before opening the browser.',
          }),
        );
      }

      return new Promise<{ code: string }>((resolve, reject) => {
        const timer = setTimeout(() => {
          settle('timeout', (w) => {
            w.reject(
              new EngineError('timeout', 'no callback arrived before the deadline', {
                hint: 'Say "connect" again to start a fresh request.',
              }),
            );
          });
        }, timeoutMs);
        // Do not hold the process open on the timer alone.
        timer.unref?.();
        waiter = { expectedState, resolve, reject, timer };

        // Anything that arrived before we started waiting is answered now, in order.
        const early = parked.splice(0, parked.length);
        for (const hit of early) handleCallback(hit.params, hit.res, hit.navigation);
      });
    },

    async close(): Promise<void> {
      if (closed) return;
      closed = true;

      // C-15: drop our port-ownership lockfile first — a listener we are closing is not an orphan,
      // and a stale lockfile pointing at a since-recycled PID is exactly what the reclaim guard
      // must never mistake for one. Idempotent and best-effort.
      removeLock(port);

      const early = parked.splice(0, parked.length);
      for (const hit of early) sendPage(hit.res, terminal ?? 'timeout', pageOptions);

      if (waiter !== null) {
        settle(terminal ?? 'timeout', (w) => {
          w.reject(
            new EngineError('timeout', 'the loopback closed before a callback arrived', {
              hint: 'Say "connect" again to start a fresh request.',
            }),
          );
        });
      }

      await closeServer(server);
      for (const socket of sockets) socket.destroy();
      sockets.clear();
    },
  };
}
