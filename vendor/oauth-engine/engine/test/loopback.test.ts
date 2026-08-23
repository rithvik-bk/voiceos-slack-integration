/**
 * P1-I3 tests — real HTTP against a real bound port.
 *
 * Nothing here is mocked: every assertion is a browser-shaped request (node `fetch`) to the
 * socket the engine actually bound, because every bug this listener can have — the wrong
 * stack answering, a wrong-state hit killing the mailbox, a port that stays held after
 * close — is invisible to a test that calls the handler function directly.
 *
 * Host spellings are assembled from bare host strings so this file never contains a second
 * spelling of a redirect URI (tools/drift-check.mjs).
 */

import { createServer, request as httpRequest } from 'node:http';
import type { Server } from 'node:http';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { CALLBACK_PATH, PORT_LADDER, redirectUri } from '../src/config.ts';
import { EngineError } from '../src/index.ts';
import { openLoopback } from '../src/loopback.ts';
import type { Loopback } from '../src/loopback.ts';
import { clearStates, consumeState, mintState } from '../src/state.ts';

/** The three names for one mailbox (§A3). Bare hosts, composed into URLs at call time. */
const HOSTS = ['localhost', '127.0.0.1', '[::1]'] as const;

const CODE = 'authcode-abc123';
/**
 * A REAL minted state, not a fabricated string. loopback.ts now redeems the callback's state
 * through the single-use + TTL store (C-2), so the success cases must present a state the store
 * actually minted — a made-up constant would be redeemed as `stale` and never deliver a code.
 * Re-minted before every test (the store is process-global) so each test owns exactly one.
 */
let STATE: string;

beforeEach(() => {
  clearStates();
  STATE = mintState();
});

/** Everything opened by a test, torn down even when the test fails. */
const openLoopbacks: Loopback[] = [];
const squatters: Server[] = [];

async function open(...args: Parameters<typeof openLoopback>): Promise<Loopback> {
  const lb = await openLoopback(...args);
  openLoopbacks.push(lb);
  return lb;
}

/** Occupy a ladder rung the way a stray dev server would. */
function squat(port: number): Promise<void> {
  const server = createServer((_req, res) => res.end('squatter'));
  squatters.push(server);
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ port, host: '::', ipv6Only: false }, () => resolve());
  });
}

function callbackUrl(host: string, port: number, query: Record<string, string>): string {
  const qs = new URLSearchParams(query).toString();
  return `http://${host}:${port}${CALLBACK_PATH}${qs === '' ? '' : `?${qs}`}`;
}

async function hit(
  host: string,
  port: number,
  query: Record<string, string>,
  init?: RequestInit,
): Promise<{ status: number; body: string }> {
  const res = await fetch(callbackUrl(host, port, query), init);
  return { status: res.status, body: await res.text() };
}

/**
 * A raw request, because `fetch` cannot send fetch metadata: `Sec-Fetch-Mode` is a forbidden
 * header name, and undici overwrites whatever you set with `cors`. The headers under test are
 * exactly the ones only a browser may set, so the test speaks HTTP directly.
 */
function rawHit(
  port: number,
  query: Record<string, string>,
  headers: Record<string, string>,
): Promise<{ status: number; body: string }> {
  const path = `${CALLBACK_PATH}?${new URLSearchParams(query).toString()}`;
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: 'localhost', port, path, method: 'GET', headers }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => {
        body += chunk;
      });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

/**
 * Attach the rejection handler at CREATION time, not after the awaits that trigger it.
 * A promise whose rejection is handled three lines later is still an unhandled rejection at
 * the moment it rejects, and a suite that prints those is a suite people stop reading.
 */
function settled<T>(p: Promise<T>): Promise<T | EngineError> {
  return p.then(
    (value) => value,
    (err: unknown) => err as EngineError,
  );
}

/** Did the promise settle yet? Used to prove a wrong-state hit did NOT end the wait. */
async function isPending(p: Promise<unknown>): Promise<boolean> {
  let settled = false;
  const mark = (): void => {
    settled = true;
  };
  p.then(mark, mark);
  await new Promise((r) => setTimeout(r, 25));
  return !settled;
}

afterEach(async () => {
  clearStates();
  await Promise.all(openLoopbacks.splice(0).map((lb) => lb.close().catch(() => undefined)));
  await Promise.all(
    squatters.splice(0).map(
      (s) =>
        new Promise<void>((resolve) => {
          s.closeAllConnections?.();
          s.close(() => resolve());
        }),
    ),
  );
});

describe('openLoopback — binding and the ladder', () => {
  it('binds the first rung and reports the ladder spelling of the redirect URI', async () => {
    const lb = await open();
    expect(lb.port).toBe(PORT_LADDER[0]);
    expect(lb.redirectUri).toBe(redirectUri(lb.port));
  });

  it('walks to the next rung when the first is occupied', async () => {
    await squat(PORT_LADDER[0]!);
    const lb = await open();
    expect(lb.port).toBe(PORT_LADDER[1]);
    expect(lb.redirectUri).toBe(redirectUri(PORT_LADDER[1]!));
  });

  it('walks to the last rung when the first two are occupied', async () => {
    await squat(PORT_LADDER[0]!);
    await squat(PORT_LADDER[1]!);
    const lb = await open();
    expect(lb.port).toBe(PORT_LADDER[2]);
  });

  it('throws port_blocked — not a crash — when the whole ladder is occupied', async () => {
    for (const port of PORT_LADDER) await squat(port);
    const err = await settled(openLoopback());
    expect(err).toBeInstanceOf(EngineError);
    expect((err as EngineError).code).toBe('port_blocked');
    expect((err as EngineError).hint).toContain(String(PORT_LADDER[0]));
  });
});

describe('one socket, three hostnames (§A3)', () => {
  for (const host of HOSTS) {
    it(`delivers the callback arriving on ${host}`, async () => {
      const lb = await open();
      const waiting = lb.waitForCallback(STATE, 5_000);
      const res = await hit(host, lb.port, { code: CODE, state: STATE });

      expect(res.status).toBe(200);
      expect(res.body).toContain('connected');
      await expect(waiting).resolves.toEqual({ code: CODE });
    });
  }

  it('answers all three hostnames from the same single mailbox', async () => {
    const lb = await open();
    const waiting = lb.waitForCallback(STATE, 5_000);

    // Two of the three names knock with the wrong state; the mailbox survives both.
    for (const host of ['[::1]', '127.0.0.1']) {
      const res = await hit(host, lb.port, { code: CODE, state: 'not-the-state-we-minted' });
      expect(res.status).toBe(200);
      expect(res.body).toContain('didn&rsquo;t match');
    }
    expect(await isPending(waiting)).toBe(true);

    // ...and the third name still delivers the real one.
    await hit('localhost', lb.port, { code: CODE, state: STATE });
    await expect(waiting).resolves.toEqual({ code: CODE });
  });
});

describe('callback routing', () => {
  it('serves only GET on the callback path', async () => {
    const lb = await open();
    const post = await hit('localhost', lb.port, { code: CODE, state: STATE }, { method: 'POST' });
    expect(post.status).toBe(405);

    const [host] = HOSTS;
    const other = await fetch(`http://${host!}:${lb.port}/not-the-callback`);
    expect(other.status).toBe(404);
    await other.text();
  });

  it('shows the denied page and rejects denied_by_user on ?error=access_denied', async () => {
    const lb = await open();
    const waiting = settled(lb.waitForCallback(STATE, 5_000));
    const res = await hit('localhost', lb.port, { error: 'access_denied', state: STATE });

    expect(res.status).toBe(200);
    expect(res.body).toContain('Nothing was connected.');
    const err = await waiting;
    expect((err as EngineError).code).toBe('denied_by_user');
  });

  it('shows the provider_error page with the provider’s own words on any other error', async () => {
    const lb = await open();
    const waiting = settled(lb.waitForCallback(STATE, 5_000));
    const res = await hit('localhost', lb.port, {
      error: 'pkce_not_allowed',
      error_description: 'PKCE is not enabled for this app',
      state: STATE,
    });

    expect(res.body).toContain('turned down');
    expect(res.body).toContain('PKCE is not enabled for this app');
    // The state-mismatch words must NOT be on the projector for a provider refusal.
    expect(res.body).not.toContain('didn&rsquo;t match the request');

    const err = await waiting;
    expect((err as EngineError).code).toBe('provider_error');
    expect((err as EngineError).providerMessage).toBe('PKCE is not enabled for this app');
  });

  /**
   * W11 (docs/THREAT-MODEL.md), fixed in audit fix round 1.
   *
   * A state-less `?error=access_denied` used to settle the flow for ANYONE who could send the
   * request — including a web page firing a no-preflight GET at localhost, which would cancel
   * an in-flight connect from the internet. It is still honored (Slack's docs never say
   * whether Cancel echoes `state`, and the Cancel beat is in the script), but only from a real
   * top-level navigation, which a cross-site fetch cannot forge.
   */
  it('ignores a state-less error that is NOT a browser navigation, and keeps listening', async () => {
    const lb = await open();
    const waiting = lb.waitForCallback(STATE, 5_000);

    const driveBy = await rawHit(
      lb.port,
      { error: 'access_denied' },
      { 'sec-fetch-dest': 'image', 'sec-fetch-mode': 'no-cors', 'sec-fetch-site': 'cross-site' },
    );
    expect(driveBy.body).toContain('didn&rsquo;t match');
    expect(driveBy.body).not.toContain('You declined');
    expect(await isPending(waiting)).toBe(true);

    // …and the real callback, arriving after the attempt, is still accepted.
    await hit('localhost', lb.port, { code: CODE, state: STATE });
    await expect(waiting).resolves.toEqual({ code: CODE });
  });

  it('still honors the deliberate Cancel beat when the provider drops state', async () => {
    for (const headers of [
      { 'sec-fetch-dest': 'document', 'sec-fetch-mode': 'navigate' }, // a current browser
      {}, // a browser too old to send fetch metadata: accepted, deliberately
    ]) {
      const lb = await open();
      const waiting = settled(lb.waitForCallback(STATE, 5_000));
      const res = await rawHit(lb.port, { error: 'access_denied' }, headers);

      expect(res.body).toContain('Nothing was connected.');
      expect((await waiting as EngineError).code).toBe('denied_by_user');
      await lb.close();
    }
  });

  it('keeps listening after a wrong-state hit, and after a code with no state at all', async () => {
    const lb = await open();
    const waiting = lb.waitForCallback(STATE, 5_000);

    const wrongState = await hit('localhost', lb.port, { code: 'attacker-code', state: 'wrong' });
    expect(wrongState.body).toContain('didn&rsquo;t match');
    const noState = await hit('localhost', lb.port, { code: 'attacker-code' });
    expect(noState.body).toContain('didn&rsquo;t match');
    expect(await isPending(waiting)).toBe(true);

    await hit('localhost', lb.port, { code: CODE, state: STATE });
    await expect(waiting).resolves.toEqual({ code: CODE });
  });

  it('answers callbacks that arrive before waitForCallback instead of dropping them', async () => {
    const lb = await open();
    const early = hit('localhost', lb.port, { code: CODE, state: STATE });
    // Give the request time to land on a listener that is not waiting yet.
    await new Promise((r) => setTimeout(r, 50));

    const waiting = lb.waitForCallback(STATE, 5_000);
    await expect(waiting).resolves.toEqual({ code: CODE });
    expect((await early).body).toContain('connected');
  });
});

describe('single delivery', () => {
  it('resolves once; duplicate and late hits get the page for what already happened', async () => {
    const lb = await open();
    const waiting = lb.waitForCallback(STATE, 5_000);
    const first = await hit('localhost', lb.port, { code: CODE, state: STATE });
    await expect(waiting).resolves.toEqual({ code: CODE });

    const replay = await hit('localhost', lb.port, { code: CODE, state: STATE });
    expect(replay.status).toBe(200);
    expect(replay.body).toBe(first.body); // the already-used answer is the outcome page

    // ...and the code cannot be handed out a second time.
    const err = await settled(lb.waitForCallback(STATE, 5_000));
    expect((err as EngineError).code).toBe('config_invalid');
  });

  it('late hits after a denial show the denied page, not a success', async () => {
    const lb = await open();
    const waiting = settled(lb.waitForCallback(STATE, 5_000));
    await hit('localhost', lb.port, { error: 'access_denied', state: STATE });
    await waiting;

    const late = await hit('localhost', lb.port, { code: CODE, state: STATE });
    expect(late.body).toContain('Nothing was connected.');
    expect(late.body).not.toContain('You&rsquo;re connected.');
  });
});

describe('state redemption (C-2 wiring — single-use + TTL, not just a byte compare)', () => {
  /**
   * The bug C-2 closes: loopback.ts used to accept a callback whose `state` merely MATCHED the
   * one this listener minted, without redeeming it through the single-use store. This proves the
   * store is actually on the code-delivery path — a state already consumed (a replay, or another
   * flow having redeemed it) is refused even though its bytes still match, and the listener keeps
   * waiting for the real one. A bare constant-time compare would (wrongly) deliver the code here.
   */
  it('refuses a callback whose state was already redeemed, and keeps listening', async () => {
    const lb = await open();
    const waiting = lb.waitForCallback(STATE, 5_000);

    // Burn the state out-of-band — exactly what a replay or a sibling flow's redemption does.
    expect(consumeState(STATE)).toBe(true);

    const res = await hit('localhost', lb.port, { code: CODE, state: STATE });
    expect(res.body).toContain('didn&rsquo;t match'); // refused as stale, code never delivered
    expect(await isPending(waiting)).toBe(true); // …and the mailbox is still open
  });
});

describe('timeout', () => {
  it('rejects with timeout and serves the timeout page to anything that arrives late', async () => {
    const lb = await open();
    const err = await settled(lb.waitForCallback(STATE, 60));
    expect(err).toBeInstanceOf(EngineError);
    expect((err as EngineError).code).toBe('timeout');

    const late = await hit('localhost', lb.port, { code: CODE, state: STATE });
    expect(late.body).toContain('took too long');
  });

  it('rejects an in-flight wait when the listener is closed under it', async () => {
    const lb = await open();
    const waiting = settled(lb.waitForCallback(STATE, 5_000));
    await lb.close();
    expect(((await waiting) as EngineError).code).toBe('timeout');
  });
});

describe('close', () => {
  it('is idempotent and frees the port immediately', async () => {
    const lb = await open();
    const waiting = lb.waitForCallback(STATE, 5_000);
    await hit('localhost', lb.port, { code: CODE, state: STATE });
    await waiting;

    await lb.close();
    await lb.close(); // idempotent: a second close is a no-op, not a throw

    // The port is genuinely free: rebind it right now, no retry loop, no grace period.
    await expect(squat(lb.port)).resolves.toBeUndefined();
    await expect(fetch(callbackUrl('localhost', lb.port, {}))).resolves.toBeTruthy();
  });
});

describe('redaction', () => {
  it('never writes the code or state to stdout, stderr or the console', async () => {
    const written: string[] = [];
    const record = (chunk: unknown): void => {
      written.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk as Uint8Array).toString('utf8'));
    };
    const stdoutWrite = process.stdout.write.bind(process.stdout) as (...a: unknown[]) => boolean;
    const stderrWrite = process.stderr.write.bind(process.stderr) as (...a: unknown[]) => boolean;
    const originals = { log: console.log, warn: console.warn, error: console.error, info: console.info };
    const capture = (...args: unknown[]): void => {
      written.push(args.map((a) => String(a)).join(' '));
    };

    process.stdout.write = ((chunk: unknown, ...rest: unknown[]) => {
      record(chunk);
      return stdoutWrite(chunk, ...rest);
    }) as typeof process.stdout.write;
    process.stderr.write = ((chunk: unknown, ...rest: unknown[]) => {
      record(chunk);
      return stderrWrite(chunk, ...rest);
    }) as typeof process.stderr.write;
    console.log = capture;
    console.warn = capture;
    console.error = capture;
    console.info = capture;

    try {
      const lb = await open();
      const waiting = lb.waitForCallback(STATE, 5_000);
      const page = await hit('localhost', lb.port, { code: CODE, state: STATE });
      await waiting;
      await lb.close();

      // Not in any log stream...
      const log = written.join('\n');
      expect(log).not.toContain(CODE);
      expect(log).not.toContain(STATE);
      // ...and not rendered into the screen-shared page either.
      expect(page.body).not.toContain(CODE);
      expect(page.body).not.toContain(STATE);
    } finally {
      process.stdout.write = stdoutWrite as typeof process.stdout.write;
      process.stderr.write = stderrWrite as typeof process.stderr.write;
      Object.assign(console, originals);
    }
  });
});
