/**
 * C-15 — redirect reclaim (SPEC §7, layer 3).
 *
 * A fixed registered port is a shared resource on the user's machine. When every rung of the
 * ladder is held, the engine inspects each holder and acts by exactly one rule:
 *
 *   - A port held by OUR OWN ABANDONED listener — an aged-out earlier flow of ours — is
 *     reclaimed: the stale process is terminated and the port is free to rebind, silently,
 *     because our own mess is ours to clean up. Ownership is proven, not guessed: a lockfile
 *     we wrote carries our PID and a flow nonce, the live holder's PID must equal it, the
 *     holder's executable must match the one we recorded, AND the lock must be older than any
 *     real flow's lifetime ({@link RECLAIM_STALE_MS}). That last clause is the one that keeps a
 *     PID+exe match from firing on a LIVE SIBLING instance mid-flow — the deployment runs five
 *     MCP processes, and killing a healthy one is the exact INV-REDIR-4 failure this prevents.
 *   - A port held by ANYTHING ELSE — a foreign process, or a live sibling of ours whose lock is
 *     still fresh — is reported by name and PID with a retry action, and is NEVER touched; the
 *     caller walks to the next ladder rung. An authorization flow that terminates unrelated (or
 *     sibling) software on the user's machine is a worse bug than the one it is fixing.
 *   - Where process identification requires permissions the engine does not have, the port is
 *     reported busy WITHOUT a name, rather than failing or guessing.
 *
 * The lockfile is a temp file, so it carries NO secret — only a PID, an executable path, a
 * non-credential flow nonce, and a timestamp. The OAuth `state` and the PKCE verifier never
 * touch it.
 *
 * Everything that talks to the OS is behind the injectable `PortProbe` / lock IO seams, so the
 * decision logic is tested deterministically without spawning or killing real processes.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * How old a matching lock must be before its still-alive holder is treated as an ABANDONED
 * orphan rather than a LIVE SIBLING.
 *
 * The subtlety INV-REDIR-4 turns on: a lockfile whose PID equals the live holder's PID proves
 * only "the process that bound this port is still running" — which is EXACTLY as true for a
 * healthy sibling instance mid-flow as for a hung leftover. PID + executable alone cannot tell
 * them apart, so reclaiming on that basis SIGTERMs a live sibling (the deployment is five MCP
 * processes; §refresh.ts:6-9). The discriminator is the lock's age: an interactive loopback
 * flow binds the port, waits for the browser callback, and closes in well under this window, so
 * a lock younger than it belongs to a flow that is still live and is never touched — the caller
 * simply walks to the next ladder rung. Only a lock older than any real flow's lifetime, whose
 * holder is still bound, is a genuinely abandoned listener safe to reclaim.
 */
export const RECLAIM_STALE_MS = 600_000; // 10 minutes — beyond any real interactive flow.

/* ─────────────────────────────── the lockfile ─────────────────────────────── */

/** What we write next to a port we bind, so a future run can recognize its own orphan. */
export interface PortLock {
  port: number;
  /** The PID that bound the port. */
  pid: number;
  /** A non-credential correlation id for the flow that bound it. Never the OAuth state/verifier. */
  nonce: string;
  /** The executable that bound it, recorded so a future run can confirm identity vs PID reuse. */
  exe: string;
  /** Epoch ms of the write. */
  writtenAt: number;
}

/** The one place lockfiles live. `tmpdir()` survives our crash but not a reboot — exactly right. */
export function lockPath(port: number): string {
  return join(tmpdir(), `voiceos-oauth-port.${port}.lock`);
}

/**
 * Record ownership of a freshly-bound `port`. Written 0600 (owner-only). `nonce` is a
 * correlation id; generate a fresh one per flow. Returns the lock it wrote.
 */
export function writeLock(port: number, nonce: string): PortLock {
  const lock: PortLock = { port, pid: process.pid, nonce, exe: process.execPath, writtenAt: Date.now() };
  writeFileSync(lockPath(port), JSON.stringify(lock), { encoding: 'utf8', mode: 0o600 });
  return lock;
}

/** Read the lockfile for `port`, or null if absent / unreadable / malformed. */
export function readLock(port: number): PortLock | null {
  let text: string;
  try {
    text = readFileSync(lockPath(port), 'utf8');
  } catch {
    return null;
  }
  try {
    const parsed = JSON.parse(text) as Partial<PortLock>;
    if (
      typeof parsed.port === 'number' &&
      typeof parsed.pid === 'number' &&
      typeof parsed.nonce === 'string' &&
      typeof parsed.exe === 'string' &&
      typeof parsed.writtenAt === 'number'
    ) {
      return { port: parsed.port, pid: parsed.pid, nonce: parsed.nonce, exe: parsed.exe, writtenAt: parsed.writtenAt };
    }
  } catch {
    // Malformed lock — treat as absent.
  }
  return null;
}

/** Remove the lockfile for `port`. Idempotent. */
export function removeLock(port: number): void {
  try {
    rmSync(lockPath(port), { force: true });
  } catch {
    // Best-effort cleanup.
  }
}

/* ─────────────────────────────── the OS probe (injectable) ─────────────────────────────── */

/** Who is listening on a port. */
export interface PortHolder {
  pid: number;
  /** The command/executable name the OS reports. */
  name: string;
}

/** The four OS facts the reclaim decision needs. Injected in tests; real impls below. */
export interface PortProbe {
  /** The listener on `port`, or null when nothing is found OR we cannot tell (no perms). */
  holderOf(port: number): PortHolder | null;
  /** Is `pid` a live process? */
  isAlive(pid: number): boolean;
  /** The executable path for `pid`, or null when we cannot read it. */
  executableOf(pid: number): string | null;
  /** Terminate `pid`. Returns true on success. Called ONLY after ownership is proven. */
  terminate(pid: number): boolean;
}

/** macOS/unix implementation. Pure spawns of first-party tools; no runtime dependency. */
export const defaultProbe: PortProbe = {
  holderOf(port: number): PortHolder | null {
    let out: string;
    try {
      out = execFileSync('/usr/sbin/lsof', ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN', '-F', 'pc'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
    } catch {
      // lsof exits non-zero when nothing holds the port, and can be absent/blocked. Either
      // way we cannot name a holder.
      return null;
    }
    // `-F pc` emits, per process: a line `p<pid>` then a line `c<command>`.
    let pid: number | null = null;
    for (const line of out.split('\n')) {
      if (line.startsWith('p')) {
        const n = Number(line.slice(1));
        pid = Number.isInteger(n) ? n : null;
      } else if (line.startsWith('c') && pid !== null) {
        return { pid, name: line.slice(1) };
      }
    }
    return null;
  },
  isAlive(pid: number): boolean {
    try {
      process.kill(pid, 0);
      return true;
    } catch (err) {
      // EPERM means the process exists but we may not signal it — still alive.
      return (err as NodeJS.ErrnoException).code === 'EPERM';
    }
  },
  executableOf(pid: number): string | null {
    try {
      const out = execFileSync('/bin/ps', ['-p', String(pid), '-o', 'comm='], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      const line = out.trim();
      return line === '' ? null : line;
    } catch {
      return null;
    }
  },
  terminate(pid: number): boolean {
    try {
      process.kill(pid, 'SIGTERM');
      return true;
    } catch {
      return false;
    }
  },
};

/* ─────────────────────────────── the decision ─────────────────────────────── */

/**
 * The verdict for one occupied port. `reclaimed`/`free` mean the caller may retry the bind;
 * `held-by-other`/`held-unknown` mean it must not, and carry what to tell the user.
 */
export type ReclaimResult =
  | { outcome: 'reclaimed'; port: number; pid: number }
  | { outcome: 'free'; port: number }
  | { outcome: 'held-by-other'; port: number; holderName: string; holderPid: number }
  | { outcome: 'held-unknown'; port: number };

export interface ReclaimDeps {
  probe: PortProbe;
  readLock: (port: number) => PortLock | null;
  removeLock: (port: number) => void;
  /** Wall clock, injected so the orphan-vs-sibling age test is deterministic. */
  now: () => number;
}

const REAL_DEPS: ReclaimDeps = { probe: defaultProbe, readLock, removeLock, now: () => Date.now() };

/**
 * Decide what to do about a port that failed to bind with EADDRINUSE.
 *
 * Reclaim test, ALL of which must hold: a lockfile exists for this port, its recorded PID equals
 * the live holder's PID, that PID is NOT this live process, that PID is alive, — when the
 * executable is readable — it matches the one the lockfile recorded (the guard against PID
 * reuse), AND the lock is older than {@link RECLAIM_STALE_MS}. When the executable cannot be read
 * at all, the lockfile PID match is trusted on its own, because only our own code writes it.
 *
 * The age clause is what separates the two things a PID+exe match cannot: an ABANDONED orphan (an
 * aged-out earlier flow of ours, safe to terminate) from a LIVE SIBLING (a second MCP instance
 * whose connect() is holding the rung right now — killing it is the INV-REDIR-4 bug). A holder
 * whose PID is our own is never reclaimed either — that is our own live listener; the current PID
 * is excluded before terminate can be reached. In every non-reclaim case the caller just walks to
 * the next rung, exactly as it would for any other occupied port.
 */
export function reclaimPort(port: number, deps: Partial<ReclaimDeps> = {}): ReclaimResult {
  const { probe, readLock: read, removeLock: remove, now } = { ...REAL_DEPS, ...deps };

  const lock = read(port);
  const holder = probe.holderOf(port);

  if (holder === null) {
    // The port is held (the caller only calls us on EADDRINUSE) but we cannot see by whom.
    // If our lockfile is stale (its PID is dead), clean it up; either way, don't guess.
    if (lock !== null && !probe.isAlive(lock.pid)) remove(port);
    return { outcome: 'held-unknown', port };
  }

  // Does this look like a listener WE bound? PID match, not us, alive, executable match. This is
  // necessary but NOT sufficient: it is equally true of a healthy sibling instance mid-flow.
  const looksOurs =
    lock !== null &&
    holder.pid === lock.pid &&
    holder.pid !== process.pid &&
    probe.isAlive(lock.pid) &&
    executableMatches(probe.executableOf(holder.pid), lock.exe);

  // A lock younger than a real flow's lifetime belongs to a LIVE SIBLING that is still using the
  // port — terminating it is the INV-REDIR-4 failure this module exists to prevent. Leave it be
  // and its lock intact; the caller walks to the next ladder rung. Only an aged-out lock whose
  // holder is still bound is an abandoned orphan we may reclaim.
  const abandoned = looksOurs && now() - (lock as PortLock).writtenAt > RECLAIM_STALE_MS;

  if (abandoned) {
    if (probe.terminate(holder.pid)) {
      remove(port);
      return { outcome: 'reclaimed', port, pid: holder.pid };
    }
    // We proved it was ours but could not kill it. Do not claim the port is free; surface it
    // as busy under its own name so the user (who can) frees it.
    return { outcome: 'held-by-other', port, holderName: holder.name, holderPid: holder.pid };
  }

  // Either a foreign holder, or a live sibling of ours mid-flow (looksOurs but not yet aged out).
  // Both are left strictly alone. Only clean up a lockfile that is genuinely stale — its PID dead,
  // or a different holder now owns the port; a live sibling's own current lock is preserved so it
  // can still recognize its rung.
  if (lock !== null && (!probe.isAlive(lock.pid) || holder.pid !== lock.pid)) remove(port);
  return { outcome: 'held-by-other', port, holderName: holder.name, holderPid: holder.pid };
}

/** Executable identity check. Unreadable (null) is accepted; a readable mismatch is not. */
function executableMatches(actual: string | null, recorded: string): boolean {
  return actual === null || actual === recorded;
}
