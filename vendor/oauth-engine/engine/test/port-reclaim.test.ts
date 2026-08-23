/**
 * C-15 redirect-reclaim tests (SPEC §7 layer 3, INV-REDIR-4).
 *
 * The one rule that matters: reclaim ONLY what is provably ours; never touch anything else.
 * The OS is behind an injectable probe, so the decision logic is exercised without spawning or
 * killing real processes. The lockfile round-trip is tested against a real temp file.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  type PortHolder,
  type PortLock,
  type PortProbe,
  RECLAIM_STALE_MS,
  lockPath,
  readLock,
  reclaimPort,
  removeLock,
  writeLock,
} from '../src/port-reclaim.ts';

/** A probe whose four facts are all fixtures. Any not-overridden fact is a safe default. */
function fakeProbe(overrides: Partial<PortProbe> = {}): PortProbe {
  return {
    holderOf: () => null,
    isAlive: () => true,
    executableOf: () => null,
    terminate: () => true,
    ...overrides,
  };
}

function lock(port: number, over: Partial<PortLock> = {}): PortLock {
  return { port, pid: 4242, nonce: 'flow-nonce', exe: '/our/node', writtenAt: Date.now(), ...over };
}

/** A lock old enough that its still-alive holder is an abandoned orphan, not a live sibling. */
function staleLock(port: number, over: Partial<PortLock> = {}): PortLock {
  return lock(port, { writtenAt: Date.now() - RECLAIM_STALE_MS - 60_000, ...over });
}

describe('reclaimPort — reclaim ours', () => {
  it('terminates our abandoned orphan and frees the port when PID + executable match an aged-out lock', () => {
    const holder: PortHolder = { pid: 4242, name: 'node' };
    const terminate = vi.fn(() => true);
    const remove = vi.fn();
    const probe = fakeProbe({
      holderOf: () => holder,
      isAlive: () => true,
      executableOf: () => '/our/node',
      terminate,
    });

    const result = reclaimPort(33418, { probe, readLock: () => staleLock(33418), removeLock: remove });

    expect(result).toEqual({ outcome: 'reclaimed', port: 33418, pid: 4242 });
    expect(terminate).toHaveBeenCalledWith(4242);
    expect(remove).toHaveBeenCalledWith(33418);
  });

  it('does NOT terminate a LIVE SIBLING: a fresh lock whose PID + executable match is left alone', () => {
    // INV-REDIR-4, the whole point: a PID+exe match is equally true of a healthy sibling
    // instance mid-flow. A lock younger than a real flow's lifetime means the holder is still
    // using the port; killing it would take down a running MCP server. Leave it; walk the ladder.
    const terminate = vi.fn(() => true);
    const remove = vi.fn();
    const probe = fakeProbe({
      holderOf: () => ({ pid: 4242, name: 'node' }),
      isAlive: () => true,
      executableOf: () => '/our/node',
      terminate,
    });

    const result = reclaimPort(33418, { probe, readLock: () => lock(33418), removeLock: remove });

    expect(result).toEqual({ outcome: 'held-by-other', port: 33418, holderName: 'node', holderPid: 4242 });
    expect(terminate).not.toHaveBeenCalled();
    // The live sibling's own current lock must be preserved so it still owns its rung.
    expect(remove).not.toHaveBeenCalled();
  });

  it('trusts the lockfile PID match when the executable cannot be read (no perms)', () => {
    const probe = fakeProbe({
      holderOf: () => ({ pid: 4242, name: 'node' }),
      executableOf: () => null,
      terminate: () => true,
    });
    const result = reclaimPort(33418, { probe, readLock: () => staleLock(33418), removeLock: () => undefined });
    expect(result.outcome).toBe('reclaimed');
  });

  it('does NOT reclaim when the executable is readable but mismatches (PID reuse)', () => {
    const terminate = vi.fn(() => true);
    const probe = fakeProbe({
      holderOf: () => ({ pid: 4242, name: 'Postgres' }),
      executableOf: () => '/usr/local/bin/postgres',
      terminate,
    });
    const result = reclaimPort(33418, { probe, readLock: () => lock(33418), removeLock: () => undefined });
    expect(result).toEqual({ outcome: 'held-by-other', port: 33418, holderName: 'Postgres', holderPid: 4242 });
    expect(terminate).not.toHaveBeenCalled();
  });

  it('surfaces the port as busy (never free) when it is our aged-out orphan but the kill fails', () => {
    const probe = fakeProbe({
      holderOf: () => ({ pid: 4242, name: 'node' }),
      executableOf: () => '/our/node',
      terminate: () => false,
    });
    const result = reclaimPort(33418, { probe, readLock: () => staleLock(33418), removeLock: () => undefined });
    expect(result).toEqual({ outcome: 'held-by-other', port: 33418, holderName: 'node', holderPid: 4242 });
  });
});

describe('reclaimPort — never touch anyone else', () => {
  it('reports a foreign holder by name and PID, and never terminates it', () => {
    const terminate = vi.fn(() => true);
    const probe = fakeProbe({ holderOf: () => ({ pid: 999, name: 'Docker' }), terminate });

    const result = reclaimPort(33418, { probe, readLock: () => null, removeLock: () => undefined });

    expect(result).toEqual({ outcome: 'held-by-other', port: 33418, holderName: 'Docker', holderPid: 999 });
    expect(terminate).not.toHaveBeenCalled();
  });

  it('does not touch a live process whose PID differs from our lockfile, and cleans the stale lock', () => {
    const terminate = vi.fn(() => true);
    const remove = vi.fn();
    // Our lock names pid 4242, but the live holder is pid 5555 — the port was reused.
    const probe = fakeProbe({
      holderOf: () => ({ pid: 5555, name: 'vite' }),
      isAlive: (pid) => pid === 5555,
      terminate,
    });

    const result = reclaimPort(33418, { probe, readLock: () => lock(33418), removeLock: remove });

    expect(result).toEqual({ outcome: 'held-by-other', port: 33418, holderName: 'vite', holderPid: 5555 });
    expect(terminate).not.toHaveBeenCalled();
    expect(remove).toHaveBeenCalledWith(33418);
  });
});

describe('reclaimPort — cannot identify', () => {
  it('reports held-unknown when the holder cannot be seen', () => {
    const probe = fakeProbe({ holderOf: () => null });
    const result = reclaimPort(33418, { probe, readLock: () => null, removeLock: () => undefined });
    expect(result).toEqual({ outcome: 'held-unknown', port: 33418 });
  });

  it('cleans a stale lock (dead PID) even when the current holder is invisible', () => {
    const remove = vi.fn();
    const probe = fakeProbe({ holderOf: () => null, isAlive: () => false });
    const result = reclaimPort(33418, { probe, readLock: () => lock(33418), removeLock: remove });
    expect(result.outcome).toBe('held-unknown');
    expect(remove).toHaveBeenCalledWith(33418);
  });

  it('leaves an invisible holder with a live lock PID alone (does not remove the lock)', () => {
    const remove = vi.fn();
    const probe = fakeProbe({ holderOf: () => null, isAlive: () => true });
    const result = reclaimPort(33418, { probe, readLock: () => lock(33418), removeLock: remove });
    expect(result.outcome).toBe('held-unknown');
    expect(remove).not.toHaveBeenCalled();
  });
});

describe('lockfile IO', () => {
  const PORT = 33999;
  afterEach(() => removeLock(PORT));

  it('round-trips through a real temp file and records our own identity (no secret)', () => {
    const written = writeLock(PORT, 'corr-123');
    expect(written.pid).toBe(process.pid);
    expect(written.exe).toBe(process.execPath);
    expect(written.nonce).toBe('corr-123');

    const read = readLock(PORT);
    expect(read).toEqual(written);
    // The persisted lock carries exactly these five fields — no token, no state, no verifier.
    expect(Object.keys(read ?? {}).sort()).toEqual(['exe', 'nonce', 'pid', 'port', 'writtenAt']);
  });

  it('removeLock makes a subsequent read return null and is idempotent', () => {
    writeLock(PORT, 'corr-123');
    removeLock(PORT);
    expect(readLock(PORT)).toBeNull();
    expect(() => removeLock(PORT)).not.toThrow();
  });

  it('readLock returns null for an absent port', () => {
    expect(readLock(34998)).toBeNull();
  });

  it('lockPath is deterministic per port', () => {
    expect(lockPath(33418)).toBe(lockPath(33418));
    expect(lockPath(33418)).not.toBe(lockPath(33419));
  });
});
