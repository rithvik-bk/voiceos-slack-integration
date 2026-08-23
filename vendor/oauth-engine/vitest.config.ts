import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['engine/test/**/*.test.ts'],
    environment: 'node',
    // The engine is deterministic by charter: no test may depend on wall-clock slop
    // or on a live network. A hanging test in CI is a failed test.
    testTimeout: 10_000,
    hookTimeout: 10_000,
    reporters: ['default'],
    // C-15: the loopback now reclaims occupied ladder ports by terminating a holder proven to be
    // our own orphan (matching lockfile PID + executable). Test files that bind the FIXED ladder
    // (loopback.test.ts, connect-flow.test.ts, and every suite that drives connect()) run as
    // separate OS processes; run in parallel they are, to the reclaim, indistinguishable from two
    // live app instances — one worker would SIGTERM a ladder port held by a live sibling worker
    // mid-flow. Serializing the files (one holds the ladder at a time) removes that collision
    // without changing a single assertion; leftover lockfiles from an exited file carry a dead PID
    // and are cleaned as stale, never mistaken for a live orphan.
    fileParallelism: false,
  },
});
