import { defineConfig } from 'vitest/config';

/**
 * The relay is its own package. It shares nothing with the engine at runtime — not a
 * dependency, not a build step, not a config — and its tests run in isolation from the
 * engine suite. The integrator wires it into the top-level gate; nothing here reaches
 * back into `engine/`.
 */
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 10_000,
    hookTimeout: 10_000,
    reporters: ['default'],
  },
});
