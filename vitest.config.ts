import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/*/test/**/*.test.ts", "apps/*/test/**/*.test.ts"],
    setupFiles: ["./test/argon2Cache.ts"],
    // Argon2id (64 MiB) in pure JS is several times slower on shared CI runners than on a laptop
    testTimeout: 180_000,
    hookTimeout: 180_000,
  },
});
