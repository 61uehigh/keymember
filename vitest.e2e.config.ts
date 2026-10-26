import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["apps/*/e2e/**/*.e2e.ts"],
    testTimeout: 120_000,
    hookTimeout: 180_000,
    fileParallelism: false,
  },
});
