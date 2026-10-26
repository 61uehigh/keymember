import { cp, mkdir, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

const root = dirname(fileURLToPath(import.meta.url));
const outdir = join(root, "dist");
const common = {
  bundle: true,
  minify: true,
  sourcemap: false,
  legalComments: "none",
  define: { "process.env.NODE_ENV": '"production"' },
  logLevel: "warning",
};

await rm(outdir, { recursive: true, force: true });
await mkdir(outdir, { recursive: true });

await Promise.all([
  // Main process: Node, CommonJS so __dirname works; Electron itself is provided at runtime
  build({
    ...common,
    entryPoints: [join(root, "src/main/index.ts")],
    outfile: join(outdir, "main.cjs"),
    platform: "node",
    target: "node22",
    format: "cjs",
    external: ["electron"],
  }),
  // Sandboxed preload: may only require "electron"
  build({
    ...common,
    entryPoints: [join(root, "src/preload/index.ts")],
    outfile: join(outdir, "preload.cjs"),
    platform: "browser",
    target: "chrome130",
    format: "cjs",
    external: ["electron"],
  }),
  build({
    ...common,
    entryPoints: [join(root, "src/renderer/main.tsx")],
    outfile: join(outdir, "renderer.js"),
    platform: "browser",
    target: "chrome130",
    format: "iife",
    jsx: "automatic",
  }),
]);

await cp(join(root, "static"), outdir, { recursive: true });

console.log(`Built the desktop app into ${outdir}`);
