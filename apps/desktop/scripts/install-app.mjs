// Builds keymember.app from this checkout and installs it into ~/Applications.
// Run again after `git pull` to update. macOS only for now.
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { build, Platform } from "electron-builder";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const appName = "keymember.app";
const target = join(homedir(), "Applications", appName);

if (process.platform !== "darwin") {
  console.error("The desktop app can only be installed on macOS for now.");
  process.exit(1);
}

if (spawnSync("pgrep", ["-x", "keymember"]).status === 0) {
  console.error(
    "Quit keymember first (menu bar: keymember → Quit), then run this again.",
  );
  process.exit(1);
}

// pnpm does not run Electron's install script; fetch its binary if it is missing
execFileSync(
  process.execPath,
  [join(root, "node_modules/electron/install.js")],
  {
    stdio: "inherit",
  },
);
// The bundle imports the workspace packages' compiled output, which a fresh clone lacks
execFileSync(
  process.execPath,
  [
    join(root, "../../node_modules/typescript/bin/tsc"),
    "-b",
    join(root, "../../packages/client"),
  ],
  { stdio: "inherit" },
);
execFileSync(process.execPath, [join(root, "build.mjs")], { stdio: "inherit" });

await build({
  projectDir: root,
  targets: Platform.MAC.createTarget(),
  config: {
    extends: join(root, "electron-builder.json"),
    // Reuse the Electron binary already in node_modules instead of downloading another
    electronDist: join(root, "node_modules/electron/dist"),
  },
});

// electron-builder names the folder mac-arm64 on Apple silicon and plain mac on Intel
const source =
  [`mac-${process.arch}`, "mac"]
    .map((folder) => join(root, "release", folder, appName))
    .find((path) => existsSync(path)) ?? join(root, "release", appName);

if (!existsSync(source)) {
  console.error(`Build finished but ${source} is missing.`);
  process.exit(1);
}

await mkdir(dirname(target), { recursive: true });
await rm(target, { recursive: true, force: true });
// ditto keeps the bundle's symlinks and signature intact
execFileSync("ditto", [source, target]);

console.log(`
Installed ${target}

Open it from Finder (Applications in your home folder) or with: open "${target}"
After an update, macOS may ask once whether keymember may use its Keychain item; allow it.
If you deny, keymember asks for your Secret Key again instead.`);
