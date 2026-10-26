// Launches the packaged keymember.app with a throwaway profile and checks that the window
// renders and the SSH agent answers. Playwright's Electron driver cannot attach to the
// packaged app (its fuses turn off the Node inspector), so this goes through Chromium's
// DevTools port instead. Usage: node scripts/smoke-packaged.mjs [path/to/keymember.app]
import { execFile, spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { chromium } from "playwright";

const app = process.argv[2] ?? join(homedir(), "Applications", "keymember.app");
const port = 9333;
// Short on purpose: Unix socket paths are limited to 104 bytes on macOS
const profile = await mkdtemp(join(tmpdir(), "km-"));
const child = spawn(
  join(app, "Contents", "MacOS", "keymember"),
  [`--user-data-dir=${profile}`, `--remote-debugging-port=${port}`],
  { stdio: "ignore" },
);

try {
  let browser;

  for (let attempt = 0; browser === undefined; attempt += 1) {
    try {
      browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`);
    } catch (error) {
      if (attempt >= 40) {
        throw error;
      }

      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }

  const page = await browser
    .contexts()[0]
    .waitForEvent("page", { timeout: 1 })
    .catch(() => browser.contexts()[0].pages()[0]);

  await page.locator("#server").waitFor({ timeout: 15_000 });

  const { stdout } = await promisify(execFile)("ssh-add", ["-L"], {
    env: { ...process.env, SSH_AUTH_SOCK: join(profile, "agent.sock") },
  }).catch((error) => error);

  if (!String(stdout).includes("no identities")) {
    throw new Error(`The SSH agent did not answer: ${String(stdout)}`);
  }

  await browser.close();
  console.log(
    `Smoke test passed: ${page.url()} rendered and the SSH agent answered.`,
  );
} finally {
  child.kill();
  await rm(profile, { recursive: true, force: true });
}
