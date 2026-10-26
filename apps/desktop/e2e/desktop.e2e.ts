import { execFile, spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  bootstrapOrganization,
  fetchTransport,
  logIn,
} from "@keymember/client";
import { formatSecretKey } from "@keymember/core";
import { buildApp, migrate, PgliteDatabase, SqlStore } from "@keymember/server";
import { _electron as electron } from "playwright";
import type { ElectronApplication, Page } from "playwright";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const APP_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const EMAIL = "owner@example.test";
const PASSWORD = "owner-password-123";
const ITEM_PASSWORD = "desktop-secret-456";
const hasOpenSsh =
  spawnSync("ssh-add", ["-h"], { stdio: "ignore" }).error === undefined;

/**
 * ### run
 *
 * Runs a command without blocking the event loop.
 *
 * @param command Program
 * @param args Arguments
 * @param env Extra environment
 * @param input Standard input
 * @returns Trimmed standard output
 */
async function run(
  command: string,
  args: Array<string>,
  env: Record<string, string> = {},
): Promise<string> {
  const { stdout } = await promisify(execFile)(command, args, {
    env: { ...process.env, ...env },
    encoding: "utf8",
    timeout: 30_000,
  });

  return stdout.trim();
}

/**
 * ### shot
 *
 * Saves a screenshot when `KEYMEMBER_E2E_SCREENSHOTS` names a directory.
 *
 * @param page Window
 * @param name File name without extension
 */
async function shot(page: Page, name: string): Promise<void> {
  const directory = process.env.KEYMEMBER_E2E_SCREENSHOTS;

  if (directory !== undefined) {
    await page.screenshot({ path: join(directory, `${name}.png`) });
  }
}

describe("desktop app in a real Electron", () => {
  let api: ReturnType<typeof buildApp>;
  let db: PgliteDatabase;
  let serverUrl: string;
  let secretKey: string;
  let dataDir: string;
  let app: ElectronApplication;
  let window: Page;

  beforeAll(async () => {
    db = new PgliteDatabase();
    await migrate(db);
    api = buildApp({
      store: new SqlStore(db),
      serverSecret: new Uint8Array(32).fill(5),
    });
    serverUrl = await api.listen({ host: "127.0.0.1", port: 0 });

    const transport = fetchTransport(serverUrl);
    const account = await bootstrapOrganization(transport, "E2E", {
      email: EMAIL,
      name: "Owner",
      password: PASSWORD,
    });
    const owner = await logIn(transport, {
      email: EMAIL,
      password: PASSWORD,
      secretKey: account.secretKey,
      deviceId: crypto.randomUUID(),
      deviceName: "setup",
    });

    await owner.orgAdmin().initializeOrganization();

    owner.setRoots(new Map([[owner.user.id, owner.signingPublicKey]]));

    const vaultId = await owner.createVault("Shared", "shared", []);

    await owner.createItem(
      vaultId,
      { type: "login", title: "Staging DB", urls: [], tags: [] },
      {
        username: "deploy",
        password: ITEM_PASSWORD,
        fields: [],
        passwordHistory: [],
      },
    );
    secretKey = formatSecretKey(account.secretKey);
    dataDir = await mkdtemp(join(tmpdir(), "km-desktop-"));
    app = await electron.launch({
      args: [
        APP_DIR,
        `--user-data-dir=${dataDir}`,
        // CI runners cannot set up Chromium's setuid sandbox helper for a node_modules Electron
        ...(process.env.CI === undefined ? [] : ["--no-sandbox"]),
      ],
    });
    window = await app.firstWindow();
  });

  afterAll(async () => {
    await app.close();
    await rm(dataDir, { recursive: true, force: true });
    await api.close();
    await db.close();
  });

  it("connects, unlocks with the Secret Key and pins the owner", async () => {
    await window.fill("#server", serverUrl);
    await window.getByRole("button", { name: "Connect" }).click();
    await window.fill("#email", EMAIL);
    await window.fill("#password", PASSWORD);
    await window.fill("#secret-key", secretKey);
    await window.getByRole("button", { name: "Unlock", exact: true }).click();
    await shot(window, "desktop-pin");
    await window.getByRole("button", { name: "They match" }).click();
    await window.getByRole("tab", { name: "Items" }).waitFor();
  });

  it("copies a password to the clipboard without the window ever holding it", async () => {
    await window.getByRole("searchbox", { name: "Search" }).fill("Staging");
    await window.getByRole("button", { name: "Copy password" }).click();
    await window.getByText("Copied password.", { exact: false }).waitFor();

    const clipboardText = await app.evaluate(({ clipboard }) =>
      clipboard.readText(),
    );

    expect(clipboardText).toBe(ITEM_PASSWORD);
    await shot(window, "desktop-items");
    expect(await window.content()).not.toContain(ITEM_PASSWORD);
  });

  it.skipIf(!hasOpenSsh)(
    "generates an SSH key and signs for ssh-keygen through the agent after approval",
    async () => {
      await window.getByRole("tab", { name: "SSH keys" }).click();
      await window.getByRole("button", { name: "Add SSH key" }).click();
      await window.fill("#ssh-title", "Deploy key");
      await window.getByRole("button", { name: "Save" }).click();
      await window.getByText("Deploy key").waitFor();

      const socketPath = join(dataDir, "agent.sock");
      const env = { SSH_AUTH_SOCK: socketPath };
      const listed = await run("ssh-add", ["-L"], env);

      expect(listed).toMatch(/^ssh-ed25519 \S+ Deploy key$/);

      const publicPath = join(dataDir, "deploy.pub");
      const message = join(dataDir, "message.txt");

      await writeFile(publicPath, `${listed}\n`);
      await writeFile(message, "release v1");

      // ssh-keygen waits on the agent while the window asks the user
      const signing = run(
        "ssh-keygen",
        ["-Y", "sign", "-f", publicPath, "-n", "file", message],
        env,
      );

      await window.getByRole("dialog", { name: "SSH key request" }).waitFor();
      await shot(window, "desktop-sign-prompt");
      await window.getByRole("button", { name: "Allow once" }).click();
      await signing;

      await writeFile(
        join(dataDir, "allowed"),
        `signer ${listed.split(" ").slice(0, 2).join(" ")}\n`,
      );

      const verified = spawnSync(
        "ssh-keygen",
        [
          "-Y",
          "verify",
          "-f",
          join(dataDir, "allowed"),
          "-I",
          "signer",
          "-n",
          "file",
          "-s",
          `${message}.sig`,
        ],
        { input: "release v1", encoding: "utf8" },
      );

      expect(verified.stdout).toContain("Good");
    },
  );

  it("offers no keys once locked", async () => {
    await window.getByRole("button", { name: "Lock", exact: true }).click();
    await window.getByRole("button", { name: "Unlock", exact: true }).waitFor();

    if (hasOpenSsh) {
      const result = spawnSync("ssh-add", ["-L"], {
        env: { ...process.env, SSH_AUTH_SOCK: join(dataDir, "agent.sock") },
        encoding: "utf8",
      });

      expect(result.stdout).not.toContain("ssh-ed25519");
    }
  });
});
