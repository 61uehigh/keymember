import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  bootstrapOrganization,
  fetchTransport,
  logIn,
} from "@keymember/client";
import type { Session } from "@keymember/client";
import { formatSecretKey } from "@keymember/core";
import { buildApp, migrate, PgliteDatabase, SqlStore } from "@keymember/server";
import { chromium } from "playwright";
import type { BrowserContext, Frame, Page } from "playwright";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const EXTENSION_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "dist",
);
const EMAIL = "owner@example.test";
const PASSWORD = "owner-password-123";
const SCREENSHOT_DIR = process.env.KEYMEMBER_E2E_SCREENSHOTS;

/**
 * ### SITE_PAGES
 *
 * A tiny login site: a Korean-labelled login form, a one-time-code page, and a landing page.
 */
const SITE_PAGES: Readonly<Record<string, string>> = {
  "/login": `<!doctype html><meta charset="utf-8"><title>로그인</title>
    <form action="/welcome" method="get" style="margin:40px;width:320px">
      <label for="uid">아이디</label><br><input id="uid" name="uid" style="width:300px;height:32px"><br><br>
      <label for="upw">비밀번호</label><br><input id="upw" name="upw" type="password" style="width:300px;height:32px"><br><br>
      <button type="submit">로그인</button>
    </form>`,
  "/otp": `<!doctype html><meta charset="utf-8"><title>인증</title>
    <form action="/welcome" style="margin:40px"><label for="code">인증번호 6자리</label><br>
      <input id="code" inputmode="numeric" maxlength="6" style="width:200px;height:32px"></form>`,
  "/welcome": `<!doctype html><meta charset="utf-8"><title>환영</title><p>welcome</p>`,
};

describe("extension in a real Chromium", () => {
  let api: ReturnType<typeof buildApp>;
  let db: PgliteDatabase;
  let site: Server;
  let siteUrl: string;
  let serverUrl: string;
  let owner: Session;
  let secretKey: string;
  let vaultId: string;
  let context: BrowserContext;
  let extensionId: string;
  let profileDir: string;

  beforeAll(async () => {
    db = new PgliteDatabase();
    await migrate(db);
    api = buildApp({
      store: new SqlStore(db),
      serverSecret: new Uint8Array(32).fill(5),
    });
    serverUrl = await api.listen({ host: "127.0.0.1", port: 0 });

    site = createServer((request, response) => {
      const body = SITE_PAGES[new URL(request.url ?? "/", "http://x").pathname];

      response.writeHead(body === undefined ? 404 : 200, {
        "content-type": "text/html; charset=utf-8",
      });
      response.end(body ?? "not found");
    });
    await new Promise<void>((resolve) => site.listen(0, "127.0.0.1", resolve));

    const address = site.address();

    siteUrl = `http://localhost:${String(typeof address === "object" && address !== null ? address.port : 0)}`;

    const transport = fetchTransport(serverUrl);
    const account = await bootstrapOrganization(transport, "E2E", {
      email: EMAIL,
      name: "Owner",
      password: PASSWORD,
    });

    owner = await logIn(transport, {
      email: EMAIL,
      password: PASSWORD,
      secretKey: account.secretKey,
      deviceId: crypto.randomUUID(),
      deviceName: "e2e-setup",
    });
    await owner.orgAdmin().initializeOrganization();
    owner.setRoots(new Map([[owner.user.id, owner.signingPublicKey]]));
    vaultId = await owner.createVault("Shared", "shared", []);
    await owner.createItem(
      vaultId,
      { type: "login", title: "Test Login", urls: [siteUrl], tags: [] },
      {
        username: "kim",
        password: "site-pass-1",
        totp: "JBSWY3DPEHPK3PXP",
        fields: [],
        passwordHistory: [],
      },
    );
    secretKey = formatSecretKey(account.secretKey);

    profileDir = await mkdtemp(join(tmpdir(), "keymember-e2e-"));
    context = await chromium.launchPersistentContext(profileDir, {
      channel: "chromium",
      headless: true,
      args: [
        `--disable-extensions-except=${EXTENSION_DIR}`,
        `--load-extension=${EXTENSION_DIR}`,
      ],
    });

    const worker =
      context.serviceWorkers()[0] ??
      (await context.waitForEvent("serviceworker"));

    extensionId = new URL(worker.url()).host;
  });

  afterAll(async () => {
    await context.close();
    await rm(profileDir, { recursive: true, force: true });
    await new Promise<void>((resolve) =>
      site.close(() => {
        resolve();
      }),
    );
    await api.close();
    await db.close();
  });

  /**
   * ### shot
   *
   * Saves a screenshot when `KEYMEMBER_E2E_SCREENSHOTS` names a directory.
   *
   * @param page Page to capture
   * @param name File name without extension
   */
  async function shot(page: Page, name: string): Promise<void> {
    if (SCREENSHOT_DIR !== undefined) {
      await page.screenshot({ path: join(SCREENSHOT_DIR, `${name}.png`) });
    }
  }

  /**
   * ### openMenu
   *
   * Focuses a field, clicks the key button drawn inside its right edge (it lives in a closed
   * shadow root, so it is clicked by position like a user would), and returns the menu frame.
   *
   * @param page Site page
   * @param selector Field to open the menu for
   * @returns The extension-origin menu frame
   */
  async function openMenu(page: Page, selector: string): Promise<Frame> {
    await page.click(selector);

    const box = await page.locator(selector).boundingBox();

    if (box === null) {
      throw new Error(`No box for ${selector}`);
    }

    // The button ignores clicks until it has been visible for half a second (clickjacking defence)
    await page.waitForTimeout(600);

    // The button is 22px wide, inset 6px from the field's right edge, vertically centred
    await page.mouse.click(box.x + box.width - 6 - 11, box.y + box.height / 2);

    for (let attempt = 0; attempt < 50; attempt += 1) {
      const frame = page
        .frames()
        .find((candidate) =>
          candidate
            .url()
            .startsWith(`chrome-extension://${extensionId}/menu.html`),
        );

      if (frame !== undefined) {
        await frame.waitForSelector("button.row, .message");
        // Menu rows likewise ignore clicks for the first half second
        await page.waitForTimeout(600);

        return frame;
      }

      await page.waitForTimeout(100);
    }

    throw new Error("Menu did not open");
  }

  it("unlocks from the popup and pins the owner key", async () => {
    const popup = await context.newPage();

    await popup.goto(`chrome-extension://${extensionId}/popup.html`);
    await popup.fill("#server", serverUrl);
    await popup.click("button[type=submit]");
    await popup.fill("#email", EMAIL);
    await popup.fill("#password", PASSWORD);
    await popup.fill("#secret-key", secretKey);
    await popup.click("button[type=submit]");
    await popup.getByText(owner.fingerprint).waitFor();
    await shot(popup, "popup-pin-owner");
    await popup.getByRole("button", { name: "They match" }).click();
    await popup.getByRole("tab", { name: "This site" }).waitFor();
    await shot(popup, "popup-main");
    await popup.close();
  });

  it("fills a login through the inline menu with real clicks", async () => {
    const page = await context.newPage();

    await page.goto(`${siteUrl}/login`);

    const menu = await openMenu(page, "#uid");

    await shot(page, "inline-menu");
    expect(await menu.locator("button.row").allTextContents()).toEqual([
      expect.stringContaining("Test Login"),
    ]);
    expect(await menu.content()).not.toContain("site-pass-1");

    await menu.locator("button.row").first().click();

    await expect.poll(() => page.inputValue("#upw")).toBe("site-pass-1");
    expect(await page.inputValue("#uid")).toBe("kim");
    await page.close();
  });

  it("fills only a one-time code into a code field", async () => {
    const page = await context.newPage();

    await page.goto(`${siteUrl}/otp`);

    const menu = await openMenu(page, "#code");

    await menu.locator("button.row").first().click();

    await expect.poll(() => page.inputValue("#code")).toMatch(/^\d{6}$/);
    await page.close();
  });

  it("offers to save a newly submitted login and stores it encrypted", async () => {
    const page = await context.newPage();

    await page.goto(`${siteUrl}/login`);
    await page.fill("#uid", "lee");
    await page.fill("#upw", "brand-new-pass");
    await Promise.all([
      page.waitForURL(/\/welcome/),
      page.click("button[type=submit]"),
    ]);

    const popup = await context.newPage();

    await popup.goto(`chrome-extension://${extensionId}/popup.html`);
    await popup.getByText("to keymember?").waitFor();
    await shot(popup, "popup-save-prompt");
    await popup.getByRole("button", { name: "Save", exact: true }).click();
    await popup.getByText("to keymember?").waitFor({ state: "detached" });

    await owner.sync();

    const saved = owner
      .listItems(vaultId)
      .find((item) => owner.getItem(item.id).details.username === "lee");

    expect(
      saved === undefined
        ? undefined
        : owner.getItem(saved.id).details.password,
    ).toBe("brand-new-pass");
    await popup.close();
    await page.close();
  });

  it("clears a copied password from the clipboard 30 seconds later", async () => {
    await context.grantPermissions(["clipboard-read", "clipboard-write"], {
      origin: siteUrl,
    });

    const popup = await context.newPage();
    const site = await context.newPage();
    const clipboardText = async (): Promise<string> => {
      await site.bringToFront();

      return site.evaluate(() => navigator.clipboard.readText());
    };

    await site.goto(`${siteUrl}/login`);
    await popup.goto(`chrome-extension://${extensionId}/popup.html`);
    // The site tab is the active one, so "this site" lists its login
    await popup.getByRole("button", { name: "Copy password" }).first().click();
    await popup.getByText("Copied the password.").waitFor();

    expect(await clipboardText()).toBe("site-pass-1");

    // The background's alarm fires after 30 seconds and finds the clipboard unchanged
    await expect
      .poll(clipboardText, { timeout: 45_000, interval: 2_000 })
      .toBe("");
    await popup.close();
    await site.close();
  }, 90_000);
});
