import {
  bootstrapOrganization,
  fetchTransport,
  logIn,
} from "@keymember/client";
import { formatSecretKey } from "@keymember/core";
import { buildApp, migrate, PgliteDatabase, SqlStore } from "@keymember/server";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { Autofill } from "../src/background/Autofill.js";
import { SavePrompts } from "../src/background/SavePrompts.js";
import { Vault } from "../src/background/Vault.js";
import { installChromeMock } from "./chromeMock.js";
import type { FakeBrowser } from "./chromeMock.js";

const EMAIL = "owner@example.test";
const PASSWORD = "owner-password-123";
const GITHUB_LOGIN = "https://github.com/login";

describe("background vault controller", () => {
  let app: ReturnType<typeof buildApp>;
  let db: PgliteDatabase;
  let serverUrl: string;
  let secretKey: string;
  let githubId: string;
  let vaultId: string;
  let browser: FakeBrowser;
  let vault: Vault;
  let autofill: Autofill;
  let savePrompts: SavePrompts;

  beforeAll(async () => {
    db = new PgliteDatabase();
    await migrate(db);
    app = buildApp({
      store: new SqlStore(db),
      serverSecret: new Uint8Array(32).fill(9),
    });
    serverUrl = await app.listen({ host: "127.0.0.1", port: 0 });

    const transport = fetchTransport(serverUrl);
    const account = await bootstrapOrganization(transport, "Test", {
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
    vaultId = await owner.createVault("Shared", "shared", []);
    githubId = await owner.createItem(
      vaultId,
      {
        type: "login",
        title: "GitHub",
        urls: ["https://github.com"],
        tags: [],
      },
      {
        username: "me",
        password: "gh-pass",
        totp: "JBSWY3DPEHPK3PXP",
        fields: [],
        passwordHistory: [],
      },
    );
    await owner.createItem(
      vaultId,
      {
        type: "login",
        title: "Intranet",
        urls: ["https://intranet.example.test"],
        tags: [],
      },
      {
        username: "staff",
        password: "intra-pass",
        fields: [],
        passwordHistory: [],
      },
    );
    await owner.logOut();
    secretKey = formatSecretKey(account.secretKey);
  });

  afterAll(async () => {
    await app.close();
    await db.close();
  });

  beforeEach(async () => {
    browser = installChromeMock();
    vault = new Vault();
    autofill = new Autofill(vault);
    savePrompts = new SavePrompts(vault);
    await vault.configure(serverUrl);

    const result = await vault.unlock({
      email: EMAIL,
      password: PASSWORD,
      secretKey,
    });

    expect(result.ok).toBe(true);
  });

  it("lists matching items for a page and marks https items on http pages as insecure", async () => {
    expect(
      (await autofill.rowsFor(GITHUB_LOGIN)).map((row) => row.title),
    ).toEqual(["GitHub"]);
    expect(
      await autofill.rowsFor("https://github.com.evil.example/login"),
    ).toEqual([]);

    const [intranet] = await autofill.rowsFor(
      "http://intranet.example.test/login",
    );

    expect(intranet?.insecure).toBe(true);
    expect(JSON.stringify(await autofill.rowsFor(GITHUB_LOGIN))).not.toContain(
      "gh-pass",
    );
  });

  it("binds menu tokens to the tab that opened the menu", async () => {
    const token = await autofill.issueMenuToken(
      { tabId: 1, frameId: 0, url: GITHUB_LOGIN },
      "password",
    );

    expect(token).toBeDefined();
    expect(await autofill.menuToken(token ?? "", 2)).toBeUndefined();
    expect(await autofill.menuToken(token ?? "", 1)).toMatchObject({
      tabId: 1,
      url: GITHUB_LOGIN,
    });
  });

  it("fills only a frame that still shows the matched URL, and never an insecure one", async () => {
    browser.frames.set("1:0", { url: GITHUB_LOGIN, received: [] });

    expect(
      await autofill.fill(
        githubId,
        [{ tabId: 1, frameId: 0, url: GITHUB_LOGIN }],
        "password",
      ),
    ).toBe(2);
    expect(browser.frames.get("1:0")?.received[0]).toMatchObject({
      username: "me",
      password: "gh-pass",
      expectedUrl: GITHUB_LOGIN,
    });

    // The page navigated to a phishing site between opening the menu and choosing an item
    browser.frames.set("1:0", {
      url: "https://github-login.evil.example",
      received: [],
    });

    expect(
      await autofill.fill(
        githubId,
        [{ tabId: 1, frameId: 0, url: GITHUB_LOGIN }],
        "password",
      ),
    ).toBe(0);
    expect(browser.frames.get("1:0")?.received).toEqual([]);

    const intranetId = (await autofill.search("Intranet"))[0]?.id ?? "";
    const httpPage = "http://intranet.example.test/login";

    browser.frames.set("2:0", { url: httpPage, received: [] });

    expect(
      await autofill.fill(intranetId, [
        { tabId: 2, frameId: 0, url: httpPage },
      ]),
    ).toBe(0);
  });

  it("sends only the current code to a one-time-code field", async () => {
    browser.frames.set("1:0", { url: GITHUB_LOGIN, received: [] });

    await autofill.fill(
      githubId,
      [{ tabId: 1, frameId: 0, url: GITHUB_LOGIN }],
      "otp",
    );

    const [message] = browser.frames.get("1:0")?.received ?? [];

    expect(message).toMatchObject({ kind: "otp" });
    expect((message as { totp?: string }).totp).toMatch(/^\d{6}$/);
    expect(message).not.toHaveProperty("password");
  });

  it("offers to save new logins and to update changed passwords, but not known ones", async () => {
    // Its own item and sites, so this test changes nothing the others read
    const site = `https://update-${crypto.randomUUID().slice(0, 8)}.test`;
    const session = await vault.require();
    const itemId = await session.createItem(
      vaultId,
      { type: "login", title: "Updatable", urls: [site], tags: [] },
      {
        username: "me",
        password: "old-pass",
        fields: [],
        passwordHistory: [],
      },
    );
    const target = { tabId: 1, frameId: 0, url: `${site}/login` };

    expect(await savePrompts.addPending(target, "me", "old-pass")).toBe(false);
    expect(await savePrompts.addPending(target, "me", "new-pass")).toBe(true);

    const { pending } = await savePrompts.pending();

    expect(pending).toMatchObject({ username: "me", updatesItemId: itemId });

    await savePrompts.savePending(pending?.id ?? "", undefined);

    expect(await autofill.reveal(itemId, "password")).toBe("new-pass");

    // A different registrable domain: subdomains of example.test would share a site with the intranet item
    const newSite = {
      tabId: 3,
      frameId: 0,
      url: `https://new-${crypto.randomUUID().slice(0, 8)}.test/login`,
    };

    expect(await savePrompts.addPending(newSite, "new-user", "new-pass")).toBe(
      true,
    );

    const next = await savePrompts.pending();

    expect(next.pending?.updatesItemId).toBeUndefined();
    await savePrompts.savePending(next.pending?.id ?? "", vaultId);

    expect(
      (await autofill.rowsFor(newSite.url)).map((row) => row.username),
    ).toEqual(["new-user"]);
  });

  it("never offers a login typed on an http page as an update to the https item", async () => {
    const target = { tabId: 4, frameId: 0, url: "http://github.com/login" };

    expect(await savePrompts.addPending(target, "me", "typed-over-http")).toBe(
      true,
    );
    expect(
      (await savePrompts.pending()).pending?.updatesItemId,
    ).toBeUndefined();
  });

  it("removes expired pending saves, with their passwords, from storage", async () => {
    await savePrompts.addPending(
      { tabId: 5, frameId: 0, url: "https://expired.test/login" },
      "someone",
      "secret-pass",
    );

    // addPending just wrote this value in the shape storage.ts defines
    const stored = browser.session.get("pending") as Array<{
      createdAt: number;
    }>;

    // Age the entry past the one-minute offer
    browser.session.set(
      "pending",
      stored.map((entry) => ({ ...entry, createdAt: Date.now() - 120_000 })),
    );
    await savePrompts.prune();

    expect(browser.session.has("pending")).toBe(false);
  });

  it("restores one session for messages that arrive together after a restart", async () => {
    const restarted = new Vault();
    const [first, second] = await Promise.all([
      restarted.current(),
      restarted.current(),
    ]);

    expect(first).toBeDefined();
    expect(first).toBe(second);
  });

  it("clears the unlocked state on lock but keeps the unlock count growing", async () => {
    const before = await vault.unlockCount();
    let snapshotWhenListenersRan: boolean | undefined;

    vault.onLock(() => {
      snapshotWhenListenersRan = browser.session.has("session");

      return Promise.resolve();
    });
    browser.session.set("clipboard", "fingerprint");
    await vault.lock();

    // Listeners (the clipboard guard) run while the clipboard fingerprint is still there
    expect(snapshotWhenListenersRan).toBe(true);
    expect(browser.session.has("session")).toBe(false);
    expect(browser.session.has("clipboard")).toBe(true);

    await vault.unlock({ email: EMAIL, password: PASSWORD });

    expect(await vault.unlockCount()).toBeGreaterThan(before ?? 0);
  });

  it("survives a service worker restart but not a lock or a browser restart", async () => {
    const restarted = new Vault();

    expect((await restarted.state()).user?.email).toBe(EMAIL);
    expect((await new Autofill(restarted).rowsFor(GITHUB_LOGIN)).length).toBe(
      1,
    );

    await restarted.lock();

    expect((await new Vault().state()).user).toBeUndefined();

    await vault.unlock({ email: EMAIL, password: PASSWORD });
    browser.session.clear();

    expect((await new Vault().state()).user).toBeUndefined();
  });
});
