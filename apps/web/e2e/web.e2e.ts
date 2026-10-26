import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  bootstrapOrganization,
  fetchTransport,
  logIn,
  shareLinkUrl,
  signUp,
} from "@keymember/client";
import type { Session } from "@keymember/client";
import { formatSecretKey } from "@keymember/core";
import type { SecretKey } from "@keymember/core";
import { buildApp, migrate, PgliteDatabase, SqlStore } from "@keymember/server";
import { chromium } from "playwright";
import type { Browser, BrowserContext, Page } from "playwright";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const WEB_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "dist");
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * ### TestServer
 *
 * The keymember server with the built web app, on an in-memory database and a movable clock.
 */
interface TestServer {
  readonly url: string;
  readonly clock: { now: Date };
  close(): Promise<void>;
}

/**
 * ### BOOTSTRAP_TOKEN
 *
 * Token the test servers ask for before the organisation can be created.
 */
const BOOTSTRAP_TOKEN = "e2e-bootstrap-token";

/**
 * ### startServer
 *
 * Starts the server on a random local port.
 *
 * @returns The running server
 */
async function startServer(): Promise<TestServer> {
  const db = new PgliteDatabase();

  await migrate(db);

  const clock = { now: new Date() };
  const app = buildApp({
    store: new SqlStore(db),
    serverSecret: new Uint8Array(32).fill(8),
    webRoot: WEB_ROOT,
    now: () => clock.now,
    bootstrapToken: BOOTSTRAP_TOKEN,
  });
  const url = await app.listen({ host: "127.0.0.1", port: 0 });

  return {
    url,
    clock,
    close: async () => {
      await app.close();
      await db.close();
    },
  };
}

/**
 * ### Account
 *
 * Credentials of a test account, and its session when created through the SDK.
 */
interface Account {
  readonly email: string;
  readonly password: string;
  readonly secretKey: SecretKey;
  readonly session: Session;
}

/**
 * ### confirmSecretKeySaved
 *
 * Ticks "I've stored my Secret Key somewhere safe" and continues past the Secret Key screen.
 *
 * @param page Page showing the Secret Key
 * @returns The Secret Key shown
 */
async function confirmSecretKeySaved(page: Page): Promise<string> {
  const secretKey =
    (await page.locator(".secret-key").first().textContent()) ?? "";

  await page.getByLabel("I've stored my Secret Key somewhere safe").check();
  await page.getByRole("button", { name: "Continue" }).click();

  return secretKey;
}

/**
 * ### logInThroughUi
 *
 * Logs in on a fresh browser profile, which also asks for the Secret Key.
 *
 * @param page Page on the server's login screen
 * @param account Account to log in as
 */
async function logInThroughUi(page: Page, account: Account): Promise<void> {
  await page.getByLabel("Email", { exact: true }).fill(account.email);
  await page.getByLabel("Password", { exact: true }).fill(account.password);
  await page
    .getByLabel("Secret Key", { exact: true })
    .fill(formatSecretKey(account.secretKey));
  await page.getByRole("button", { name: "Unlock" }).click();
  await page.waitForURL(/#\/vault/);
}

/**
 * ### createAccount
 *
 * Signs an invited member up through the SDK, certifies their keys from `admin`'s session, and
 * saves the owner's key as their trusted root so a web login needs no fingerprint check.
 *
 * @param server Test server
 * @param admin Inviting admin
 * @param email New member's email
 * @param role Role to invite with
 * @returns The new account
 */
async function createAccount(
  server: TestServer,
  admin: Session,
  email: string,
  role: "admin" | "member",
): Promise<Account> {
  const transport = fetchTransport(server.url);
  const password = `${email}-password`;
  const { inviteToken } = await admin.orgAdmin().invite(email, role);
  const account = await signUp(transport, inviteToken, {
    email,
    name: email.split("@")[0] ?? email,
    password,
  });
  const session = await logIn(transport, {
    email,
    password,
    secretKey: account.secretKey,
    deviceId: crypto.randomUUID(),
    deviceName: "e2e-setup",
  });

  await admin.orgAdmin().certify(session.user.id, session.fingerprint);
  session.setRoots(new Map([[admin.user.id, admin.signingPublicKey]]));
  await session.saveTrustedRoots();

  return { email, password, secretKey: account.secretKey, session };
}

/**
 * ### createOwner
 *
 * Creates the organisation through the SDK and saves the owner's own key as their root.
 *
 * @param server Test server
 * @returns The owner's account
 */
async function createOwner(server: TestServer): Promise<Account> {
  const transport = fetchTransport(server.url);
  const email = "owner@example.test";
  const password = "owner-password-123";
  const account = await bootstrapOrganization(
    transport,
    "E2E",
    { email, name: "Owner", password },
    BOOTSTRAP_TOKEN,
  );
  const session = await logIn(transport, {
    email,
    password,
    secretKey: account.secretKey,
    deviceId: crypto.randomUUID(),
    deviceName: "e2e-setup",
  });

  await session.orgAdmin().initializeOrganization();
  session.setRoots(new Map([[session.user.id, session.signingPublicKey]]));
  await session.saveTrustedRoots();

  return { email, password, secretKey: account.secretKey, session };
}

describe("web vault in a real Chromium", () => {
  let browser: Browser;

  beforeAll(async () => {
    browser = await chromium.launch({ channel: "chromium", headless: true });
  });

  afterAll(async () => {
    await browser.close();
  });

  /**
   * ### openContext
   *
   * A browser profile of its own, so each person has their own device storage.
   *
   * @returns The context and a page in it
   */
  const openContext = async (): Promise<{
    context: BrowserContext;
    page: Page;
  }> => {
    const context = await browser.newContext();

    return { context, page: await context.newPage() };
  };

  it("lets a member join by link, be certified when the admin's console opens, and see a vault shared with them", async () => {
    const server = await startServer();
    const admin = await openContext();
    const member = await openContext();

    try {
      // The owner creates the organisation in the browser
      await admin.page.goto(server.url);
      await admin.page.getByLabel("Bootstrap token").fill(BOOTSTRAP_TOKEN);
      await admin.page.getByLabel("Organization name").fill("Web E2E");
      await admin.page.getByLabel("Name", { exact: true }).fill("Owner");
      await admin.page
        .getByLabel("Email", { exact: true })
        .fill("owner@example.test");
      await admin.page
        .getByLabel("Password", { exact: true })
        .fill("owner-password-123");
      await admin.page
        .getByLabel("Confirm password")
        .fill("owner-password-123");
      await admin.page
        .getByRole("button", { name: "Create organization" })
        .click();
      await confirmSecretKeySaved(admin.page);
      await admin.page.waitForURL(/#\/vault/);

      // The owner invites Bob by link
      await admin.page.goto(`${server.url}/#/admin`);
      await admin.page.getByLabel("Email to invite").fill("bob@example.test");
      await admin.page.getByRole("button", { name: "Create invite" }).click();

      const link =
        (await admin.page.locator(".notice code").textContent()) ?? "";

      expect(link).toContain("#/join?");
      expect(
        await admin.page
          .getByRole("link", { name: "Send by email" })
          .getAttribute("href"),
      ).toMatch(/^mailto:bob%40example\.test\?/);

      // Bob joins from the link: no token field, the email is fixed, no fingerprint step
      await member.page.goto(link);
      await expect(
        member.page.getByLabel("Invite token").count(),
      ).resolves.toBe(0);
      expect(
        await member.page.getByLabel("Email", { exact: true }).inputValue(),
      ).toBe("bob@example.test");
      await member.page.getByLabel("Name", { exact: true }).fill("Bob");
      await member.page
        .getByLabel("Password", { exact: true })
        .fill("bob-password-1234");
      await member.page
        .getByLabel("Confirm password")
        .fill("bob-password-1234");
      await member.page
        .getByRole("button", { name: "Join", exact: true })
        .click();
      await confirmSecretKeySaved(member.page);
      await member.page.waitForURL(/#\/vault/);
      await member.page
        .getByText("Waiting for an admin to verify you", { exact: false })
        .waitFor();

      // Opening the console again certifies Bob without a fingerprint
      await admin.page.goto(`${server.url}/#/vault`);
      await admin.page.goto(`${server.url}/#/admin`);

      const bobRow = admin.page.getByRole("row", { name: /bob@example\.test/ });

      await bobRow.getByText("Verified", { exact: true }).waitFor();
      expect(await bobRow.getByText("Active", { exact: true }).count()).toBe(1);

      // The owner makes a shared vault and adds Bob
      await admin.page.goto(`${server.url}/#/vault`);
      await admin.page.getByRole("button", { name: "+ New vault" }).click();
      await admin.page.getByLabel("Name", { exact: true }).fill("배포");
      await admin.page
        .getByRole("button", { name: "Create", exact: true })
        .click();
      await admin.page.getByRole("button", { name: "Manage sharing" }).click();
      await admin.page
        .getByLabel("Member or group to share with")
        .selectOption({ label: "Bob (bob@example.test)" });
      await admin.page
        .getByRole("button", { name: "Add", exact: true })
        .click();
      await admin.page.getByText("bob@example.test").first().waitFor();

      // Bob logs in again and sees the vault
      await member.page.reload();
      await member.page
        .getByLabel("Password", { exact: true })
        .fill("bob-password-1234");
      await member.page.getByRole("button", { name: "Unlock" }).click();
      await member.page.waitForURL(/#\/vault/);
      await member.page.getByText("배포").first().waitFor();
    } finally {
      await admin.context.close();
      await member.context.close();
      await server.close();
    }
  });

  it("opens share links: refuses a wrong passphrase, shows the item with the right one, and refuses an expired link", async () => {
    const server = await startServer();
    const viewer = await openContext();

    try {
      const owner = await createOwner(server);
      const vaultId = await owner.session.createVault("공용", "shared", []);
      const itemId = await owner.session.createItem(
        vaultId,
        { type: "login", title: "Staging DB", urls: [], tags: [] },
        {
          username: "deploy",
          password: "staging-pass-42",
          fields: [],
          passwordHistory: [],
        },
      );
      const withPassphrase = await owner.session.createShareLink(itemId, {
        fields: ["username", "password"],
        expiresInMs: DAY_MS,
        maxViews: 3,
        passphrase: "open sesame",
      });
      const expiring = await owner.session.createShareLink(itemId, {
        fields: ["password"],
        expiresInMs: 60 * 60 * 1000,
        maxViews: 3,
      });

      await viewer.page.goto(shareLinkUrl(server.url, withPassphrase));
      await viewer.page.getByLabel("Access password").fill("wrong");
      await viewer.page.getByRole("button", { name: "View contents" }).click();
      await viewer.page.getByText("Incorrect access password.").waitFor();

      await viewer.page.getByLabel("Access password").fill("open sesame");
      await viewer.page.getByRole("button", { name: "View contents" }).click();
      await viewer.page.getByText("Staging DB").waitFor();
      expect(await viewer.page.content()).toContain("deploy");

      server.clock.now = new Date(
        server.clock.now.getTime() + 2 * 60 * 60 * 1000,
      );
      await viewer.page.goto(shareLinkUrl(server.url, expiring));
      await viewer.page.reload();
      await viewer.page.getByRole("button", { name: "View contents" }).click();
      await viewer.page
        .getByText("This link has expired, used up its views", {
          exact: false,
        })
        .waitFor();
    } finally {
      await viewer.context.close();
      await server.close();
    }
  });

  it("runs a two-admin recovery: request, approval, re-enrolment, certification and completion", async () => {
    const server = await startServer();
    const owner = await createOwner(server);
    const alice = await createAccount(
      server,
      owner.session,
      "alice@example.test",
      "admin",
    );
    const bob = await createAccount(
      server,
      owner.session,
      "bob@example.test",
      "member",
    );
    const vaultId = await owner.session.createVault("인프라", "shared", [
      { userId: bob.session.user.id, permission: "view" },
    ]);

    expect(vaultId).not.toBe("");

    // Both admins must have been confirmed members for a week before they can run a recovery
    server.clock.now = new Date(server.clock.now.getTime() + 8 * DAY_MS);

    const ownerUi = await openContext();
    const aliceUi = await openContext();
    const bobUi = await openContext();

    try {
      // The owner requests Bob's recovery
      await ownerUi.page.goto(server.url);
      await logInThroughUi(ownerUi.page, owner);
      await ownerUi.page.goto(`${server.url}/#/admin`);
      await ownerUi.page.getByRole("tab", { name: "Account recovery" }).click();
      await ownerUi.page
        .getByLabel("Member to recover")
        .selectOption({ label: "bob (bob@example.test)" });
      await ownerUi.page
        .getByRole("button", { name: "Request recovery" })
        .click();
      await ownerUi.page
        .getByRole("row", { name: /bob@example\.test/ })
        .waitFor();

      // Alice, a different admin, approves it and gets the one-time link
      await aliceUi.page.goto(server.url);
      await logInThroughUi(aliceUi.page, alice);
      await aliceUi.page.goto(`${server.url}/#/admin`);
      await aliceUi.page.getByRole("tab", { name: "Account recovery" }).click();
      await aliceUi.page.getByRole("button", { name: "Approve" }).click();

      const recoveryLink =
        (await aliceUi.page.locator(".notice code").textContent()) ?? "";

      expect(recoveryLink).toContain("#/recover?");

      // Bob re-enrols from the link with a new password, and reads out his new fingerprint
      let fingerprint = "";

      bobUi.page.on("dialog", (dialog) => {
        fingerprint =
          /fingerprint (\S+) to/.exec(dialog.message())?.[1] ?? fingerprint;
        void dialog.accept();
      });
      await bobUi.page.goto(recoveryLink);
      await bobUi.page.getByRole("button", { name: "Check token" }).click();
      await bobUi.page
        .getByLabel("New password", { exact: true })
        .fill("bob-new-password-1");
      await bobUi.page
        .getByLabel("Confirm new password")
        .fill("bob-new-password-1");
      await bobUi.page
        .getByRole("button", { name: "Recover", exact: true })
        .click();
      await confirmSecretKeySaved(bobUi.page);

      // Re-keying dropped Bob's saved roots, so he confirms the owner's key again
      await bobUi.page.getByText(owner.session.fingerprint).waitFor();
      await bobUi.page.getByRole("button", { name: "They match" }).click();
      await bobUi.page.waitForURL(/#\/account/);
      expect(fingerprint).toMatch(/^[0-9a-f]{4}(-[0-9a-f]{4}){4}$/);

      // The owner certifies the new keys with that fingerprint and completes the recovery
      await ownerUi.page.goto(`${server.url}/#/vault`);
      await ownerUi.page.goto(`${server.url}/#/admin`);
      await ownerUi.page
        .getByRole("row", { name: /bob@example\.test/ })
        .getByRole("button", { name: "Verify", exact: true })
        .click();
      await ownerUi.page
        .getByLabel("Fingerprint from the member")
        .fill(fingerprint);
      await ownerUi.page
        .getByRole("dialog")
        .getByRole("button", { name: "Verify", exact: true })
        .click();
      await ownerUi.page.getByRole("tab", { name: "Account recovery" }).click();
      await ownerUi.page
        .getByRole("button", { name: "Complete", exact: true })
        .click();
      await ownerUi.page
        .getByText("Recovery complete", { exact: false })
        .waitFor();

      // Bob sees the vault he had before
      await bobUi.page.goto(`${server.url}/#/vault`);
      await bobUi.page.getByText("인프라").first().waitFor();
    } finally {
      await ownerUi.context.close();
      await aliceUi.context.close();
      await bobUi.context.close();
      await server.close();
    }
  });
});
