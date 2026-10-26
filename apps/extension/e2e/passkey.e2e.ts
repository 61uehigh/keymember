import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
import type { IncomingMessage, Server } from "node:http";
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
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type { WebAuthnCredential } from "@simplewebauthn/server";
import { chromium } from "playwright";
import type { BrowserContext, Locator, Page } from "playwright";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const EXTENSION_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "dist",
);
const EMAIL = "owner@example.test";
const PASSWORD = "owner-password-123";

/**
 * ### RP_PAGE
 *
 * A relying party page that registers and signs in with whatever `navigator.credentials`
 * returns, letting the test server verify the results.
 */
const RP_PAGE = `<!doctype html><meta charset="utf-8"><title>RP</title>
<button id="register">register</button> <button id="login">login</button> <button id="bad-rp">bad rp</button>
<button id="conditional">autofill sign-in</button>
<form><input id="who" name="username" autocomplete="username webauthn" placeholder="email"></form>
<pre id="status">idle</pre>
<script>
const b = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const status = (text) => { document.getElementById("status").textContent = text; };
const post = async (path, body) => (await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body ?? {}) })).json();
document.getElementById("register").onclick = async () => {
  try {
    const o = await post("/reg-options");
    const credential = await navigator.credentials.create({ publicKey: { ...o, challenge: b(o.challenge), user: { ...o.user, id: b(o.user.id) },
      excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: b(c.id) })) } });
    const result = await post("/reg-verify", credential.toJSON());
    status("register:" + result.verified + ":" + (credential instanceof PublicKeyCredential));
  } catch (error) { status("register-error:" + error.name); }
};
document.getElementById("login").onclick = async () => {
  try {
    const o = await post("/auth-options");
    const credential = await navigator.credentials.get({ publicKey: { ...o, challenge: b(o.challenge),
      allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: b(c.id) })) } });
    const result = await post("/auth-verify", credential.toJSON());
    status("login:" + result.verified);
  } catch (error) { status("login-error:" + error.name); }
};
document.getElementById("conditional").onclick = async () => {
  try {
    status("conditional:waiting");
    const o = await post("/auth-options?uv=preferred");
    const credential = await navigator.credentials.get({ mediation: "conditional", publicKey: { ...o, challenge: b(o.challenge),
      allowCredentials: [] } });
    const result = await post("/auth-verify-conditional", credential.toJSON());
    status("conditional:" + result.verified);
  } catch (error) { status("conditional-error:" + error.name); }
};
document.getElementById("bad-rp").onclick = async () => {
  try {
    await navigator.credentials.create({ publicKey: { rp: { id: "example.com", name: "x" }, user: { id: new Uint8Array(8), name: "x", displayName: "x" },
      challenge: new Uint8Array(32), pubKeyCredParams: [{ type: "public-key", alg: -7 }] } });
    status("bad-rp:accepted");
  } catch (error) { status("bad-rp-error:" + error.name); }
};
</script>`;

/**
 * ### readJson
 *
 * Reads a JSON request body.
 *
 * @param request Incoming request
 * @returns The parsed body
 */
async function readJson(request: IncomingMessage): Promise<unknown> {
  let text = "";

  for await (const chunk of request) {
    text += String(chunk);
  }

  return text === "" ? {} : JSON.parse(text);
}

describe("passkeys in a real Chromium", () => {
  let api: ReturnType<typeof buildApp>;
  let db: PgliteDatabase;
  let rp: Server;
  let rpOrigin: string;
  let owner: Session;
  let context: BrowserContext;
  let extensionId: string;
  let profileDir: string;
  let serverUrl: string;
  let secretKey: string;
  let challenge = "";
  let registered: WebAuthnCredential | undefined;

  beforeAll(async () => {
    db = new PgliteDatabase();
    await migrate(db);
    api = buildApp({
      store: new SqlStore(db),
      serverSecret: new Uint8Array(32).fill(6),
    });
    serverUrl = await api.listen({ host: "127.0.0.1", port: 0 });

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
    await owner.createVault("Shared", "shared", []);
    secretKey = formatSecretKey(account.secretKey);

    rp = createServer((request, response) => {
      void (async () => {
        const path = request.url ?? "/";
        const send = (body: unknown): void => {
          response.writeHead(200, { "content-type": "application/json" });
          response.end(JSON.stringify(body));
        };

        if (path === "/") {
          response.writeHead(200, {
            "content-type": "text/html; charset=utf-8",
          });
          response.end(RP_PAGE);
        } else if (path === "/reg-options") {
          const options = await generateRegistrationOptions({
            rpName: "Test RP",
            rpID: "localhost",
            userName: "kim@example.test",
            attestationType: "none",
            authenticatorSelection: {
              residentKey: "required",
              userVerification: "required",
            },
          });

          challenge = options.challenge;
          send(options);
        } else if (path === "/reg-verify") {
          const result = await verifyRegistrationResponse({
            // The page sends PublicKeyCredential.toJSON(); the library validates its shape
            response: (await readJson(request)) as Parameters<
              typeof verifyRegistrationResponse
            >[0]["response"],
            expectedChallenge: challenge,
            expectedOrigin: rpOrigin,
            expectedRPID: "localhost",
            requireUserVerification: true,
          }).catch(() => ({ verified: false, registrationInfo: undefined }));

          registered = result.registrationInfo?.credential;
          send({ verified: result.verified });
        } else if (path.startsWith("/auth-options")) {
          const options = await generateAuthenticationOptions({
            rpID: "localhost",
            // Autofill sign-ins usually only prefer verification; keymember leaves "required" to the browser
            userVerification: path.endsWith("uv=preferred")
              ? "preferred"
              : "required",
            allowCredentials:
              registered === undefined ? [] : [{ id: registered.id }],
          });

          challenge = options.challenge;
          send(options);
        } else if (
          path === "/auth-verify-conditional" &&
          registered !== undefined
        ) {
          // Picked from the autofill list: the user was present but not re-verified
          const result = await verifyAuthenticationResponse({
            response: (await readJson(request)) as Parameters<
              typeof verifyAuthenticationResponse
            >[0]["response"],
            expectedChallenge: challenge,
            expectedOrigin: rpOrigin,
            expectedRPID: "localhost",
            credential: registered,
            requireUserVerification: false,
          }).catch(() => ({ verified: false }));

          send({ verified: result.verified });
        } else if (path === "/auth-verify" && registered !== undefined) {
          const result = await verifyAuthenticationResponse({
            response: (await readJson(request)) as Parameters<
              typeof verifyAuthenticationResponse
            >[0]["response"],
            expectedChallenge: challenge,
            expectedOrigin: rpOrigin,
            expectedRPID: "localhost",
            credential: registered,
            requireUserVerification: true,
          }).catch(() => ({ verified: false }));

          send({ verified: result.verified });
        } else {
          response.writeHead(404);
          response.end();
        }
      })();
    });
    await new Promise<void>((resolve) => rp.listen(0, "127.0.0.1", resolve));

    const address = rp.address();

    rpOrigin = `http://localhost:${String(typeof address === "object" && address !== null ? address.port : 0)}`;

    profileDir = await mkdtemp(join(tmpdir(), "keymember-passkey-e2e-"));
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

    const popup = await context.newPage();

    await popup.goto(`chrome-extension://${extensionId}/popup.html`);
    await popup.fill("#server", serverUrl);
    await popup.click("button[type=submit]");
    await popup.fill("#email", EMAIL);
    await popup.fill("#password", PASSWORD);
    await popup.fill("#secret-key", secretKey);
    await popup.click("button[type=submit]");
    await popup.getByRole("button", { name: "They match" }).click();
    await popup.close();
  });

  afterAll(async () => {
    await context.close();
    await rm(profileDir, { recursive: true, force: true });
    await new Promise<void>((resolve) =>
      rp.close(() => {
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
    const directory = process.env.KEYMEMBER_E2E_SCREENSHOTS;

    if (directory !== undefined) {
      await page.screenshot({ path: join(directory, `${name}.png`) });
    }
  }

  /**
   * ### chooseAndClose
   *
   * Clicks a choice in the consent window. The background closes the window as soon as the
   * choice arrives, which can interrupt the click's own bookkeeping, so closing is the success signal.
   *
   * @param window Consent window
   * @param choice Button to click
   */
  async function chooseAndClose(window: Page, choice: Locator): Promise<void> {
    const closed = window.waitForEvent("close");

    await choice.click({ noWaitAfter: true }).catch((error: unknown) => {
      if (!window.isClosed()) {
        throw error;
      }
    });
    await closed;
  }

  /**
   * ### consentWindow
   *
   * Clicks a page button and returns the keymember consent window it opens.
   *
   * @param page Relying party page
   * @param button Button to click
   * @returns The consent window
   */
  async function consentWindow(page: Page, button: string): Promise<Page> {
    const opened = context.waitForEvent("page", (candidate) =>
      candidate.url().includes("/passkey.html"),
    );

    await page.click(button);

    const window = await opened;

    await window.waitForLoadState();

    // The relying party requires user verification, so the password is asked for this ceremony
    const password = window.locator("#password");

    await window.locator("#password, fieldset").first().waitFor();

    if (await password.isVisible()) {
      await password.fill(PASSWORD);
      await password.press("Enter");
    }

    return window;
  }

  it("registers a passkey the relying party verifies, stored encrypted in the vault", async () => {
    const page = await context.newPage();

    await page.goto(rpOrigin);

    const window = await consentWindow(page, "#register");

    await window.getByRole("button", { name: "Save passkey" }).waitFor();
    await shot(window, "passkey-create");
    await chooseAndClose(
      window,
      window.getByRole("button", { name: "Save passkey" }),
    );
    await expect
      .poll(() => page.textContent("#status"))
      .toBe("register:true:true");

    await owner.sync();

    const stored = owner
      .listItems()
      .flatMap((item) => owner.getItem(item.id).details.passkeys ?? [])
      .find((passkey) => passkey.rpId === "localhost");

    expect(stored?.userName).toBe("kim@example.test");
    await page.close();
  });

  it("signs in with the stored passkey", async () => {
    const page = await context.newPage();

    await page.goto(rpOrigin);

    const window = await consentWindow(page, "#login");

    await window.getByRole("button", { name: /kim@example.test/ }).waitFor();
    await shot(window, "passkey-get");
    await chooseAndClose(
      window,
      window.getByRole("button", { name: /kim@example.test/ }),
    );
    await expect.poll(() => page.textContent("#status")).toBe("login:true");
    await page.close();
  });

  it("rejects a relying party id that does not belong to the page's origin", async () => {
    const page = await context.newPage();

    await page.goto(rpOrigin);
    await page.click("#bad-rp");
    await expect
      .poll(() => page.textContent("#status"))
      .toBe("bad-rp-error:SecurityError");
    await page.close();
  });

  it("offers the stored passkey in the inline menu for an autofill sign-in", async () => {
    const page = await context.newPage();

    await page.goto(rpOrigin);
    await page.click("#conditional");
    await expect
      .poll(() => page.textContent("#status"))
      .toBe("conditional:waiting");
    await page.click("#who");

    const box = await page.locator("#who").boundingBox();

    if (box === null) {
      throw new Error("No box for the username field");
    }

    // The key button and menu rows ignore clicks for half a second after appearing
    await page.waitForTimeout(600);
    await page.mouse.click(box.x + box.width - 6 - 11, box.y + box.height / 2);

    const menu = await expect
      .poll(() =>
        page.frames().find((frame) => frame.url().includes("/menu.html")),
      )
      .toBeDefined()
      .then(() =>
        page.frames().find((frame) => frame.url().includes("/menu.html")),
      );
    const row = menu?.getByRole("button", { name: /Sign in with passkey/ });

    await row?.waitFor();
    await page.waitForTimeout(600);
    await shot(page, "passkey-conditional");
    await row?.click();
    await expect
      .poll(() => page.textContent("#status"))
      .toBe("conditional:true");
    await page.close();
  });
});
