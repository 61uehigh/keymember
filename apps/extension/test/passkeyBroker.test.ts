import {
  bootstrapOrganization,
  fetchTransport,
  logIn,
} from "@keymember/client";
import {
  formatSecretKey,
  fromBase64Url,
  randomBytes,
  toBase64Url,
} from "@keymember/core";
import { buildApp, migrate, PgliteDatabase, SqlStore } from "@keymember/server";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { Autofill } from "../src/background/Autofill.js";
import { PasskeyBroker } from "../src/background/PasskeyBroker.js";
import { PasskeyStore } from "../src/background/PasskeyStore.js";
import { Vault } from "../src/background/Vault.js";
import type { PasskeyDecision, PasskeyReply } from "../src/shared/messages.js";
import { installChromeMock } from "./chromeMock.js";
import type { FakeBrowser } from "./chromeMock.js";

const EMAIL = "owner@example.test";
const PASSWORD = "owner-password-123";
const PAGE = "https://login.example.com/signin";

describe("passkey broker", () => {
  let app: ReturnType<typeof buildApp>;
  let db: PgliteDatabase;
  let serverUrl: string;
  let secretKey: string;
  let vaultId: string;
  let browser: FakeBrowser;
  let vault: Vault;
  let broker: PasskeyBroker;
  let passkeys: PasskeyStore;

  beforeAll(async () => {
    db = new PgliteDatabase();
    await migrate(db);
    app = buildApp({
      store: new SqlStore(db),
      serverSecret: new Uint8Array(32).fill(4),
    });
    serverUrl = await app.listen({ host: "127.0.0.1", port: 0 });

    const transport = fetchTransport(serverUrl);
    const account = await bootstrapOrganization(transport, "T", {
      email: EMAIL,
      name: "O",
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
    vaultId = await owner.createVault("V", "shared", []);
    secretKey = formatSecretKey(account.secretKey);
  });

  afterAll(async () => {
    await app.close();
    await db.close();
  });

  beforeEach(async () => {
    browser = installChromeMock();
    vault = new Vault();
    passkeys = new PasskeyStore(vault, new Autofill(vault));
    broker = new PasskeyBroker(vault, passkeys);
    await vault.configure(serverUrl);
    await vault.unlock({ email: EMAIL, password: PASSWORD, secretKey });
  });

  /**
   * ### answerWith
   *
   * Makes the fake consent window answer every request with the given decision.
   *
   * @param decide Produces the decision, given the request's view
   */
  function answerWith(
    decide: (
      view: Awaited<ReturnType<PasskeyBroker["view"]>>,
    ) => PasskeyDecision,
  ): void {
    browser.onWindow = (url) => {
      const id = new URL(url).hash.slice(1);

      void (async () => {
        const view = await broker.view(id);

        // The window asks for the password when the site requires user verification
        if (view?.needsReverify === true) {
          await vault.unlock({ email: EMAIL, password: PASSWORD, secretKey });
        }

        broker.decide(id, decide(await broker.view(id)));
      })();
    };
  }

  const createRequest = (rpId?: string, exclude: Array<string> = []) => ({
    type: "passkey-create" as const,
    options: {
      rp: { name: "Example", ...(rpId === undefined ? {} : { id: rpId }) },
      user: {
        id: toBase64Url(randomBytes(8)),
        name: "kim",
        displayName: "Kim",
      },
      challenge: toBase64Url(randomBytes(32)),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      excludeCredentials: exclude.map((id) => ({ id })),
      userVerification: "required" as const,
    },
  });

  const getRequest = (allow: Array<string> = []) => ({
    type: "passkey-get" as const,
    options: {
      rpId: "example.com",
      challenge: toBase64Url(randomBytes(32)),
      allowCredentials: allow.map((id) => ({ id })),
    },
  });

  /**
   * ### credentialIdOf
   *
   * Reads the credential id from a successful reply.
   *
   * @param reply Broker reply
   * @returns The credential id
   */
  function credentialIdOf(reply: PasskeyReply): string {
    if (reply.outcome !== "credential") {
      throw new Error(`Expected a credential, got ${reply.outcome}`);
    }

    return String(reply.credential.id);
  }

  it("refuses a relying party id foreign to the page before asking the user", async () => {
    let asked = false;

    browser.onWindow = () => {
      asked = true;
    };

    expect(
      await broker.handle(createRequest("evil.example"), PAGE),
    ).toMatchObject({
      outcome: "error",
      name: "SecurityError",
    });
    expect(await broker.handle(createRequest("com"), PAGE)).toMatchObject({
      name: "SecurityError",
    });
    expect(asked).toBe(false);
  });

  it("hands sites asking only for unsupported algorithms back to the browser", async () => {
    const request = createRequest("example.com");

    expect(
      await broker.handle(
        {
          ...request,
          options: {
            ...request.options,
            pubKeyCredParams: [{ type: "public-key", alg: -257 }],
          },
        },
        PAGE,
      ),
    ).toEqual({ outcome: "fallback" });
  });

  it("creates, honours excludeCredentials, and signs in only with a passkey the request allows", async () => {
    answerWith(() => ({ action: "create", vaultId }));

    const credentialId = credentialIdOf(
      await broker.handle(createRequest("example.com"), PAGE),
    );

    expect(
      await broker.handle(createRequest("example.com", [credentialId]), PAGE),
    ).toMatchObject({
      name: "InvalidStateError",
    });

    // Nothing stored matches this allow-list, so the browser handles it without a keymember window
    expect(
      await broker.handle(getRequest([toBase64Url(randomBytes(16))]), PAGE),
    ).toEqual({ outcome: "fallback" });

    answerWith((view) => {
      const [candidate] = view?.candidates ?? [];

      return candidate === undefined
        ? { action: "cancel" }
        : {
            action: "use",
            itemId: candidate.itemId,
            credentialId: candidate.credentialId,
          };
    });

    expect(
      credentialIdOf(await broker.handle(getRequest([credentialId]), PAGE)),
    ).toBe(credentialId);
  });

  it("rejects a spoofed choice of a passkey outside the request", async () => {
    answerWith(() => ({ action: "create", vaultId }));

    const allowed = credentialIdOf(
      await broker.handle(createRequest("example.com"), PAGE),
    );
    const [first] = await passkeys.passkeyCandidates("example.com", [allowed]);

    // A second passkey on the same item, so only the allow-list check can stop the spoof
    answerWith(() => ({ action: "create", itemId: first?.itemId ?? "" }));

    const other = credentialIdOf(
      await broker.handle(createRequest("example.com"), PAGE),
    );

    expect(
      (await passkeys.passkeyCandidates("example.com", [other]))[0]?.itemId,
    ).toBe(first?.itemId);

    answerWith((view) => {
      const victim = view?.candidates.find(
        (candidate) => candidate.credentialId === allowed,
      );

      // A compromised window tries to answer with a passkey the site did not allow
      return victim === undefined
        ? { action: "cancel" }
        : { action: "use", itemId: victim.itemId, credentialId: other };
    });

    expect(await broker.handle(getRequest([allowed]), PAGE)).toMatchObject({
      outcome: "error",
      name: "NotAllowedError",
    });
  });

  it("reports cancel and fallback choices faithfully", async () => {
    answerWith(() => ({ action: "cancel" }));
    expect(await broker.handle(createRequest(), PAGE)).toMatchObject({
      outcome: "error",
      name: "NotAllowedError",
    });

    answerWith(() => ({ action: "fallback" }));
    expect(await broker.handle(createRequest(), PAGE)).toEqual({
      outcome: "fallback",
    });
  });

  it("claims user verification only when the password was entered for this request", async () => {
    // A window that picks without asking for the password
    const decideWithoutVerifying = (decision: PasskeyDecision): void => {
      browser.onWindow = (url) => {
        broker.decide(new URL(url).hash.slice(1), decision);
      };
    };

    decideWithoutVerifying({ action: "create", vaultId });
    expect(
      await broker.handle(createRequest("example.com"), PAGE),
    ).toMatchObject({ outcome: "error", name: "NotAllowedError" });

    const preferred = createRequest("example.com");
    const reply = await broker.handle(
      {
        ...preferred,
        options: { ...preferred.options, userVerification: "preferred" },
      },
      PAGE,
    );

    if (reply.outcome !== "credential") {
      throw new Error(`Expected a credential, got ${reply.outcome}`);
    }

    const flags =
      fromBase64Url(String(reply.credential.authenticatorData))?.[32] ?? 0;

    // User present, but not verified: the unlock happened before this request
    expect(flags & 0x01).toBe(0x01);
    expect(flags & 0x04).toBe(0);
  });

  it("keeps one consent window per tab", async () => {
    let release: (() => void) | undefined;

    browser.onWindow = (url) => {
      release = () => {
        broker.decide(new URL(url).hash.slice(1), { action: "cancel" });
      };
    };

    const first = broker.handle(createRequest("example.com"), PAGE, 7);

    await expect.poll(() => release !== undefined).toBe(true);
    expect(
      await broker.handle(createRequest("example.com"), PAGE, 7),
    ).toMatchObject({
      outcome: "error",
      name: "NotAllowedError",
    });
    release?.();
    await first;
  });

  it("parks an autofill sign-in only when keymember can answer it, and signs only allowed passkeys", async () => {
    answerWith(() => ({ action: "create", vaultId }));

    const credentialId = credentialIdOf(
      await broker.handle(createRequest("example.com"), PAGE),
    );
    const conditional = (
      options: Partial<{
        userVerification: "required" | "preferred";
        allow: Array<string>;
      }> = {},
    ) => ({
      type: "passkey-conditional" as const,
      requestId: crypto.randomUUID(),
      options: {
        rpId: "example.com",
        challenge: toBase64Url(randomBytes(32)),
        allowCredentials: (options.allow ?? []).map((id) => ({ id })),
        ...(options.userVerification === undefined
          ? {}
          : { userVerification: options.userVerification }),
      },
    });

    // Verification-required requests and requests nothing here can answer stay with the browser
    expect(
      await broker.registerConditional(
        conditional({ userVerification: "required" }),
        PAGE,
        3,
      ),
    ).toEqual({ outcome: "fallback" });
    expect(
      await broker.registerConditional(
        conditional({ allow: [toBase64Url(randomBytes(16))] }),
        PAGE,
        3,
      ),
    ).toEqual({ outcome: "fallback" });
    expect(
      await broker.registerConditional(
        {
          ...conditional(),
          options: { ...conditional().options, rpId: "evil.example" },
        },
        PAGE,
        3,
      ),
    ).toMatchObject({ name: "SecurityError" });

    expect(await broker.registerConditional(conditional(), PAGE, 3)).toEqual({
      outcome: "registered",
    });

    const offered = await broker.conditionalPasskeys(3, 0, PAGE);

    // Earlier tests in this file stored passkeys for the same site too
    expect(offered.map((passkey) => passkey.credentialId)).toContain(
      credentialId,
    );
    // Not in frames, not for another page's origin
    expect(await broker.conditionalPasskeys(3, 1, PAGE)).toEqual([]);
    expect(
      await broker.conditionalPasskeys(3, 0, "https://other.example/login"),
    ).toEqual([]);
    expect(
      await broker.completeConditional(
        3,
        "https://other.example/login",
        offered.find((passkey) => passkey.credentialId === credentialId)
          ?.itemId ?? "",
        credentialId,
      ),
    ).toBe(false);
  });
});
