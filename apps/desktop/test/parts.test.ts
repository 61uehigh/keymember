import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { BiometricUnlock } from "../src/main/BiometricUnlock.js";
import { ClipboardGuard } from "../src/main/ClipboardGuard.js";
import { DesktopVault } from "../src/main/DesktopVault.js";
import type { DesktopVaultParts } from "../src/main/DesktopVault.js";
import { DeviceConfigStore } from "../src/main/DeviceConfigStore.js";
import type { SecretBox } from "../src/main/platform.js";

const reversibleBox: SecretBox = {
  encrypt: (plaintext) => new TextEncoder().encode(`sealed:${plaintext}`),
  decrypt: (ciphertext) =>
    new TextDecoder().decode(ciphertext).replace(/^sealed:/, ""),
};

const refusingBox: SecretBox = {
  encrypt: () => {
    throw new Error("User denied Keychain access");
  },
  decrypt: () => {
    throw new Error("User denied Keychain access");
  },
};

let dataDir: string;

beforeEach(async () => {
  dataDir = await mkdtemp(join(tmpdir(), "keymember-parts-"));
});

afterEach(async () => {
  await rm(dataDir, { recursive: true, force: true });
});

describe("ClipboardGuard", () => {
  it("clears only the secret it put there, and a new copy replaces the pending clear", async () => {
    let text = "";
    const guard = new ClipboardGuard(
      {
        read: () => Promise.resolve(text),
        write: (value) => {
          text = value;
        },
      },
      60_000,
    );

    guard.copy("first");
    guard.copy("second");
    // The first copy's pending clear ran when the second replaced it, and left "second" alone
    expect(text).toBe("second");

    await guard.clearIfUnchanged();
    expect(text).toBe("");

    guard.copy("third");
    text = "the user's own notes";
    await guard.clearIfUnchanged();
    expect(text).toBe("the user's own notes");
  });
});

describe("DeviceConfigStore", () => {
  it("forgets the account but keeps the device id when the server changes", async () => {
    const store = new DeviceConfigStore(dataDir, reversibleBox);

    await store.switchServer("https://a.example.com");
    await store.rememberLogin("me@example.com", "K1-AAAAAA");
    await store.pinRoots(new Map([["owner", Uint8Array.of(1, 2, 3)]]));

    const before = await store.current();

    expect(await store.switchServer("https://a.example.com")).toBe(false);
    expect(await store.switchServer("https://b.example.com")).toBe(true);
    expect(await store.current()).toEqual({
      deviceId: before.deviceId,
      serverUrl: "https://b.example.com",
      email: undefined,
      roots: new Map(),
    });
    expect(await store.secretKey()).toBeUndefined();
  });

  it("keeps the Secret Key sealed, and never in the clear when the Keychain refuses", async () => {
    const sealed = new DeviceConfigStore(dataDir, reversibleBox);

    await sealed.rememberLogin("me@example.com", "K1-SECRET");
    expect(await readFile(join(dataDir, "config.json"), "utf8")).not.toContain(
      "K1-SECRET",
    );
    expect(
      await new DeviceConfigStore(dataDir, reversibleBox).secretKey(),
    ).toBe("K1-SECRET");

    // After a rebuild the Keychain may refuse: the key reads as missing but the sealed copy stays
    const refused = new DeviceConfigStore(dataDir, refusingBox);

    expect(await refused.hasSecretKey()).toBe(true);
    expect(await refused.secretKey()).toBeUndefined();
    expect(await refused.hasSecretKey()).toBe(false);
    await refused.rememberLogin("me@example.com", "K1-SECRET");
    expect(await readFile(join(dataDir, "config.json"), "utf8")).not.toContain(
      "K1-SECRET",
    );

    // Allowed again, the same sealed copy opens: one refusal did not cost the key
    expect(
      await new DeviceConfigStore(dataDir, reversibleBox).secretKey(),
    ).toBe("K1-SECRET");
  });

  it("writes atomically and sets a damaged config aside instead of losing it", async () => {
    const store = new DeviceConfigStore(dataDir, reversibleBox);

    await store.switchServer("https://a.example.com");
    expect(await readdir(dataDir)).toEqual(["config.json"]);

    await writeFile(join(dataDir, "config.json"), "{ not json");

    const reopened = new DeviceConfigStore(dataDir, reversibleBox);

    expect((await reopened.current()).serverUrl).toBeUndefined();
    expect(
      (await readdir(dataDir)).some((name) =>
        name.startsWith("config.json.damaged-"),
      ),
    ).toBe(true);
  });
});

describe("BiometricUnlock", () => {
  it("opens only after Touch ID passes, and drops a snapshot it can no longer open", async () => {
    let passes = false;
    const unlock = new BiometricUnlock(dataDir, reversibleBox, () =>
      Promise.resolve(passes),
    );

    expect(unlock.available).toBe(true);
    await unlock.seal({ toSnapshot: () => ({ token: "t" }) }, Date.now());
    expect(await unlock.open()).toMatchObject({ ok: false, code: "cancelled" });

    passes = true;
    expect(await unlock.open()).toMatchObject({
      ok: true,
      snapshot: { token: "t" },
    });

    const afterRebuild = new BiometricUnlock(dataDir, refusingBox, () =>
      Promise.resolve(true),
    );

    expect(await afterRebuild.open()).toMatchObject({
      ok: false,
      code: "password_required",
    });
    expect(await unlock.isEnabled()).toBe(false);
  });
});

describe("DesktopVault with stand-in parts", () => {
  /**
   * ### standIns
   *
   * Parts that record what the vault asks of them; no files, Keychain or server.
   *
   * @param calls Receives one entry per call
   * @param opening What Touch ID unlock answers
   * @returns The parts
   */
  function standIns(
    calls: Array<string>,
    opening: Awaited<ReturnType<DesktopVaultParts["biometric"]["open"]>>,
  ): DesktopVaultParts {
    return {
      config: {
        current: () =>
          Promise.resolve({
            deviceId: "d",
            serverUrl: "https://example.com",
            email: undefined,
            roots: new Map(),
          }),
        hasSecretKey: () => Promise.resolve(false),
        rememberLogin: () => Promise.resolve(),
        secretKey: () => Promise.resolve(undefined),
        switchServer: () => {
          calls.push("switchServer");

          return Promise.resolve(true);
        },
      },
      trust: {
        afterUnlock: () => Promise.resolve(true),
        apply: () => Promise.resolve(new Map()),
        pinOwner: () => Promise.resolve(),
      },
      biometric: {
        available: true,
        forget: () => {
          calls.push("forget");

          return Promise.resolve();
        },
        isEnabled: () => Promise.resolve(false),
        open: () => Promise.resolve(opening),
        seal: () => Promise.resolve(),
      },
      clipboard: {
        copy: () => undefined,
        clearIfUnchanged: () => {
          calls.push("clipboard");

          return Promise.resolve();
        },
      },
      keyring: {
        attach: () => undefined,
        detach: () => {
          calls.push("keyring");
        },
        list: () => Promise.resolve([]),
        add: () => Promise.resolve(""),
        identities: () => Promise.resolve([]),
        sign: () => Promise.resolve(undefined),
      },
      openExternal: () => undefined,
    };
  }

  it("passes a refused Touch ID through without touching anything else", async () => {
    const calls: Array<string> = [];
    const vault = new DesktopVault(
      standIns(calls, {
        ok: false,
        code: "cancelled",
        message: "Touch ID was cancelled.",
      }),
    );

    expect(await vault.unlockWithBiometric()).toMatchObject({
      ok: false,
      code: "cancelled",
    });
    expect(calls).toEqual([]);
    expect((await vault.state()).user).toBeUndefined();
  });

  it("on a server change, drops Touch ID before locking so the old login ends", async () => {
    const calls: Array<string> = [];
    const vault = new DesktopVault(
      standIns(calls, { ok: false, code: "unavailable", message: "" }),
    );

    await vault.configure("https://other.example.com");
    expect(calls).toEqual(["forget", "keyring", "clipboard", "switchServer"]);
  });
});
