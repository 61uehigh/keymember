import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  bootstrapOrganization,
  fetchTransport,
  logIn,
} from "@keymember/client";
import type { Session } from "@keymember/client";
import { formatSecretKey } from "@keymember/core";
import { buildApp, migrate, PgliteDatabase, SqlStore } from "@keymember/server";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { BIOMETRIC_PASSWORD_MAX_AGE_MS } from "../src/main/BiometricUnlock.js";
import { createDesktopVault } from "../src/main/createDesktopVault.js";
import type { DesktopVault } from "../src/main/DesktopVault.js";
import type { PlatformServices } from "../src/main/platform.js";

const EMAIL = "owner@example.test";
const PASSWORD = "owner-password-123";

describe("desktop vault", () => {
  let app: ReturnType<typeof buildApp>;
  let db: PgliteDatabase;
  let serverUrl: string;
  let secretKey: string;
  let owner: Session;
  let vaultId: string;
  let dataDir: string;
  let clipboardText: string;
  let biometricAnswer: boolean;
  let signingAnswer: "session" | "once" | "deny";
  let signingPrompts: number;
  let platform: PlatformServices;

  beforeAll(async () => {
    db = new PgliteDatabase();
    await migrate(db);
    app = buildApp({
      store: new SqlStore(db),
      serverSecret: new Uint8Array(32).fill(9),
    });
    serverUrl = await app.listen({ host: "127.0.0.1", port: 0 });

    const transport = fetchTransport(serverUrl);
    const account = await bootstrapOrganization(transport, "T", {
      email: EMAIL,
      name: "Owner",
      password: PASSWORD,
    });

    owner = await logIn(transport, {
      email: EMAIL,
      password: PASSWORD,
      secretKey: account.secretKey,
      deviceId: crypto.randomUUID(),
      deviceName: "setup",
    });
    await owner.orgAdmin().initializeOrganization();
    owner.setRoots(new Map([[owner.user.id, owner.signingPublicKey]]));
    vaultId = await owner.createVault("Shared", "shared", []);
    await owner.createItem(
      vaultId,
      {
        type: "login",
        title: "DB prod",
        urls: ["https://db.example.test"],
        tags: [],
      },
      {
        username: "app",
        password: "db-secret-123",
        fields: [],
        passwordHistory: [],
      },
    );
    secretKey = formatSecretKey(account.secretKey);
  });

  afterAll(async () => {
    await app.close();
    await db.close();
  });

  beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), "keymember-desktop-"));
    clipboardText = "";
    biometricAnswer = true;
    signingAnswer = "once";
    signingPrompts = 0;
    platform = {
      dataDir,
      // A reversible stand-in for the Keychain: what matters here is that it is used
      secretBox: {
        encrypt: (plaintext) => new TextEncoder().encode(`sealed:${plaintext}`),
        decrypt: (ciphertext) =>
          new TextDecoder().decode(ciphertext).replace(/^sealed:/, ""),
      },
      biometric: () => Promise.resolve(biometricAnswer),
      clipboard: {
        read: () => Promise.resolve(clipboardText),
        write: (text) => {
          clipboardText = text;
        },
      },
      openExternal: () => undefined,
      confirmSigning: () => {
        signingPrompts += 1;

        return Promise.resolve(signingAnswer);
      },
    };

    return async () => {
      await rm(dataDir, { recursive: true, force: true });
    };
  });

  /**
   * ### unlocked
   *
   * A vault unlocked with the password and the owner key pinned.
   *
   * @returns The vault
   */
  async function unlocked(): Promise<DesktopVault> {
    const vault = createDesktopVault(platform);

    await vault.configure(serverUrl);
    expect(
      await vault.unlock({ email: EMAIL, password: PASSWORD, secretKey }),
    ).toMatchObject({ ok: true });

    const [candidate] = await vault.ownerCandidates();

    await vault.pinOwner(candidate?.userId ?? "", candidate?.fingerprint ?? "");

    return vault;
  }

  it("unlocks, lists items without secrets, and copies to a clipboard it clears", async () => {
    const vault = await unlocked();
    const [row] = await vault.search("db");

    expect(row).toMatchObject({
      title: "DB prod",
      username: "app",
      hasPassword: true,
    });
    expect(JSON.stringify(row)).not.toContain("db-secret-123");

    vault.copy(row?.id ?? "", "password");
    expect(clipboardText).toBe("db-secret-123");

    // The 30-second timer runs this same check; calling it directly avoids faking timers,
    // which would also stall the HTTP client and the database
    await vault.clearClipboardIfUnchanged();
    expect(clipboardText).toBe("");

    // Something the user copied in between is left alone
    vault.copy(row?.id ?? "", "password");
    clipboardText = "my notes";
    await vault.clearClipboardIfUnchanged();
    expect(clipboardText).toBe("my notes");
  });

  it("offers a code only for a TOTP secret that parses", async () => {
    for (const [title, totp] of [
      ["TOTP good", "JBSWY3DPEHPK3PXP"],
      ["TOTP broken", "not a secret!"],
    ] as const) {
      await owner.createItem(
        vaultId,
        { type: "login", title, urls: [], tags: [] },
        { username: "u", totp, fields: [], passwordHistory: [] },
      );
    }

    const vault = await unlocked();
    const rows = await vault.search("TOTP");

    expect(
      Object.fromEntries(rows.map((row) => [row.title, row.hasTotp])),
    ).toEqual({ "TOTP good": true, "TOTP broken": false });
  });

  it("keeps the Secret Key sealed on disk and remembers this computer", async () => {
    await unlocked();

    const config = await readFile(join(dataDir, "config.json"), "utf8");

    expect(config).not.toContain(secretKey);

    const again = createDesktopVault(platform);

    expect((await again.state()).knownDevice).toBe(true);
    expect(
      await again.unlock({ email: EMAIL, password: PASSWORD }),
    ).toMatchObject({
      ok: true,
    });
  });

  it("asks for the Secret Key again when the Keychain stops trusting a rebuilt app", async () => {
    await unlocked();

    // A self-built app gets a new signature on every rebuild; the user may deny it Keychain access
    const denied: PlatformServices = {
      ...platform,
      secretBox: {
        encrypt: () => {
          throw new Error("User denied Keychain access");
        },
        decrypt: () => {
          throw new Error("User denied Keychain access");
        },
      },
    };
    const rebuilt = createDesktopVault(denied);

    // Showing the window does not touch the Keychain; the refusal comes with the unlock
    expect((await rebuilt.state()).knownDevice).toBe(true);
    expect(
      await rebuilt.unlock({ email: EMAIL, password: PASSWORD }),
    ).toMatchObject({ ok: false, code: "secret_key" });
    expect((await rebuilt.state()).knownDevice).toBe(false);
    expect(
      await rebuilt.unlock({ email: EMAIL, password: PASSWORD, secretKey }),
    ).toMatchObject({ ok: true });
    // Never falls back to storing the Secret Key in the clear, and keeps the sealed copy
    const config = await readFile(join(dataDir, "config.json"), "utf8");

    expect(config).not.toContain(secretKey);
    expect(config).toContain('"secretKey"');

    // Once allowed again, the kept copy opens without typing the Secret Key
    const allowed = createDesktopVault(platform);

    expect((await allowed.state()).knownDevice).toBe(true);
    expect(
      await allowed.unlock({ email: EMAIL, password: PASSWORD }),
    ).toMatchObject({ ok: true });
  });

  it("unlocks with Touch ID from a sealed snapshot, and falls back to the password when it must", async () => {
    const vault = await unlocked();

    await vault.setBiometric(true);
    await vault.lock();
    expect((await vault.state()).user).toBeUndefined();

    biometricAnswer = false;
    expect(await vault.unlockWithBiometric()).toMatchObject({
      ok: false,
      code: "cancelled",
    });

    biometricAnswer = true;
    expect(await vault.unlockWithBiometric()).toMatchObject({ ok: true });
    expect((await vault.search("db")).length).toBe(1);

    // Two weeks after the last password, Touch ID is no longer enough
    await vault.lock();
    vi.useFakeTimers({ toFake: ["Date"] });

    try {
      vi.setSystemTime(Date.now() + BIOMETRIC_PASSWORD_MAX_AGE_MS + 1000);
      expect(await vault.unlockWithBiometric()).toMatchObject({
        ok: false,
        code: "password_required",
      });
      expect((await vault.state()).biometricEnabled).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps Touch ID when the server cannot be reached", async () => {
    const vault = await unlocked();

    await vault.setBiometric(true);
    await vault.lock();

    // The same computer, started while the server is unreachable
    const path = join(dataDir, "config.json");
    const config = JSON.parse(await readFile(path, "utf8")) as Record<
      string,
      unknown
    >;

    await writeFile(
      path,
      JSON.stringify({ ...config, serverUrl: "http://127.0.0.1:1" }),
    );

    const offline = createDesktopVault(platform);

    expect(await offline.unlockWithBiometric()).toMatchObject({
      ok: false,
      code: "offline",
    });
    expect((await offline.state()).biometricEnabled).toBe(true);
  });

  it("locks and tells the window when the server ends the login", async () => {
    const vault = await unlocked();
    let locks = 0;

    vault.onLocked(() => {
      locks += 1;
    });
    await db.query("UPDATE sessions SET revoked_at = now()");

    await expect(vault.ownerCandidates()).rejects.toThrow(/Unlock again/);
    expect(locks).toBe(1);
    expect((await vault.state()).user).toBeUndefined();
  });

  it("drops the Touch ID snapshot when the server has ended that login", async () => {
    const vault = await unlocked();

    await vault.setBiometric(true);
    await vault.lock();
    await db.query("UPDATE sessions SET revoked_at = now()");

    expect(await vault.unlockWithBiometric()).toMatchObject({
      ok: false,
      code: "password_required",
    });
    expect((await vault.state()).biometricEnabled).toBe(false);
  });

  it("adds SSH keys and asks before each signature unless allowed until lock", async () => {
    const vault = await unlocked();
    const [target] = vault.writableVaults();
    const id = await vault.keyring.add({
      vaultId: target?.id ?? "",
      title: "GitHub deploy",
    });
    const [row] = (await vault.keyring.list()).filter((key) => key.id === id);
    const [identity] = await vault.keyring.identities();

    expect(row?.publicKey).toMatch(/^ssh-ed25519 /);
    expect(identity?.comment).toBe("GitHub deploy");

    const blob = identity?.publicBlob ?? new Uint8Array();

    signingAnswer = "deny";
    expect(await vault.keyring.sign(blob, Uint8Array.of(1), 0)).toBeUndefined();

    signingAnswer = "once";
    expect(await vault.keyring.sign(blob, Uint8Array.of(1), 0)).toBeDefined();
    expect(await vault.keyring.sign(blob, Uint8Array.of(1), 0)).toBeDefined();
    expect(signingPrompts).toBe(3);

    signingAnswer = "session";
    await vault.keyring.sign(blob, Uint8Array.of(1), 0);
    await vault.keyring.sign(blob, Uint8Array.of(1), 0);
    expect(signingPrompts).toBe(4);

    // Locking forgets both the keys and the permission
    await vault.lock();
    expect(await vault.keyring.identities()).toEqual([]);
    expect(await vault.keyring.sign(blob, Uint8Array.of(1), 0)).toBeUndefined();
  });

  it("forgets the old organization's owner keys and Secret Key when the server changes", async () => {
    const vault = await unlocked();

    await vault.setBiometric(true);
    // Same server again: nothing changes
    await vault.configure(serverUrl);
    expect(await vault.state()).toMatchObject({
      knownDevice: true,
      pinned: true,
      biometricEnabled: true,
    });

    await vault.configure("https://other.example.test");

    const state = await vault.state();

    expect(state).toMatchObject({
      serverUrl: "https://other.example.test",
      knownDevice: false,
      pinned: false,
      biometricEnabled: false,
    });
    expect(state.user).toBeUndefined();
    expect(state.email).toBeUndefined();

    const config = await readFile(join(dataDir, "config.json"), "utf8");

    expect(config).not.toContain('"secretKey"');
    expect(JSON.parse(config)).toMatchObject({ roots: {} });
  });

  it("adopts the roots the account saved when an earlier device pinned the owner", async () => {
    const vault = createDesktopVault(platform);

    await vault.configure(serverUrl);
    expect((await vault.state()).pinned).toBe(false);

    await vault.unlock({ email: EMAIL, password: PASSWORD, secretKey });

    expect((await vault.state()).pinned).toBe(true);
  });

  it("pins the owner only with the fingerprint the user compared", async () => {
    const vault = createDesktopVault(platform);

    await vault.configure(serverUrl);
    await vault.unlock({ email: EMAIL, password: PASSWORD, secretKey });

    const roots = async (): Promise<unknown> =>
      (
        JSON.parse(await readFile(join(dataDir, "config.json"), "utf8")) as {
          roots: unknown;
        }
      ).roots;
    const before = await roots();
    const [candidate] = await vault.ownerCandidates();

    await expect(
      vault.pinOwner(candidate?.userId ?? "", "0000-0000-0000-0000-0000"),
    ).rejects.toThrow(/Compare the fingerprint again/);
    expect(await roots()).toEqual(before);
  });
});
