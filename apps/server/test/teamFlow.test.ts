import {
  ApiError,
  bootstrapOrganization,
  loginEnded,
  signUp,
} from "@keymember/client";
import type { Session } from "@keymember/client";
import { utf8Encode } from "@keymember/core";
import type { SecretKey } from "@keymember/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { loginAs, startTestServer } from "./harness.js";
import type { TestServer } from "./harness.js";

const ITEM_PASSWORD = "Tr0ub4dor&3-plaintext-marker";

describe("team password sharing end to end", () => {
  let server: TestServer;
  let owner: Session;
  let bob: Session;
  let bobSecretKey: SecretKey;
  let vaultId: string;
  let itemId: string;

  beforeAll(async () => {
    server = await startTestServer();

    const ownerAccount = await bootstrapOrganization(
      server.transport,
      "Example",
      {
        email: "owner@example.com",
        name: "Owner",
        password: "owner-password",
      },
    );

    owner = await loginAs(
      server,
      "owner@example.com",
      "owner-password",
      ownerAccount.secretKey,
    );
    await owner.orgAdmin().initializeOrganization();

    // The owner's key is the trust root; other clients pin it on first use after comparing fingerprints
    server.roots.set(owner.user.id, owner.signingPublicKey);
    owner.setRoots(server.roots);

    const { inviteToken } = await owner
      .orgAdmin()
      .invite("bob@example.com", "member");

    bobSecretKey = (
      await signUp(server.transport, inviteToken, {
        email: "bob@example.com",
        name: "Bob",
        password: "bob-password",
      })
    ).secretKey;
    bob = await loginAs(
      server,
      "bob@example.com",
      "bob-password",
      bobSecretKey,
    );
  });

  afterAll(async () => {
    await server.close();
  });

  it("keeps an unconfirmed member away from vaults", async () => {
    await expect(bob.sync()).rejects.toMatchObject({ status: 403 });
  });

  it("refuses to share with a member whose keys nobody certified", async () => {
    await expect(
      owner.createVault("인프라", "shared", [
        { userId: bob.user.id, permission: "edit" },
      ]),
    ).rejects.toThrow(/key isn't verified/);
  });

  it("rejects certification when the fingerprint does not match", async () => {
    await expect(
      owner.orgAdmin().certify(bob.user.id, "0000-0000-0000-0000-0000"),
    ).rejects.toThrow(/doesn't match/);
  });

  it("shares a vault with a certified member who can then read and edit", async () => {
    await owner.orgAdmin().certify(bob.user.id, bob.fingerprint);

    vaultId = await owner.createVault("인프라", "shared", [
      { userId: bob.user.id, permission: "edit" },
    ]);
    itemId = await owner.createItem(
      vaultId,
      {
        type: "login",
        title: "AWS root",
        urls: ["https://console.aws.amazon.com"],
        tags: ["infra"],
      },
      {
        username: "root@example.com",
        password: ITEM_PASSWORD,
        fields: [],
        passwordHistory: [],
      },
    );

    await bob.sync();

    expect(bob.listVaults().map((vault) => vault.name)).toEqual(["인프라"]);
    expect(bob.getItem(itemId).details.password).toBe(ITEM_PASSWORD);

    const { overview, details } = bob.getItem(itemId);

    await bob.updateItem(itemId, overview, {
      ...details,
      notes: "rotated quarterly",
    });
    await owner.sync();

    expect(owner.getItem(itemId).details.notes).toBe("rotated quarterly");
  });

  it("never stores a plaintext secret, title or URL", async () => {
    const tables = [
      "users",
      "vaults",
      "vault_access",
      "items",
      "audit_events",
      "memberships",
    ];
    const needles = [
      ITEM_PASSWORD,
      "AWS root",
      "console.aws.amazon.com",
      "인프라",
      "rotated quarterly",
    ];

    for (const table of tables) {
      const rows = await server.tables.select(table);

      // An empty read would make the check below pass without looking at anything
      expect(rows.length).toBeGreaterThan(0);

      for (const row of rows) {
        for (const value of Object.values(row)) {
          const haystack =
            value instanceof Uint8Array
              ? Buffer.from(value).toString("latin1")
              : JSON.stringify(value);

          for (const needle of needles) {
            expect(haystack).not.toContain(needle);
            expect(haystack).not.toContain(
              Buffer.from(utf8Encode(needle)).toString("latin1"),
            );
          }
        }
      }
    }
  });

  it("rejects a stale update with revision_conflict and accepts it after syncing", async () => {
    const { overview, details } = owner.getItem(itemId);

    await bob.sync();
    await bob.updateItem(itemId, overview, {
      ...details,
      notes: "bob was first",
    });

    const error = await owner
      .updateItem(itemId, overview, { ...details, notes: "owner second" })
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ code: "revision_conflict" });

    await owner.sync();
    await owner.updateItem(itemId, overview, {
      ...owner.getItem(itemId).details,
      notes: "owner after sync",
    });

    expect(owner.getItem(itemId).details.notes).toBe("owner after sync");
  });

  it("does not let a view-only member write", async () => {
    await owner.grantAccess(vaultId, bob.user.id, "view");
    await bob.sync();

    const { overview, details } = bob.getItem(itemId);

    await expect(
      bob.updateItem(itemId, overview, details),
    ).rejects.toMatchObject({ status: 403 });
  });

  it("cuts a suspended member off immediately", async () => {
    let ended = false;
    bob.onEnded(() => {
      ended = true;
    });
    await owner.orgAdmin().suspendMember(bob.user.id);

    const failure: unknown = await bob.sync().catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(ApiError);
    expect(loginEnded(failure)).toBe(true);
    expect(ended).toBe(true);
    await expect(
      loginAs(server, "bob@example.com", "bob-password", bobSecretKey),
    ).rejects.toMatchObject({ status: 403 });
  });

  it("records every sensitive action in the audit log", async () => {
    const actions = (await owner.orgAdmin().auditLog(200)).map(
      (event) => event.action,
    );

    expect(actions).toEqual(
      expect.arrayContaining([
        "org.bootstrapped",
        "org.invite_created",
        "user.signed_up",
        "org.member_confirmed",
        "vault.created",
        "item.created",
        "item.updated",
        "vault.access_granted",
        "org.member_suspended",
      ]),
    );
  });
});
