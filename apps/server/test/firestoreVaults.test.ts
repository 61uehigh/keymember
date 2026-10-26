import { Firestore } from "@google-cloud/firestore";
import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { COLLECTIONS, documentId } from "../src/firestore/collections.js";
import {
  DirectDocuments,
  runDocumentTransaction,
} from "../src/firestore/FirestoreDocuments.js";
import { FirestoreChangeFeedRepository } from "../src/firestore/FirestoreChangeFeedRepository.js";
import { FirestoreItemRepository } from "../src/firestore/FirestoreItemRepository.js";
import { FirestoreVaultRepository } from "../src/firestore/FirestoreVaultRepository.js";
import type { VaultGrant } from "../src/repositories/VaultRepository.js";

const emulator = process.env.FIRESTORE_EMULATOR_HOST;
const projectId = "demo-keymember-vaults";

const bytes = (...values: Array<number>): Uint8Array => new Uint8Array(values);

const grant = (
  principalId: string,
  permission: VaultGrant["permission"],
  principalType: VaultGrant["principalType"] = "user",
): VaultGrant => ({
  principalType,
  principalId,
  wrappedKey: bytes(1),
  permission,
  grantSignature: bytes(2),
});

describe.skipIf(emulator === undefined)("Firestore vaults and items", () => {
  const db = new Firestore({ projectId });
  const docs = new DirectDocuments(db);
  const vaults = new FirestoreVaultRepository(docs);
  const items = new FirestoreItemRepository(docs);
  const changeFeed = new FirestoreChangeFeedRepository(docs);

  const addGroup = async (
    groupId: string,
    memberIds: ReadonlyArray<string>,
    deleted = false,
  ): Promise<void> => {
    await docs.set(COLLECTIONS.groups, groupId, {
      id: groupId,
      orgId: "org",
      name: groupId,
      encryptionPublicKey: bytes(0),
      keysetVersion: 1,
      certificate: "{}",
      certificateSignature: bytes(0),
      recoveryWrappedKey: null,
      createdBy: "admin",
      createdAt: new Date(0),
      deletedAt: deleted ? new Date(0) : null,
      revision: await docs.nextSequence("change"),
    });

    for (const userId of memberIds) {
      await docs.set(
        COLLECTIONS.groupMembers,
        documentId.groupMember(groupId, userId),
        {
          groupId,
          userId,
          wrappedPrivateKey: bytes(0),
          keysetVersion: 1,
          revision: await docs.nextSequence("change"),
        },
      );
    }
  };

  const addVault = (id: string, kind: "personal" | "shared" = "shared") =>
    vaults.insert({
      id,
      orgId: "org",
      kind,
      encryptedName: bytes(7),
      createdBy: "alice",
    });

  beforeEach(async () => {
    await fetch(
      `http://${emulator ?? ""}/emulator/v1/projects/${projectId}/databases/(default)/documents`,
      { method: "DELETE" },
    );
  });

  afterAll(async () => {
    await db.terminate();
  });

  it("creates vaults and reports access through users and live groups", async () => {
    await addVault("v1");
    expect(await vaults.exists("v1")).toBe(true);
    expect(await vaults.exists("v2")).toBe(false);
    expect(await vaults.liveKeyGeneration("v1")).toBe(1);

    await addGroup("g-live", ["bob"]);
    await addGroup("g-dead", ["carol"], true);
    await vaults.putGrant("v1", grant("alice", "manage"), 1, "alice");
    await vaults.putGrant("v1", grant("g-live", "edit", "group"), 1, "alice");
    await vaults.putGrant("v1", grant("g-dead", "view", "group"), 1, "alice");

    expect(await vaults.accessOf("v1", "alice")).toEqual([
      { permission: "manage", kind: "shared", keyGeneration: 1 },
    ]);
    expect(await vaults.accessOf("v1", "bob")).toEqual([
      { permission: "edit", kind: "shared", keyGeneration: 1 },
    ]);
    expect(await vaults.accessOf("v1", "carol")).toEqual([]);
    expect(await vaults.grants("v1")).toEqual([
      expect.objectContaining({
        principalType: "user",
        principalId: "alice",
        permission: "manage",
      }),
      expect.objectContaining({
        principalType: "group",
        principalId: "g-dead",
        permission: "view",
      }),
      expect.objectContaining({
        principalType: "group",
        principalId: "g-live",
        permission: "edit",
      }),
    ]);
    expect(await vaults.userGrants("alice")).toEqual([
      { vaultId: "v1", permission: "manage" },
    ]);
  });

  it("keeps the stored principal type when a grant is replaced", async () => {
    await addVault("v1");
    await vaults.putGrant("v1", grant("g", "view", "group"), 1, "alice");
    await vaults.putGrant("v1", grant("g", "edit", "user"), 2, "alice");

    expect(await vaults.grants("v1")).toEqual([
      expect.objectContaining({
        principalType: "group",
        principalId: "g",
        permission: "edit",
      }),
    ]);
  });

  it("tracks managers and vaults that would lose their last one", async () => {
    await addVault("v1");
    await addVault("v2");
    await addGroup("admins", ["bob", "carol"]);
    await vaults.putGrant("v1", grant("alice", "manage"), 1, "alice");
    await vaults.putGrant("v2", grant("alice", "manage"), 1, "alice");
    await vaults.putGrant("v2", grant("admins", "manage", "group"), 1, "alice");

    expect(await vaults.hasManager("v1")).toBe(true);
    expect(await vaults.leftWithoutManager("alice")).toEqual(["v1"]);
    expect(await vaults.leftWithoutManager("alice", ["v2"])).toEqual([]);
    expect(
      (await vaults.managers(["v1", "v2"], "bob")).sort((a, b) =>
        `${a.vaultId}${a.userId}`.localeCompare(`${b.vaultId}${b.userId}`),
      ),
    ).toEqual([
      { vaultId: "v1", userId: "alice" },
      { vaultId: "v2", userId: "alice" },
      { vaultId: "v2", userId: "carol" },
    ]);

    await vaults.removeGrant("v1", "alice");
    expect(await vaults.hasManager("v1")).toBe(false);
  });

  it("replaces grants and removes them by principal", async () => {
    await addVault("v1");
    await vaults.putGrant("v1", grant("alice", "manage"), 1, "alice");
    await vaults.putGrant("v1", grant("bob", "view"), 1, "alice");
    await vaults.replaceGrants(
      "v1",
      [grant("alice", "manage"), grant("g", "edit", "group")],
      2,
      "alice",
    );

    expect(await vaults.grants("v1")).toEqual([
      expect.objectContaining({
        principalType: "user",
        principalId: "alice",
        permission: "manage",
      }),
      expect.objectContaining({
        principalType: "group",
        principalId: "g",
        permission: "edit",
      }),
    ]);

    await vaults.removeGroupGrants("g");
    await vaults.removeUserGrants("alice");
    expect(await vaults.grants("v1")).toEqual([]);
  });

  it("lists access paths with the user's own grant first and group revisions", async () => {
    await addVault("v1");
    await addVault("v2", "personal");
    await addGroup("g", ["alice"]);
    await vaults.putGrant("v1", grant("g", "edit", "group"), 1, "bob");
    await vaults.putGrant("v1", grant("alice", "view"), 1, "bob");
    await vaults.putGrant("v2", grant("alice", "manage"), 1, "alice");

    // Re-adding alice to the group makes the membership newer than the grant
    const memberRevision = await docs.nextSequence("change");

    await docs.update(
      COLLECTIONS.groupMembers,
      documentId.groupMember("g", "alice"),
      { revision: memberRevision },
    );

    const paths = await vaults.accessPaths("alice");

    expect(
      paths.map((path) => [path.vaultId, path.principalType, path.principalId]),
    ).toEqual([
      ["v1", "user", "alice"],
      ["v1", "group", "g"],
      ["v2", "user", "alice"],
    ]);
    expect(paths[1]?.accessRevision).toBe(memberRevision);
    expect(paths[0]).toMatchObject({
      kind: "shared",
      encryptedName: bytes(7),
      keyGeneration: 1,
      rotationDue: false,
      wrappedKey: bytes(1),
      accessGeneration: 1,
      grantedBy: "bob",
      grantSignature: bytes(2),
    });
  });

  it("rotates keys, flags shared vaults and keeps recovery copies per generation", async () => {
    await addVault("v1");
    await addVault("v2", "personal");
    await addVault("v3");
    await addGroup("g", ["alice"]);
    await vaults.putGrant("v1", grant("alice", "manage"), 1, "alice");
    await vaults.putGrant("v2", grant("alice", "manage"), 1, "alice");
    await vaults.putGrant("v3", grant("g", "manage", "group"), 1, "alice");

    expect(
      await vaults.flagForRotation("alice", ["g"], new Date(5000)),
    ).toEqual(["v1", "v3"]);
    expect((await vaults.accessPaths("alice"))[0]?.rotationDue).toBe(true);

    await vaults.storeRecoveryWrap("v1", bytes(9), 1);
    expect(await vaults.recoveryCopies(["v1", "v3"])).toEqual([
      { vaultId: "v1", keyGeneration: 1, wrappedKey: bytes(9) },
    ]);

    await vaults.advanceKey("v1", 2, bytes(8));
    expect(await vaults.liveKeyGeneration("v1")).toBe(2);
    expect(await vaults.recoveryCopies(["v1"])).toEqual([]);
    expect((await vaults.accessPaths("alice"))[0]).toMatchObject({
      keyGeneration: 2,
      encryptedName: bytes(8),
      rotationDue: false,
    });

    expect(await vaults.grantsToGroup("g")).toEqual([
      {
        vaultId: "v3",
        wrappedKey: bytes(1),
        keyGeneration: 1,
        vaultKeyGeneration: 1,
        permission: "manage",
      },
    ]);
    await vaults.rewrapForGroup(
      "v3",
      "g",
      { wrappedKey: bytes(4), keyGeneration: 1, grantSignature: bytes(5) },
      "bob",
    );
    await vaults.rewrapForGroup(
      "v1",
      "alice",
      { wrappedKey: bytes(4), keyGeneration: 1, grantSignature: bytes(5) },
      "bob",
    );
    expect((await vaults.grantsToGroup("g"))[0]?.wrappedKey).toEqual(bytes(4));
    expect(
      (await vaults.accessPaths("alice")).find((path) => path.vaultId === "v1")
        ?.wrappedKey,
    ).toEqual(bytes(1));
  });

  it("stores items, versions them and syncs changes", async () => {
    const item = (id: string, vaultId = "v1") => ({
      id,
      vaultId,
      encryptedItemKey: bytes(1),
      encryptedOverview: bytes(2),
      encryptedDetails: bytes(3),
    });
    const at = new Date(1000);

    const first = await items.insert(item("i1"), "alice", at);
    const second = await items.insert(item("i2"), "alice", at);

    await items.insert(item("i3", "v2"), "alice", at);

    expect(second).toBeGreaterThan(first);
    expect(await items.exists("i1")).toBe(true);
    expect(await items.isLiveIn("i1", "v1")).toBe(true);
    expect(await items.isLiveIn("i1", "v2")).toBe(false);
    expect(await items.lockLive("i1")).toEqual({
      vaultId: "v1",
      revision: first,
    });

    const replaced = await items.replace(item("i1", "v2"), "bob", at);

    expect(replaced).toBeGreaterThan(second);
    expect(await items.lockLive("i1")).toEqual({
      vaultId: "v2",
      revision: replaced,
    });
    expect(await items.replace(item("missing"), "bob", at)).toBeNaN();
    expect(await items.exists("missing")).toBe(false);

    await items.markDeleted("i2", at);
    expect(await items.lockLive("i2")).toBeUndefined();
    expect(await items.lockLive("missing")).toBeUndefined();
    expect(await items.lockLiveInVault("v1")).toEqual([]);

    await items.reencrypt(
      {
        id: "i3",
        encryptedItemKey: bytes(4),
        encryptedOverview: bytes(5),
        encryptedDetails: bytes(6),
      },
      "bob",
      at,
    );

    const changes = await items.changesForSync(["v1", "v2"], second, []);

    expect(changes.map((change) => [change.id, change.deleted])).toEqual([
      ["i1", false],
      ["i2", true],
      ["i3", false],
    ]);
    expect(changes[2]).toMatchObject({ encryptedItemKey: bytes(4) });
    expect(
      (await items.changesForSync(["v2"], 1_000_000, ["v2"])).map(
        (change) => change.id,
      ),
    ).toEqual(["i1", "i3"]);
    expect(await changeFeed.latestRevision()).toBe(
      Math.max(...changes.map((change) => change.revision)),
    );
  });

  it("orders writers on the revision counter", async () => {
    const pause = (): Promise<void> =>
      new Promise((resolve) => setTimeout(resolve, 200));
    const write = (id: string): Promise<number> =>
      runDocumentTransaction(db, async (tx) => {
        await new FirestoreChangeFeedRepository(tx).lock();
        await pause();

        return new FirestoreItemRepository(tx).insert(
          {
            id,
            vaultId: "v1",
            encryptedItemKey: bytes(1),
            encryptedOverview: bytes(2),
            encryptedDetails: bytes(3),
          },
          "alice",
          new Date(0),
        );
      });

    const revisions = await Promise.all([write("a"), write("b")]);

    expect(revisions.sort()).toEqual([1, 2]);
    expect(await changeFeed.latestRevision()).toBe(2);
  });
});
