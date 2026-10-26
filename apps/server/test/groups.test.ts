import { recoverAccount, Session } from "@keymember/client";
import { generateEncryptionKeyPair, toBase64Url } from "@keymember/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  bootstrapTeam,
  joinTeam,
  loginAs,
  rewriting,
  serverFixture,
} from "./harness.js";
import type { TestServer } from "./harness.js";

interface Team {
  owner: Session;
  alice: Session;
  bob: Session;
  carol: Session;
}

/**
 * ### setUpTeam
 *
 * Creates an organisation with an owner, an admin (Alice) and two members (Bob, Carol), all certified.
 *
 * @param server Test server
 * @returns Logged-in sessions
 */
async function setUpTeam(server: TestServer): Promise<Team> {
  const owner = (await bootstrapTeam(server)).session;
  const join = async (email: string, role?: "admin" | "member") =>
    (await joinTeam(server, owner, email, role)).session;

  return {
    owner,
    alice: await join("alice@example.com", "admin"),
    bob: await join("bob@example.com"),
    carol: await join("carol@example.com"),
  };
}

describe("groups", () => {
  const fixture = serverFixture(setUpTeam);
  let server: TestServer;
  let team: Team & {
    join: (email: string) => Promise<Session>;
  };

  beforeEach(async () => {
    const restored = await fixture.restore();

    server = restored.server;
    team = {
      ...restored.fixture,
      join: async (email) =>
        (await joinTeam(server, restored.fixture.owner, email)).session,
    };
  });

  afterEach(async () => {
    await server.close();
  });

  /**
   * ### sharedVault
   *
   * Creates a group of Bob and Carol and a vault shared with it, holding one item.
   *
   * @returns Group, vault and item ids
   */
  async function sharedVault(): Promise<{
    groupId: string;
    vaultId: string;
    itemId: string;
  }> {
    const { owner, bob, carol } = team;
    const groupId = await owner
      .groupAdmin()
      .create("개발", [bob.user.id, carol.user.id]);
    const vaultId = await owner.createVault(
      "개발 공용",
      "shared",
      [],
      [{ groupId, permission: "edit" }],
    );
    const itemId = await owner.createItem(
      vaultId,
      { type: "login", title: "CI", urls: [], tags: [] },
      { password: "ci-pass", fields: [], passwordHistory: [] },
    );

    return { groupId, vaultId, itemId };
  }

  it("gives every group member the vault with the strongest permission they hold", async () => {
    const { owner, bob, carol } = team;
    const { groupId, vaultId, itemId } = await sharedVault();

    await owner.grantAccess(vaultId, bob.user.id, "view");
    await bob.sync();
    await carol.sync();

    expect(bob.getItem(itemId).details.password).toBe("ci-pass");
    expect(carol.getItem(itemId).details.password).toBe("ci-pass");
    expect(bob.listVaults()[0]?.permission).toBe("edit");

    // Edit through the group is enforced by the server too
    await bob.createItem(
      vaultId,
      { type: "login", title: "from bob", urls: [], tags: [] },
      { password: "x", fields: [], passwordHistory: [] },
    );

    const [group] = await owner.groups();

    expect(group).toMatchObject({
      id: groupId,
      name: "개발",
      keysetVersion: 1,
    });
    expect(group?.certificate).toBeDefined();
    expect(new Set(group?.memberIds)).toEqual(
      new Set([bob.user.id, carol.user.id]),
    );
    expect(await owner.vaultAccess(vaultId)).toContainEqual({
      principalType: "group",
      principalId: groupId,
      permission: "edit",
    });
  });

  it("rotates the group key when a member leaves, and lets an admin outside the group add members", async () => {
    const { owner, alice, bob, carol, join } = team;
    const { groupId, vaultId, itemId } = await sharedVault();

    await carol.sync();
    expect(carol.listVaults().map((vault) => vault.id)).toEqual([vaultId]);

    await owner.groupAdmin().removeMember(groupId, carol.user.id);
    await carol.sync();
    await bob.sync();

    expect(carol.listVaults()).toEqual([]);
    expect(bob.getItem(itemId).details.password).toBe("ci-pass");
    expect((await owner.groups())[0]?.keysetVersion).toBe(2);

    // Alice holds no group copy; she opens the group key through the recovery key
    const dave = await join("dave@example.com");

    // Dave has synced past the vault's items, so joining must bring them in full
    await dave.sync();
    expect(dave.listVaults()).toEqual([]);

    await alice.groupAdmin().addMember(groupId, dave.user.id);
    await dave.sync();

    expect(dave.getItem(itemId).details.password).toBe("ci-pass");

    const rows = await server.tables.select("group_members", {
      group_id: groupId,
    });

    expect(rows.map((row) => row.user_id).sort()).toEqual(
      [bob.user.id, dave.user.id].sort(),
    );
  });

  it("refuses to share with a group key the server swapped", async () => {
    const { groupId } = await sharedVault();
    const forged = toBase64Url(generateEncryptionKeyPair().publicKey);
    const swapping = rewriting(server.transport, {
      response: (path, body) => {
        if (path !== "/api/org/groups") {
          return body;
        }

        const { groups } = body as {
          groups: Array<{ certificate: Record<string, unknown> }>;
        };

        // Both the served key and the certificate's key are replaced; only the signature can tell
        return {
          groups: groups.map((group) => ({
            ...group,
            encryptionPublicKey: forged,
            certificate: { ...group.certificate, encryptionPublicKey: forged },
          })),
        };
      },
    });
    const session = Session.fromSnapshot(swapping, team.owner.toSnapshot());

    session.setRoots(server.roots);

    expect((await session.groups())[0]?.certificate).toBeUndefined();
    await expect(
      session.createVault("x", "shared", [], [{ groupId, permission: "view" }]),
    ).rejects.toThrow(/isn't certified by a trusted admin/);
  });

  it("leaves a member the server slipped into the group out of the next key", async () => {
    const { owner, carol } = team;
    const { groupId } = await sharedVault();
    const [current] = await server.tables.select("group_members", {
      group_id: groupId,
    });

    // A hostile server adds Dave with a copy no admin signed
    const dave = await team.join("dave@example.com");

    await server.tables.insert("group_members", {
      group_id: groupId,
      user_id: dave.user.id,
      wrapped_private_key: new Uint8Array(80),
      keyset_version: current?.keyset_version,
    });
    await owner.groupAdmin().rotate(groupId);

    const members = await server.tables.select("group_members", {
      group_id: groupId,
    });

    expect(members.map((row) => row.user_id).sort()).toEqual(
      [team.bob.user.id, carol.user.id].sort(),
    );
    expect(
      members.every((row) => row.membership_signature instanceof Uint8Array),
    ).toBe(true);
  });

  it("rejects a vault key wrapped to a superseded group key", async () => {
    const { owner, bob } = team;
    const { groupId } = await sharedVault();
    const otherVault = await owner.createVault("기타", "shared", []);

    await owner.groupAdmin().rotate(groupId);

    const stale = rewriting(server.transport, {
      request: (path, body) =>
        path.endsWith(`/access/${groupId}`)
          ? { ...(body as Record<string, unknown>), groupKeysetVersion: 1 }
          : body,
    });
    const ownerViaStale = Session.fromSnapshot(stale, owner.toSnapshot());

    ownerViaStale.setRoots(server.roots);

    await ownerViaStale.sync();
    await expect(
      ownerViaStale.grantGroupAccess(otherVault, groupId, "view"),
    ).rejects.toMatchObject({ status: 409 });

    await owner.grantGroupAccess(otherVault, groupId, "view");
    await bob.sync();
    expect(bob.listVaults().map((vault) => vault.id)).toContain(otherVault);
  });

  it("restores group membership on account recovery and drops it on suspension", async () => {
    const { owner, alice, bob, carol } = team;
    const { itemId } = await sharedVault();
    const recoveryId = await alice.recovery().request(bob.user.id);
    // Both admins must have been members for 7 days before a recovery is approved
    server.clock.now = new Date(
      server.clock.now.getTime() + 8 * 24 * 60 * 60 * 1000,
    );

    const { recoveryToken } = await owner.recovery().approve(recoveryId);
    const recovered = await recoverAccount(
      server.transport,
      recoveryToken,
      "bob-new-password",
    );
    const newBob = await loginAs(
      server,
      "bob@example.com",
      "bob-new-password",
      recovered.secretKey,
    );

    await alice.orgAdmin().certify(newBob.user.id, newBob.fingerprint);

    expect(await alice.recovery().complete(recoveryId)).toEqual({
      vaults: 0,
      groups: 1,
    });

    await newBob.sync();
    expect(newBob.getItem(itemId).details.password).toBe("ci-pass");

    await owner.orgAdmin().suspendMember(carol.user.id);

    const rows = await server.tables.select("group_members", {
      user_id: carol.user.id,
    });

    expect(rows).toEqual([]);
  });

  it("deletes a group only when its vaults keep another manager", async () => {
    const { owner, bob } = team;
    const { groupId, vaultId } = await sharedVault();
    const groupManaged = await owner.createVault(
      "그룹 관리",
      "shared",
      [],
      [{ groupId, permission: "manage" }],
    );

    // The owner leaves the vault, so only the group manages it
    await owner.revokeAccess(groupManaged, owner.user.id);
    await expect(owner.groupAdmin().delete(groupId)).rejects.toMatchObject({
      status: 409,
    });

    await bob.sync();
    await bob.grantAccess(groupManaged, bob.user.id, "manage");
    await owner.groupAdmin().delete(groupId);
    await bob.sync();

    expect(bob.listVaults().map((vault) => vault.id)).toEqual([groupManaged]);
    expect(await owner.groups()).toEqual([]);
    expect(
      (await owner.vaultAccess(vaultId)).map((entry) => entry.principalType),
    ).toEqual(["user"]);
  });

  it("only lets admins manage groups", async () => {
    const { bob, carol } = team;

    await expect(
      bob.groupAdmin().create("몰래", [carol.user.id]),
    ).rejects.toMatchObject({ status: 403 });
  });
});
