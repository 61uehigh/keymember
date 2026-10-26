import { ApiError, logIn, recoverAccount, Session } from "@keymember/client";
import type { Transport } from "@keymember/client";
import {
  generateEncryptionKeyPair,
  generateVaultKey,
  sealVaultName,
  toBase64Url,
  wrapVaultKey,
} from "@keymember/core";
import type { SecretKey } from "@keymember/core";
import { codeForStep } from "@keymember/server";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  base32Decode,
  bootstrapTeam,
  joinTeam,
  loginAs,
  rewriting,
  serverFixture,
} from "./harness.js";
import type { TestServer } from "./harness.js";
import { NEXT_REVISION } from "./tables.js";

interface Team {
  owner: Session;
  ownerSecretKey: SecretKey;
  alice: Session;
  bob: Session;
  bobSecretKey: SecretKey;
}

/**
 * ### setUpTeam
 *
 * Creates an organisation with an owner, a second admin (Alice) and a member (Bob), all certified.
 *
 * @param server Test server
 * @returns Logged-in sessions and the Secret Keys tests log in with again
 */
async function setUpTeam(server: TestServer): Promise<Team> {
  const owner = await bootstrapTeam(server);
  const alice = await joinTeam(
    server,
    owner.session,
    "alice@example.com",
    "admin",
  );
  const bob = await joinTeam(server, owner.session, "bob@example.com");

  return {
    owner: owner.session,
    ownerSecretKey: owner.secretKey,
    alice: alice.session,
    bob: bob.session,
    bobSecretKey: bob.secretKey,
  };
}

describe("account recovery, key rotation and policies", () => {
  const fixture = serverFixture(setUpTeam);
  let server: TestServer;
  let team: Team;

  beforeEach(async () => {
    ({ server, fixture: team } = await fixture.restore());
  });

  afterEach(async () => {
    await server.close();
  });

  it("wraps every vault key for the recovery key and refuses vaults without that copy", async () => {
    const { owner, bob } = team;
    const vaultId = await owner.createVault("인프라", "shared", [
      { userId: bob.user.id, permission: "edit" },
    ]);
    const rows = await server.tables.select("vault_recovery", {
      vault_id: vaultId,
    });

    expect(rows.map((row) => row.key_generation)).toEqual([1]);

    const stripping = rewriting(server.transport, {
      request: (path, body) => {
        if (
          path !== "/api/vaults" ||
          typeof body !== "object" ||
          body === null
        ) {
          return body;
        }

        const { recoveryWrappedKey: _dropped, ...rest } = body as Record<
          string,
          unknown
        >;

        return rest;
      },
    });
    const ownerViaStripper = await loginAsOwner(stripping);

    await expect(
      ownerViaStripper.createVault("no recovery", "personal", []),
    ).rejects.toMatchObject({
      status: 400,
    });
  });

  it("refuses to wrap vault keys to a recovery key the server swapped", async () => {
    const swapping = rewriting(server.transport, {
      response: (path, body) =>
        path === "/api/org" && typeof body === "object" && body !== null
          ? {
              ...(body as Record<string, unknown>),
              recoveryKey: {
                ...(body as { recoveryKey: Record<string, unknown> })
                  .recoveryKey,
                publicKey: toBase64Url(generateEncryptionKeyPair().publicKey),
              },
            }
          : body,
    });
    const owner = await loginAsOwner(swapping);

    await expect(owner.createVault("x", "personal", [])).rejects.toThrow(
      /recovery key isn't signed by a trusted admin/,
    );
  });

  it("recovers a member with two admins without either seeing the member's secrets", async () => {
    const { owner, alice, bob } = team;
    const vaultId = await owner.createVault("인프라", "shared", [
      { userId: bob.user.id, permission: "edit" },
    ]);
    const itemId = await owner.createItem(
      vaultId,
      { type: "login", title: "DB", urls: [], tags: [] },
      { password: "db-pass", fields: [], passwordHistory: [] },
    );
    const recoveryId = await alice.recovery().request(bob.user.id);

    // The requester cannot also approve
    await expect(alice.recovery().approve(recoveryId)).rejects.toMatchObject({
      status: 403,
    });

    // Both admins must have been members for 7 days before a recovery is approved
    server.clock.now = new Date(
      server.clock.now.getTime() + 8 * 24 * 60 * 60 * 1000,
    );

    const { recoveryToken } = await owner.recovery().approve(recoveryId);

    // Approval freezes the account and ends its sessions
    await expect(bob.sync()).rejects.toBeInstanceOf(ApiError);

    // Admins still read the directory while a member is mid-recovery
    expect(
      (await owner.directory()).find((member) => member.userId === bob.user.id)
        ?.status,
    ).toBe("recovering");

    const recovered = await recoverAccount(
      server.transport,
      recoveryToken,
      "bob-new-password",
    );

    // The old credentials are gone, and the token is single-use
    await expect(
      loginAs(server, "bob@example.com", "bob-password", team.bobSecretKey),
    ).rejects.toMatchObject({
      code: "invalid_credentials",
    });
    await expect(
      recoverAccount(server.transport, recoveryToken, "again-password"),
    ).rejects.toMatchObject({
      status: 403,
    });

    const newBob = await loginAs(
      server,
      "bob@example.com",
      "bob-new-password",
      recovered.secretKey,
    );

    // New keys stay untrusted until an admin compares fingerprints and certifies them
    await expect(newBob.sync()).rejects.toMatchObject({ status: 403 });
    await expect(alice.recovery().complete(recoveryId)).rejects.toThrow(
      /Verify the member's new key/,
    );

    await alice.orgAdmin().certify(newBob.user.id, newBob.fingerprint);

    expect(await alice.recovery().complete(recoveryId)).toEqual({
      vaults: 1,
      groups: 0,
    });

    await newBob.sync();

    expect(newBob.getItem(itemId).details.password).toBe("db-pass");

    const actions = (await owner.orgAdmin().auditLog(200)).map(
      (event) => event.action,
    );

    expect(actions).toEqual(
      expect.arrayContaining([
        "recovery.requested",
        "recovery.approved",
        "recovery.rekeyed",
        "recovery.completed",
      ]),
    );
  });

  it("cancels a recovery as soon as the member logs in with the original credentials", async () => {
    const { owner, alice, bob } = team;
    const recoveryId = await alice.recovery().request(bob.user.id);
    // Both admins must have been members for 7 days before a recovery is approved
    server.clock.now = new Date(
      server.clock.now.getTime() + 8 * 24 * 60 * 60 * 1000,
    );

    const { recoveryToken } = await owner.recovery().approve(recoveryId);
    const again = await loginAs(
      server,
      "bob@example.com",
      "bob-password",
      team.bobSecretKey,
    );

    expect(again.recoveryCancelled).toBe(true);
    await expect(again.sync()).resolves.toBeUndefined();
    await expect(
      recoverAccount(server.transport, recoveryToken, "hijack-password"),
    ).rejects.toMatchObject({
      status: 403,
    });
    expect(
      (await owner.recovery().list()).find(
        (recovery) => recovery.id === recoveryId,
      )?.status,
    ).toBe("cancelled");
  });

  it("does not let admins recover the owner, whose key every device trusts", async () => {
    await expect(
      team.alice.recovery().request(team.owner.user.id),
    ).rejects.toMatchObject({ status: 400 });
  });

  it("rotates a vault key, drops a member and re-encrypts every item", async () => {
    const { owner, alice, bob } = team;
    const vaultId = await owner.createVault("인프라", "shared", [
      { userId: bob.user.id, permission: "view" },
    ]);
    const itemId = await owner.createItem(
      vaultId,
      { type: "login", title: "DB", urls: [], tags: [] },
      { password: "before-rotation", fields: [], passwordHistory: [] },
    );
    const [before] = await server.tables.select("items", { id: itemId });

    await owner.rotateVaultKey(vaultId, [bob.user.id]);
    await bob.sync();

    expect(bob.listVaults()).toEqual([]);

    const [after] = await server.tables.select("items", { id: itemId });
    const recoveryRows = await server.tables.select("vault_recovery", {
      vault_id: vaultId,
    });

    expect(after?.enc_item_key).not.toEqual(before?.enc_item_key);
    expect(recoveryRows.map((row) => row.key_generation)).toEqual([2]);
    expect(owner.getItem(itemId).details.password).toBe("before-rotation");

    // New grants use the new generation
    await owner.grantAccess(vaultId, alice.user.id, "view");
    await alice.sync();

    expect(alice.getItem(itemId).details.password).toBe("before-rotation");
  });

  it("blocks vault access until a member enrols two-factor login when the policy requires it", async () => {
    const { owner, bob } = team;

    await owner.orgAdmin().setRequireTotp(true);

    await expect(bob.sync()).rejects.toMatchObject({
      code: "totp_enrollment_required",
    });

    const { secret } = await bob.setupTotp();
    const step = Math.floor(server.clock.now.getTime() / 30_000);

    await bob.confirmTotp(codeForStep(base32Decode(secret), step));

    await expect(bob.sync()).resolves.toBeUndefined();
  });

  /**
   * ### loginAsOwner
   *
   * Logs the owner in through a different transport, such as a tampering one.
   *
   * @param transport Transport to use
   * @returns The owner's session over that transport
   */
  async function loginAsOwner(transport: Transport): Promise<Session> {
    const session = await logIn(transport, {
      email: "owner@example.com",
      password: "owner-password",
      secretKey: team.ownerSecretKey,
      deviceId: crypto.randomUUID(),
      deviceName: "tamper",
    });

    session.setRoots(server.roots);

    return session;
  }

  it("ignores a vault key the server wraps to a member without a signed grant", async () => {
    const { bob, owner } = team;
    const vaultId = crypto.randomUUID();
    const serverKnownKey = generateVaultKey();
    const wrapped = await wrapVaultKey(serverKnownKey, vaultId, 1, {
      principalId: bob.user.id,
      encryptionPublicKey:
        (await owner.directory()).find(
          (member) => member.userId === bob.user.id,
        )?.certificate?.encryptionPublicKey ?? new Uint8Array(32),
    });
    const [org] = await server.tables.select("organizations");

    // A hostile server plants a vault whose key it knows, claiming the owner granted it
    await server.tables.insert("vaults", {
      id: vaultId,
      org_id: org?.id,
      kind: "shared",
      enc_name: sealVaultName(serverKnownKey, vaultId, "Engineering"),
      key_generation: 1,
      created_by: owner.user.id,
      revision: NEXT_REVISION,
      deleted_at: null,
      rotation_due_at: null,
    });
    await server.tables.insert("vault_access", {
      vault_id: vaultId,
      principal_type: "user",
      principal_id: bob.user.id,
      wrapped_key: wrapped,
      key_generation: 1,
      permission: "edit",
      revision: NEXT_REVISION,
      granted_by: owner.user.id,
      grant_signature: new Uint8Array(64),
    });

    await bob.sync();

    expect(bob.listVaults().map((vault) => vault.id)).not.toContain(vaultId);

    // A genuine grant from a certified member still works
    const real = await owner.createVault("인프라", "shared", [
      { userId: bob.user.id, permission: "view" },
    ]);

    await bob.sync();
    expect(bob.listVaults().map((vault) => vault.id)).toEqual([real]);
  });

  it("keeps personal vaults personal through rotation and keeps a manager on every vault", async () => {
    const { owner } = team;
    const personal = await owner.createVault("개인", "personal", []);
    const shared = await owner.createVault("공유", "shared", []);
    const widening = Session.fromSnapshot(
      rewriting(server.transport, {
        request: (path, body) => {
          if (!path.endsWith(`/vaults/${personal}/rotate`)) {
            return body;
          }

          const { access } = body as { access: Array<unknown> };

          return { ...(body as object), access: [...access, ...access] };
        },
      }),
      owner.toSnapshot(),
    );

    widening.setRoots(server.roots);
    await expect(widening.rotateVaultKey(personal)).rejects.toMatchObject({
      status: 400,
    });

    await owner.sync();
    await expect(
      owner.grantAccess(shared, owner.user.id, "view"),
    ).rejects.toMatchObject({ status: 409 });
  });
});
