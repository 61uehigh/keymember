import { Firestore } from "@google-cloud/firestore";
import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { COLLECTIONS } from "../src/firestore/collections.js";
import {
  DirectDocuments,
  runDocumentTransaction,
} from "../src/firestore/FirestoreDocuments.js";
import { FirestoreGroupRepository } from "../src/firestore/FirestoreGroupRepository.js";
import { FirestoreMembershipRepository } from "../src/firestore/FirestoreMembershipRepository.js";
import { FirestoreRecoveryRepository } from "../src/firestore/FirestoreRecoveryRepository.js";
import type { StoredCertificate } from "../src/repositories/MembershipRepository.js";

const emulator = process.env.FIRESTORE_EMULATOR_HOST;
const projectId = "demo-keymember-members";

/**
 * ### signed
 *
 * A membership signature stand-in; storage keeps it as given.
 */
const signed = { grantedBy: "alice", signature: new Uint8Array(64).fill(3) };

describe.skipIf(emulator === undefined)(
  "Firestore memberships, groups and recoveries",
  () => {
    const db = new Firestore({ projectId });
    const docs = new DirectDocuments(db);
    const at = new Date("2026-10-24T10:00:00Z");

    const addUser = (id: string, email: string): Promise<void> =>
      docs.set(COLLECTIONS.users, id, {
        id,
        email,
        name: email.split("@")[0] ?? email,
        encryptionPublicKey: new Uint8Array([1]),
        signingPublicKey: new Uint8Array([2]),
        keysetVersion: 3,
        selfSignature: new Uint8Array([4]),
      });

    const certificate: StoredCertificate = {
      orgId: "org",
      userId: "bob",
      email: "bob@example.com",
      encryptionPublicKey: "AQ",
      signingPublicKey: "Ag",
      keysetVersion: 3,
      role: "member",
      issuerId: "alice",
      issuedAt: 1,
    };

    beforeEach(async () => {
      await fetch(
        `http://${emulator ?? ""}/emulator/v1/projects/${projectId}/databases/(default)/documents`,
        { method: "DELETE" },
      );
      await addUser("alice", "alice@example.com");
      await addUser("bob", "bob@example.com");
      await docs.set(COLLECTIONS.organizations, "org", {
        id: "org",
        name: "Acme",
      });
    });

    afterAll(async () => {
      await db.terminate();
    });

    it("moves a membership through certification, freezing and suspension", async () => {
      const memberships = new FirestoreMembershipRepository(docs);

      await memberships.insert("org", "bob", "member");
      expect(await memberships.isConfirmed("org", "bob")).toBe(false);
      expect(await memberships.status("bob")).toBe("accepted");
      expect(await memberships.lockForCertification("bob")).toEqual({
        email: "bob@example.com",
        orgId: "org",
        role: "member",
        status: "accepted",
        encryptionPublicKey: new Uint8Array([1]),
        signingPublicKey: new Uint8Array([2]),
        keysetVersion: 3,
      });
      expect(await memberships.confirmation("bob")).toEqual({
        confirmedBy: undefined,
        confirmedAt: undefined,
      });

      await memberships.certify(
        "bob",
        certificate,
        new Uint8Array([5]),
        "alice",
        at,
      );
      expect(await memberships.isConfirmed("org", "bob")).toBe(true);
      expect(await memberships.confirmation("bob")).toEqual({
        confirmedBy: "alice",
        confirmedAt: at,
      });

      expect(await memberships.freeze("bob")).toBe(true);
      expect(await memberships.freeze("bob")).toBe(false);
      expect(await memberships.status("bob")).toBe("recovering");
      await memberships.unfreeze("bob");
      expect(await memberships.status("bob")).toBe("confirmed");

      await memberships.resetForRekey("bob");
      expect(await memberships.lockState("org", "bob")).toEqual({
        role: "member",
        status: "accepted",
      });
      expect(
        (await memberships.directory("org"))[0]?.certificate,
      ).toBeUndefined();

      await memberships.suspend("org", "bob");
      expect(await memberships.lockRole("org", "bob")).toBe("member");
      expect(await memberships.status("bob")).toBe("suspended");
      expect(await memberships.lockRole("org", "nobody")).toBeUndefined();
      expect(await memberships.lockState("org", "nobody")).toBeUndefined();
      expect(await memberships.status("nobody")).toBeUndefined();
      expect(await memberships.lockForCertification("nobody")).toBeUndefined();
    });

    it("lists the directory by email with certificates and the last used invite", async () => {
      const memberships = new FirestoreMembershipRepository(docs);
      const invite = (
        id: string,
        usedAt: Date | null,
        statement: string,
      ): Promise<void> =>
        docs.set(COLLECTIONS.invites, id, {
          tokenHash: new Uint8Array([id.length]),
          orgId: "org",
          email: "bob@example.com",
          role: "member",
          createdBy: "alice",
          expiresAt: at,
          usedAt,
          statement,
          signature: new Uint8Array([id.length]),
        });

      await memberships.insert("org", "bob", "member");
      await memberships.insert("org", "alice", "owner");
      await memberships.certify(
        "bob",
        certificate,
        new Uint8Array([5]),
        "alice",
        at,
      );
      await invite("a", new Date(1000), '{"n":1}');
      await invite("bb", new Date(2000), '{"n":2}');
      await invite("ccc", null, '{"n":3}');

      const directory = await memberships.directory("org");

      expect(directory.map((entry) => entry.email)).toEqual([
        "alice@example.com",
        "bob@example.com",
      ]);
      expect(directory[0]?.invite).toBeUndefined();
      expect(directory[1]).toEqual({
        userId: "bob",
        email: "bob@example.com",
        name: "bob",
        role: "member",
        status: "confirmed",
        encryptionPublicKey: new Uint8Array([1]),
        signingPublicKey: new Uint8Array([2]),
        keysetVersion: 3,
        selfSignature: new Uint8Array([4]),
        certificate,
        certificateSignature: new Uint8Array([5]),
        invite: { statement: { n: 2 }, signature: new Uint8Array([2]) },
      });
    });

    it("keeps groups, their members and their key versions", async () => {
      const groups = new FirestoreGroupRepository(docs);
      const key = (version: number, name: string) => ({
        name,
        encryptionPublicKey: new Uint8Array([version]),
        keysetVersion: version,
        certificate: {
          orgId: "org",
          groupId: "g1",
          name,
          encryptionPublicKey: "AQ",
          keysetVersion: version,
          issuerId: "alice",
          issuedAt: version,
        },
        certificateSignature: new Uint8Array([9]),
        recoveryWrappedKey: version === 1 ? new Uint8Array([8]) : undefined,
      });

      expect(await groups.exists("g1")).toBe(false);
      await groups.insert({
        ...key(1, "Design"),
        id: "g1",
        orgId: "org",
        createdBy: "alice",
      });
      await groups.insert({
        ...key(1, "Admins"),
        id: "g2",
        orgId: "org",
        createdBy: "alice",
      });
      await groups.putMember("g1", "bob", new Uint8Array([7]), 1, signed);
      await groups.putMember("g1", "alice", new Uint8Array([6]), 1, signed);
      await groups.putMember("g2", "bob", new Uint8Array([5]), 1, signed);

      expect(await groups.exists("g1")).toBe(true);
      expect(await groups.liveKeysetVersion("org", "g1")).toBe(1);
      expect(await groups.liveKeysetVersion("other", "g1")).toBeUndefined();
      expect((await groups.listLive("org")).map((group) => group.name)).toEqual(
        ["Admins", "Design"],
      );
      expect((await groups.listLive("org"))[1]?.members).toEqual([
        { userId: "alice", keysetVersion: 1 },
        { userId: "bob", keysetVersion: 1 },
      ]);
      expect(await groups.liveGroupsOf("bob")).toEqual(["g1", "g2"]);
      expect(await groups.recoveryCopies(["g1", "g2", "missing"])).toEqual([
        {
          groupId: "g1",
          keysetVersion: 1,
          encryptionPublicKey: new Uint8Array([1]),
          recoveryWrappedKey: new Uint8Array([8]),
        },
        {
          groupId: "g2",
          keysetVersion: 1,
          encryptionPublicKey: new Uint8Array([1]),
          recoveryWrappedKey: new Uint8Array([8]),
        },
      ]);

      await groups.changeKey("g1", key(2, "Design"));
      await groups.putMember("g1", "bob", new Uint8Array([17]), 2, signed);
      expect(await groups.lockLive("org", "g1")).toMatchObject({
        id: "g1",
        keysetVersion: 2,
        recoveryWrappedKey: undefined,
      });
      expect(await groups.memberKey("g1", "bob")).toEqual({
        wrappedPrivateKey: new Uint8Array([17]),
        keysetVersion: 2,
      });

      // A copy written before membership signatures existed reads as unsigned
      await docs.set("groupMembers", "g1:carol", {
        groupId: "g1",
        userId: "carol",
        wrappedPrivateKey: new Uint8Array([4]),
        keysetVersion: 2,
        revision: 99,
      });
      expect(await groups.memberships("g1")).toEqual([
        {
          userId: "alice",
          wrappedPrivateKey: new Uint8Array([6]),
          keysetVersion: 1,
          grantedBy: "alice",
          signature: new Uint8Array(64).fill(3),
        },
        {
          userId: "bob",
          wrappedPrivateKey: new Uint8Array([17]),
          keysetVersion: 2,
          grantedBy: "alice",
          signature: new Uint8Array(64).fill(3),
        },
        {
          userId: "carol",
          wrappedPrivateKey: new Uint8Array([4]),
          keysetVersion: 2,
          grantedBy: undefined,
          signature: undefined,
        },
      ]);
      await docs.delete("groupMembers", "g1:carol");
      expect(await groups.keysHeldBy("alice")).toEqual([
        expect.objectContaining({
          id: "g1",
          keysetVersion: 2,
          memberKeysetVersion: 1,
          wrappedPrivateKey: new Uint8Array([6]),
        }),
      ]);

      await groups.removeFromAll("bob");
      expect(await groups.liveGroupsOf("bob")).toEqual([]);

      await groups.removeAllMembers("g1");
      await groups.markDeleted("g1", at);
      expect(await groups.lockLive("org", "g1")).toBeUndefined();
      expect(await groups.exists("g1")).toBe(true);
      expect(await groups.memberKey("g1", "alice")).toBeUndefined();
      expect((await groups.listLive("org")).map((group) => group.id)).toEqual([
        "g2",
      ]);
    });

    it("gives every group change a new revision inside a transaction", async () => {
      await runDocumentTransaction(db, async (tx) => {
        const groups = new FirestoreGroupRepository(tx);

        await groups.insert({
          id: "g1",
          orgId: "org",
          createdBy: "alice",
          name: "Design",
          encryptionPublicKey: new Uint8Array([1]),
          keysetVersion: 1,
          certificate: {
            orgId: "org",
            groupId: "g1",
            name: "Design",
            encryptionPublicKey: "AQ",
            keysetVersion: 1,
            issuerId: "alice",
            issuedAt: 1,
          },
          certificateSignature: new Uint8Array([9]),
          recoveryWrappedKey: undefined,
        });
        await groups.putMember("g1", "bob", new Uint8Array([7]), 1, signed);
        await groups.markDeleted("g1", at);
      });

      expect((await docs.get(COLLECTIONS.groups, "g1"))?.revision).toBe(3);
      expect(
        (await docs.get(COLLECTIONS.groupMembers, "g1:bob"))?.revision,
      ).toBe(2);
    });

    it("runs a recovery from request to completion", async () => {
      const recoveries = new FirestoreRecoveryRepository(docs);
      const token = {
        hash: new Uint8Array([3, 3]),
        expiresAt: new Date(at.getTime() + 60_000),
      };
      const snapshot = {
        vaults: [{ vaultId: "v1", permission: "edit" as const }],
        groups: ["g1"],
      };

      expect(await recoveries.hasOpen("bob")).toBe(false);
      await recoveries.insert(
        {
          id: "r1",
          orgId: "org",
          userId: "bob",
          requestedBy: "alice",
          requestSignature: new Uint8Array([4]),
          snapshot,
        },
        at,
      );
      expect(await recoveries.hasOpen("bob")).toBe(true);
      expect(await recoveries.find("org", "r1")).toEqual({
        id: "r1",
        orgId: "org",
        userId: "bob",
        email: "bob@example.com",
        requestedBy: "alice",
        approvedBy: undefined,
        status: "pending",
        snapshot,
        requestSignature: new Uint8Array([4]),
        createdAt: at,
      });
      expect(await recoveries.find("other", "r1")).toBeUndefined();

      expect(await recoveries.markRekeyed("r1", at)).toBe(false);
      expect(await recoveries.approve("r1", "carol", token, at)).toBe(true);
      expect(await recoveries.approve("r1", "carol", token, at)).toBe(false);
      await recoveries.replaceSnapshot("r1", { vaults: [], groups: [] });

      expect(
        await recoveries.approvedByToken(token.hash, token.expiresAt),
      ).toBeUndefined();
      expect(await recoveries.approvedByToken(token.hash, at)).toMatchObject({
        id: "r1",
        approvedBy: "carol",
        status: "approved",
        snapshot: { vaults: [], groups: [] },
        keysetVersion: 3,
        orgName: "Acme",
      });

      expect(await recoveries.markRekeyed("r1", at)).toBe(true);
      expect(await recoveries.approvedByToken(token.hash, at)).toBeUndefined();
      expect(await recoveries.complete("r1", at)).toBe(true);
      expect(await recoveries.cancel("r1", at)).toBe(false);
      expect(await recoveries.hasOpen("bob")).toBe(false);
    });

    it("cancels open recoveries for and by a member", async () => {
      const recoveries = new FirestoreRecoveryRepository(docs);
      const request = (
        id: string,
        userId: string,
        requestedBy: string,
        createdAt: Date,
      ): Promise<void> =>
        recoveries.insert(
          {
            id,
            orgId: "org",
            userId,
            requestedBy,
            requestSignature: new Uint8Array([1]),
            snapshot: { vaults: [], groups: [] },
          },
          createdAt,
        );

      await request("r1", "bob", "alice", new Date(1000));
      await request("r2", "alice", "bob", new Date(2000));

      // A member has at most one open recovery
      await expect(
        request("r9", "bob", "alice", new Date(1500)),
      ).rejects.toThrow(/already exists/);
      expect(await recoveries.cancelOpen("bob", at)).toEqual(["r1"]);

      await request("r3", "bob", "alice", new Date(3000));
      await recoveries.approve(
        "r3",
        "carol",
        { hash: new Uint8Array([1]), expiresAt: at },
        at,
      );

      expect(
        (await recoveries.list("org")).map((recovery) => recovery.id),
      ).toEqual(["r3", "r2", "r1"]);

      expect(await recoveries.cancelOpen("bob", at)).toEqual(["r3"]);
      expect((await recoveries.find("org", "r3"))?.status).toBe("cancelled");
      expect(await recoveries.hasOpen("alice")).toBe(true);

      await recoveries.cancelInvolving("bob", at);
      expect(await recoveries.hasOpen("alice")).toBe(false);
      expect((await recoveries.find("org", "r2"))?.status).toBe("cancelled");
    });
  },
);
