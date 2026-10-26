import { Firestore } from "@google-cloud/firestore";
import type { KdfParams } from "@keymember/core";
import { afterAll, beforeEach, describe, expect, it } from "vitest";

import type { Documents } from "../src/firestore/Documents.js";
import { FirestoreAuditRepository } from "../src/firestore/FirestoreAuditRepository.js";
import {
  DirectDocuments,
  runDocumentTransaction,
} from "../src/firestore/FirestoreDocuments.js";
import { FirestoreLoginChallengeRepository } from "../src/firestore/FirestoreLoginChallengeRepository.js";
import { FirestoreSessionRepository } from "../src/firestore/FirestoreSessionRepository.js";
import { FirestoreUserRepository } from "../src/firestore/FirestoreUserRepository.js";
import type { NewUser } from "../src/repositories/UserRepository.js";

const emulator = process.env.FIRESTORE_EMULATOR_HOST;
const projectId = "demo-keymember-auth";

const kdf: KdfParams = {
  algorithm: "argon2id",
  memoryKiB: 65536,
  iterations: 3,
  parallelism: 1,
};

/**
 * ### newUser
 *
 * A user as sign-up would create it, with distinct bytes per field.
 */
function newUser(id: string, email: string, accountId: string): NewUser {
  return {
    id,
    email,
    name: `Name ${id}`,
    accountId,
    salt: new Uint8Array([1]),
    kdf,
    loginPublicKey: new Uint8Array([2]),
    keyset: {
      encryptedAccountKey: new Uint8Array([3]),
      encryptedPrivateKeys: new Uint8Array([4]),
      encryptionPublicKey: new Uint8Array([5]),
      signingPublicKey: new Uint8Array([6]),
      keysetVersion: 1,
      selfSignature: new Uint8Array([7]),
    },
  };
}

/**
 * ### addMember
 *
 * Stores an organisation and a membership the way their repositories lay them out.
 */
async function addMember(
  docs: Documents,
  orgId: string,
  userId: string,
  policies: { requireTotp: boolean; requireSso: boolean } = {
    requireTotp: false,
    requireSso: false,
  },
): Promise<void> {
  await docs.set("organizations", orgId, {
    id: orgId,
    name: "Acme",
    createdAt: new Date(),
    requireTotp: policies.requireTotp,
    requireSso: policies.requireSso,
    recoveryPublicKey: null,
    recoveryKeySignature: null,
    recoveryKeySigner: null,
  });
  await docs.set("memberships", `${orgId}:${userId}`, {
    orgId,
    userId,
    role: "admin",
    status: "confirmed",
    certificate: null,
    certificateSignature: null,
    confirmedBy: null,
    confirmedAt: null,
  });
}

describe.skipIf(emulator === undefined)("Firestore auth repositories", () => {
  const db = new Firestore({ projectId });
  const docs = new DirectDocuments(db);

  beforeEach(async () => {
    await fetch(
      `http://${emulator ?? ""}/emulator/v1/projects/${projectId}/databases/(default)/documents`,
      { method: "DELETE" },
    );
  });

  afterAll(async () => {
    await db.terminate();
  });

  describe("users", () => {
    const users = new FirestoreUserRepository(docs);

    it("registers users and detects taken ids, emails and account ids", async () => {
      await users.insert(newUser("u1", "a@example.com", "acc1"));

      expect(
        await users.isRegistered({
          id: "u1",
          email: "x@example.com",
          accountId: "x",
        }),
      ).toBe(true);
      expect(
        await users.isRegistered({
          id: "u2",
          email: "a@example.com",
          accountId: "x",
        }),
      ).toBe(true);
      expect(
        await users.isRegistered({
          id: "u2",
          email: "x@example.com",
          accountId: "acc1",
        }),
      ).toBe(true);
      expect(
        await users.isRegistered({
          id: "u2",
          email: "x@example.com",
          accountId: "x",
        }),
      ).toBe(false);
      expect(await users.signingPublicKey("u1")).toEqual(new Uint8Array([6]));
      expect(await users.signingPublicKey("missing")).toBeUndefined();
      expect(await users.accountIdTakenByOther("acc1", "u1")).toBe(false);
      expect(await users.accountIdTakenByOther("acc1", "u2")).toBe(true);
    });

    it("answers prelogin and switches legacy accounts to signed login", async () => {
      await users.insert(newUser("u1", "a@example.com", "acc1"));

      expect(await users.prelogin("a@example.com")).toEqual({
        salt: new Uint8Array([1]),
        kdf,
        legacy: false,
      });
      expect(await users.prelogin("missing@example.com")).toBeUndefined();

      // A legacy account has a verifier and no login key
      await docs.update("users", "u1", {
        authPublicKey: null,
        authVerifier: new Uint8Array([9]),
      });
      expect((await users.prelogin("a@example.com"))?.legacy).toBe(true);
      expect(await users.credentialsForUpdate("u1")).toEqual({
        authVerifier: new Uint8Array([9]),
        authPublicKey: undefined,
      });

      await users.adoptLoginKey("u1", new Uint8Array([8]));
      expect(await users.credentialsForUpdate("u1")).toEqual({
        authVerifier: undefined,
        authPublicKey: new Uint8Array([8]),
      });

      // Only an account without a login key adopts one
      await users.adoptLoginKey("u1", new Uint8Array([10]));
      expect((await users.credentialsForUpdate("u1"))?.authPublicKey).toEqual(
        new Uint8Array([8]),
      );
      expect(await users.credentialsForUpdate("missing")).toBeUndefined();
    });

    it("joins a login account with its membership and organisation", async () => {
      await users.insert(newUser("u1", "a@example.com", "acc1"));

      // No membership yet: the inner join drops the user
      expect(await users.loginAccount({ id: "u1" })).toBeUndefined();

      await addMember(docs, "org", "u1", {
        requireTotp: false,
        requireSso: true,
      });

      const expected = {
        id: "u1",
        email: "a@example.com",
        name: "Name u1",
        authVerifier: undefined,
        authPublicKey: new Uint8Array([2]),
        totpSecret: undefined,
        totpLastStep: undefined,
        ssoSubject: undefined,
        orgId: "org",
        role: "admin",
        status: "confirmed",
        requireSso: true,
        keyset: {
          encryptedAccountKey: new Uint8Array([3]),
          encryptedPrivateKeys: new Uint8Array([4]),
          encryptionPublicKey: new Uint8Array([5]),
          signingPublicKey: new Uint8Array([6]),
          keysetVersion: 1,
          selfSignature: new Uint8Array([7]),
        },
      };

      expect(await users.loginAccount({ id: "u1" })).toEqual(expected);
      expect(await users.loginAccount({ email: "a@example.com" })).toEqual(
        expected,
      );
      expect(
        await users.loginAccount({ email: "missing@example.com" }),
      ).toBeUndefined();
    });

    it("enrols two-factor login and claims each step once", async () => {
      await users.insert(newUser("u1", "a@example.com", "acc1"));

      expect(await users.totpState("u1")).toEqual({
        pendingSecret: undefined,
        secret: undefined,
        lastStep: undefined,
      });

      await users.setPendingTotp("u1", new Uint8Array([11]));
      await users.confirmTotp("u1", 100);
      expect(await users.totpState("u1")).toEqual({
        pendingSecret: undefined,
        secret: new Uint8Array([11]),
        lastStep: 100,
      });

      expect(await users.claimTotpStep("u1", 100)).toBe(false);
      expect(await users.claimTotpStep("u1", 101)).toBe(true);
      expect(await users.claimTotpStep("u1", 101)).toBe(false);
      expect(await users.claimTotpStep("missing", 1)).toBe(false);
      expect(await users.totpState("missing")).toBeUndefined();
    });

    it("lets only one of two racing logins claim the same step", async () => {
      await users.insert(newUser("u1", "a@example.com", "acc1"));

      const claim = (): Promise<boolean> =>
        runDocumentTransaction(db, async (tx) => {
          const claimed = await new FirestoreUserRepository(tx).claimTotpStep(
            "u1",
            5,
          );

          // Both transactions have read before either writes
          await new Promise((resolve) => setTimeout(resolve, 300));

          return claimed;
        });

      expect((await Promise.all([claim(), claim()])).sort()).toEqual([
        false,
        true,
      ]);
    });

    it("changes passwords and rekeys after a recovery", async () => {
      await users.insert(newUser("u1", "a@example.com", "acc1"));
      await users.setPendingTotp("u1", new Uint8Array([11]));
      await users.confirmTotp("u1", 100);

      await users.changePassword("u1", {
        salt: new Uint8Array([20]),
        kdf,
        loginPublicKey: new Uint8Array([21]),
        encryptedAccountKey: new Uint8Array([22]),
      });
      expect(await users.prelogin("a@example.com")).toEqual({
        salt: new Uint8Array([20]),
        kdf,
        legacy: false,
      });

      const rekeyed = newUser("ignored", "ignored", "acc2");

      await users.rekey("u1", {
        ...rekeyed,
        keyset: { ...rekeyed.keyset, keysetVersion: 2 },
      });
      expect(await users.totpState("u1")).toEqual({
        pendingSecret: undefined,
        secret: undefined,
        lastStep: undefined,
      });
      expect(await users.accountIdTakenByOther("acc2", "other")).toBe(true);
      expect(await users.accountIdTakenByOther("acc1", "other")).toBe(false);

      // Updates leave a missing user missing
      await users.changePassword("missing", {
        salt: new Uint8Array([1]),
        kdf,
        loginPublicKey: new Uint8Array([1]),
        encryptedAccountKey: new Uint8Array([1]),
      });
      expect(await docs.get("users", "missing")).toBeUndefined();
    });
  });

  describe("login challenges", () => {
    const challenges = new FirestoreLoginChallengeRepository(docs);
    const now = new Date("2026-10-24T10:00:00Z");
    const later = new Date("2026-10-24T10:05:00Z");

    it("consumes a challenge once, for its email, before it expires", async () => {
      await challenges.issue(
        {
          id: "c1",
          email: "a@example.com",
          challenge: new Uint8Array([1, 2]),
          expiresAt: later,
        },
        now,
      );

      expect(
        await challenges.consume("c1", "b@example.com", now),
      ).toBeUndefined();
      expect(await challenges.consume("c1", "a@example.com", later)).toBe(
        undefined,
      );
      expect(await challenges.consume("c1", "a@example.com", now)).toEqual(
        new Uint8Array([1, 2]),
      );
      expect(
        await challenges.consume("c1", "a@example.com", now),
      ).toBeUndefined();
      expect(
        await challenges.consume("missing", "a@example.com", now),
      ).toBeUndefined();
    });

    it("prunes expired challenges when issuing a new one", async () => {
      await challenges.issue(
        {
          id: "old",
          email: "a@example.com",
          challenge: new Uint8Array([1]),
          expiresAt: now,
        },
        now,
      );
      await challenges.issue(
        {
          id: "new",
          email: "a@example.com",
          challenge: new Uint8Array([2]),
          expiresAt: new Date(later.getTime() + 60_000),
        },
        later,
      );

      expect(await docs.get("loginChallenges", "old")).toBeUndefined();
      expect(await docs.get("loginChallenges", "new")).toBeDefined();
    });
  });

  describe("sessions", () => {
    const sessions = new FirestoreSessionRepository(docs);
    const users = new FirestoreUserRepository(docs);
    const now = new Date("2026-10-24T10:00:00Z");
    const session = (access: number, refresh: number, familyId: string) => ({
      accessHash: new Uint8Array([access]),
      refreshHash: new Uint8Array([refresh]),
      familyId,
      userId: "u1",
      deviceId: "d1",
      deviceName: "Laptop",
      accessExpiresAt: new Date(now.getTime() + 60_000),
      refreshExpiresAt: new Date(now.getTime() + 3_600_000),
    });

    it("authenticates live sessions with their policy gaps", async () => {
      await users.insert(newUser("u1", "a@example.com", "acc1"));
      await addMember(docs, "org", "u1", {
        requireTotp: true,
        requireSso: true,
      });
      await sessions.insert(session(1, 101, "f1"));

      expect(await sessions.authenticate(new Uint8Array([1]), now)).toEqual({
        userId: "u1",
        email: "a@example.com",
        orgId: "org",
        role: "admin",
        status: "confirmed",
        familyId: "f1",
        totpMissing: true,
        ssoMissing: true,
      });

      await docs.set("ssoSessions", "f1", {
        familyId: "f1",
        userId: "u1",
        subject: "sub",
        encRefreshToken: new Uint8Array([1]),
        checkedAt: now,
      });
      await users.setPendingTotp("u1", new Uint8Array([11]));
      await users.confirmTotp("u1", 1);
      expect(
        await sessions.authenticate(new Uint8Array([1]), now),
      ).toMatchObject({ totpMissing: false, ssoMissing: false });

      // Expired or unknown tokens do not authenticate
      expect(
        await sessions.authenticate(
          new Uint8Array([1]),
          new Date(now.getTime() + 60_000),
        ),
      ).toBeUndefined();
      expect(
        await sessions.authenticate(new Uint8Array([2]), now),
      ).toBeUndefined();
    });

    it("rotates refresh tokens and revokes families, users and others", async () => {
      await users.insert(newUser("u1", "a@example.com", "acc1"));
      await addMember(docs, "org", "u1");
      await sessions.insert(session(1, 101, "f1"));
      await sessions.insert(session(2, 102, "f2"));
      await sessions.insert(session(3, 103, "f3"));

      expect(await sessions.refreshTarget(new Uint8Array([101]))).toEqual({
        familyId: "f1",
        userId: "u1",
        orgId: "org",
        requireSso: false,
      });
      expect(await sessions.lockForRefresh(new Uint8Array([101]))).toEqual({
        familyId: "f1",
        userId: "u1",
        orgId: "org",
        deviceId: "d1",
        deviceName: "Laptop",
        refreshExpiresAt: new Date(now.getTime() + 3_600_000),
        spent: false,
      });

      await sessions.markRotated(new Uint8Array([101]), now);
      expect(
        await sessions.refreshTarget(new Uint8Array([101])),
      ).toBeUndefined();
      expect(
        (await sessions.lockForRefresh(new Uint8Array([101])))?.spent,
      ).toBe(true);
      expect(await sessions.isFamilyActive("f1")).toBe(false);
      expect(
        await sessions.lockForRefresh(new Uint8Array([200])),
      ).toBeUndefined();

      await sessions.revokeOthers("u1", "f2", now);
      expect(await sessions.isFamilyActive("f2")).toBe(true);
      expect(await sessions.isFamilyActive("f3")).toBe(false);

      await sessions.revokeFamily("f2", now);
      expect(await sessions.isFamilyActive("f2")).toBe(false);

      await sessions.insert(session(4, 104, "f4"));
      await sessions.revokeAll("u1", now);
      expect(await sessions.isFamilyActive("f4")).toBe(false);
      expect(
        await sessions.authenticate(new Uint8Array([4]), now),
      ).toBeUndefined();
    });
  });

  describe("audit events", () => {
    const audit = new FirestoreAuditRepository(docs);

    it("returns an organisation's newest events first, up to the limit", async () => {
      await audit.record({
        orgId: "org",
        actorId: "u1",
        action: "auth.login",
        ip: "1.2.3.4",
      });
      await runDocumentTransaction(db, async (tx) => {
        const inTx = new FirestoreAuditRepository(tx);

        await inTx.record({
          orgId: "org",
          actorId: undefined,
          action: "item.created",
          targetId: "item",
          detail: { vaultId: "v", count: 2 },
          ip: "1.2.3.4",
        });
        await inTx.record({
          orgId: "other",
          actorId: "u2",
          action: "auth.login",
          ip: "5.6.7.8",
        });
      });
      await audit.record({
        orgId: "org",
        actorId: "u1",
        action: "item.deleted",
        targetId: "item",
        ip: "1.2.3.4",
      });

      const events = await audit.latest("org", 2);

      expect(events.map((event) => event.action)).toEqual([
        "item.deleted",
        "item.created",
      ]);
      expect(events[0]?.id).toBeGreaterThan(events[1]?.id ?? Infinity);
      expect(events[1]).toMatchObject({
        actorId: undefined,
        targetId: "item",
        detail: { vaultId: "v", count: 2 },
        ip: "1.2.3.4",
      });
      expect(events[1]?.at).toBeInstanceOf(Date);
      expect(await audit.latest("org", 10)).toHaveLength(3);
    });
  });
});
