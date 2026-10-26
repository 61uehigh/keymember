import { Firestore } from "@google-cloud/firestore";
import { afterAll, beforeEach, describe, expect, it } from "vitest";

import type { Documents } from "../src/firestore/Documents.js";
import {
  DirectDocuments,
  runDocumentTransaction,
} from "../src/firestore/FirestoreDocuments.js";
import { FirestoreShareRepository } from "../src/firestore/FirestoreShareRepository.js";
import { FirestoreSsoRepository } from "../src/firestore/FirestoreSsoRepository.js";
import type { NewShareLink } from "../src/repositories/ShareRepository.js";

const emulator = process.env.FIRESTORE_EMULATOR_HOST;
const projectId = "demo-keymember-shares-sso";

describe.skipIf(emulator === undefined)("Firestore shares and SSO", () => {
  const db = new Firestore({ projectId });
  let docs: Documents;

  beforeEach(async () => {
    await fetch(
      `http://${emulator ?? ""}/emulator/v1/projects/${projectId}/databases/(default)/documents`,
      { method: "DELETE" },
    );
    docs = new DirectDocuments(db);
  });

  afterAll(async () => {
    await db.terminate();
  });

  const now = new Date("2026-10-24T10:00:00Z");
  const hourLater = new Date("2026-10-24T11:00:00Z");
  const share = (
    id: string,
    overrides: Partial<NewShareLink> = {},
  ): NewShareLink => ({
    id,
    orgId: "org",
    vaultId: "vault",
    itemId: "item",
    createdBy: "alice",
    ciphertext: new Uint8Array([1, 2, 3]),
    accessHash: new Uint8Array([4, 5]),
    passphrase: false,
    expiresAt: hourLater,
    maxViews: 2,
    ...overrides,
  });

  describe("shares", () => {
    it("stores a link and reads it back", async () => {
      const shares = new FirestoreShareRepository(docs);

      expect(await shares.exists("s1")).toBe(false);
      await shares.insert(share("s1", { passphrase: true }), now);
      expect(await shares.exists("s1")).toBe(true);

      const stored = await shares.lock("s1");

      expect(stored).toMatchObject({
        id: "s1",
        orgId: "org",
        vaultId: "vault",
        itemId: "item",
        createdBy: "alice",
        ciphertext: new Uint8Array([1, 2, 3]),
        accessHash: new Uint8Array([4, 5]),
        passphrase: true,
        expiresAt: hourLater,
        maxViews: 2,
        views: 0,
        failedAttempts: 0,
        revokedAt: undefined,
        lastOpenedAt: undefined,
      });
      expect(stored?.createdAt).toBeInstanceOf(Date);
      expect(await shares.lock("s1", "other-org")).toBeUndefined();
      expect(await shares.lock("s1", "org")).toBeDefined();
      expect(await shares.lock("missing")).toBeUndefined();
    });

    it("drops the ciphertext of expired links when another is created", async () => {
      const shares = new FirestoreShareRepository(docs);

      await shares.insert(share("old", { expiresAt: now }), now);
      await shares.insert(share("new"), hourLater);

      expect((await shares.lock("old"))?.ciphertext).toBeUndefined();
      expect((await shares.lock("new"))?.ciphertext).toBeDefined();
    });

    it("lists an organisation's links newest first, filtered", async () => {
      const shares = new FirestoreShareRepository(docs);

      await shares.insert(share("a"), now);
      await shares.insert(share("b", { createdBy: "bob" }), now);
      await shares.insert(share("c", { itemId: "other" }), now);
      await shares.insert(share("d", { orgId: "elsewhere" }), now);

      expect((await shares.list({ orgId: "org" })).map((s) => s.id)).toEqual([
        "c",
        "b",
        "a",
      ]);
      expect(
        (await shares.list({ orgId: "org", createdBy: "bob" })).map(
          (s) => s.id,
        ),
      ).toEqual(["b"]);
      expect(
        (await shares.list({ orgId: "org", itemId: "item" })).map((s) => s.id),
      ).toEqual(["b", "a"]);
    });

    it("keeps the first revocation time and drops the ciphertext", async () => {
      const shares = new FirestoreShareRepository(docs);

      await shares.insert(share("s1"), now);
      await shares.revoke("s1", now);
      await shares.revoke("s1", hourLater);
      await shares.revoke("missing", now);

      expect(await shares.lock("s1")).toMatchObject({
        revokedAt: now,
        ciphertext: undefined,
      });
    });

    it("revokes every open link of a member", async () => {
      const shares = new FirestoreShareRepository(docs);

      await shares.insert(share("open"), now);
      await shares.insert(share("revoked"), now);
      await shares.insert(share("other", { createdBy: "bob" }), now);
      await shares.revoke("revoked", now);

      expect(await shares.revokeAllBy("alice", hourLater)).toBe(1);
      expect(await shares.lock("open")).toMatchObject({
        revokedAt: hourLater,
        ciphertext: undefined,
      });
      expect((await shares.lock("revoked"))?.revokedAt).toEqual(now);
      expect((await shares.lock("other"))?.revokedAt).toBeUndefined();
    });

    it("closes a link after too many wrong passphrases", async () => {
      const shares = new FirestoreShareRepository(docs);

      await shares.insert(share("s1"), now);
      await shares.recordFailedAttempt("s1", 1, 3, now);
      expect(await shares.lock("s1")).toMatchObject({
        failedAttempts: 1,
        revokedAt: undefined,
      });

      await shares.recordFailedAttempt("s1", 3, 3, hourLater);
      expect(await shares.lock("s1")).toMatchObject({
        failedAttempts: 3,
        revokedAt: hourLater,
        ciphertext: undefined,
      });
    });

    it("drops the ciphertext when the last view is used", async () => {
      const shares = new FirestoreShareRepository(docs);

      await shares.insert(share("s1"), now);
      await shares.recordView("s1", 1, now);
      expect(await shares.lock("s1")).toMatchObject({
        views: 1,
        lastOpenedAt: now,
        ciphertext: new Uint8Array([1, 2, 3]),
      });

      await shares.recordView("s1", 2, hourLater);
      expect(await shares.lock("s1")).toMatchObject({
        views: 2,
        lastOpenedAt: hourLater,
        ciphertext: undefined,
      });
    });
  });

  describe("sso", () => {
    const ticket = (id: string, expiresAt = hourLater) => ({
      id,
      secretHash: new Uint8Array([7]),
      kind: "login" as const,
      userId: "alice",
      familyId: undefined,
      deviceId: "device",
      deviceName: "Laptop",
      state: `state-${id}`,
      nonce: "nonce",
      codeVerifier: "verifier",
      expiresAt,
    });

    const addUser = async (id: string, ssoSubject: string | null = null) => {
      await docs.set("users", id, {
        id,
        email: `${id}@example.com`,
        ssoSubject,
      });
      await docs.set("memberships", `org:${id}`, { orgId: "org", userId: id });
    };

    it("stores a pending ticket and finds it by id or state", async () => {
      const sso = new FirestoreSsoRepository(docs);

      await addUser("alice", "sub-a");
      await sso.insertTicket(ticket("t1"), now);

      expect(await sso.ticket("t1")).toMatchObject({
        id: "t1",
        kind: "login",
        userId: "alice",
        familyId: undefined,
        deviceId: "device",
        deviceName: "Laptop",
        state: "state-t1",
        status: "pending",
        failure: undefined,
        subject: undefined,
        encryptedRefreshToken: undefined,
        expiresAt: hourLater,
      });

      const expected = {
        id: "t1",
        email: "alice@example.com",
        boundSubject: "sub-a",
        orgId: "org",
      };

      expect(await sso.pendingTicket({ id: "t1" }, now)).toMatchObject(
        expected,
      );
      expect(await sso.pendingTicket({ state: "state-t1" }, now)).toMatchObject(
        expected,
      );
      expect(await sso.pendingTicket({ id: "t1" }, hourLater)).toBeUndefined();
      expect(await sso.ticket("missing")).toBeUndefined();
    });

    it("does not find a ticket whose user has no membership", async () => {
      const sso = new FirestoreSsoRepository(docs);

      await docs.set("users", "alice", {
        id: "alice",
        email: "alice@example.com",
        ssoSubject: null,
      });
      await sso.insertTicket(ticket("t1"), now);

      expect(await sso.pendingTicket({ id: "t1" }, now)).toBeUndefined();
    });

    it("drops tickets that expired a day ago when adding one", async () => {
      const sso = new FirestoreSsoRepository(docs);
      const twoDaysLater = new Date(now.getTime() + 2 * 24 * 60 * 60 * 1000);

      await sso.insertTicket(ticket("old", now), now);
      await sso.insertTicket(
        ticket("recent", new Date(now.getTime() + 36 * 60 * 60 * 1000)),
        now,
      );
      await sso.insertTicket(ticket("t3"), twoDaysLater);

      expect(await sso.ticket("old")).toBeUndefined();
      expect(await sso.ticket("recent")).toBeDefined();
    });

    it("moves tickets through verified and used, or failed", async () => {
      const sso = new FirestoreSsoRepository(docs);

      await addUser("alice");
      await sso.insertTicket(ticket("ok"), now);
      await sso.insertTicket(ticket("bad"), now);

      expect(await sso.claimTicket("ok")).toBe(false);
      await sso.verifyTicket("ok", "sub-a", new Uint8Array([9]));
      await sso.failTicket("ok", "too late");
      expect(await sso.ticket("ok")).toMatchObject({
        status: "verified",
        subject: "sub-a",
        encryptedRefreshToken: new Uint8Array([9]),
        failure: undefined,
      });
      expect(await sso.pendingTicket({ id: "ok" }, now)).toBeUndefined();

      expect(
        await runDocumentTransaction(db, (tx) =>
          new FirestoreSsoRepository(tx).claimTicket("ok"),
        ),
      ).toBe(true);
      expect(await sso.claimTicket("ok")).toBe(false);
      expect((await sso.ticket("ok"))?.status).toBe("used");

      await sso.failTicket("bad", "wrong account");
      await sso.verifyTicket("bad", "sub-a", new Uint8Array([9]));
      expect(await sso.ticket("bad")).toMatchObject({
        status: "failed",
        failure: "wrong account",
        subject: undefined,
      });
    });

    it("keeps, re-checks and removes provider links", async () => {
      const sso = new FirestoreSsoRepository(docs);
      const link = {
        subject: "sub-a",
        encryptedRefreshToken: new Uint8Array([1]),
        checkedAt: now,
      };

      expect(await sso.link("family")).toBeUndefined();
      await sso.putLink("family", "alice", link);
      expect(await sso.link("family")).toEqual(link);

      await sso.recordCheck("family", hourLater, undefined);
      expect(await sso.link("family")).toEqual({
        ...link,
        checkedAt: hourLater,
      });

      await sso.recordCheck("family", now, new Uint8Array([2]));
      expect(await sso.link("family")).toEqual({
        subject: "sub-a",
        encryptedRefreshToken: new Uint8Array([2]),
        checkedAt: now,
      });

      await sso.putLink("family", "bob", { ...link, subject: "sub-b" });
      expect((await sso.link("family"))?.subject).toBe("sub-b");
      expect((await docs.get("ssoSessions", "family"))?.userId).toBe("alice");

      expect(await sso.removeLink("family")).toMatchObject({
        subject: "sub-b",
      });
      expect(await sso.removeLink("family")).toBeUndefined();
      await sso.recordCheck("family", now, undefined);
      expect(await sso.link("family")).toBeUndefined();
    });

    it("binds a provider account to one user only", async () => {
      const sso = new FirestoreSsoRepository(docs);

      await addUser("alice");
      await addUser("bob");

      expect(await sso.subjectTakenByOther("sub-a", "alice")).toBe(false);
      expect(await sso.bindSubject("alice", "sub-a")).toBe("sub-a");
      expect(await sso.subjectTakenByOther("sub-a", "alice")).toBe(false);
      expect(await sso.subjectTakenByOther("sub-a", "bob")).toBe(true);

      // Bound already: keeps the first account
      expect(await sso.bindSubject("alice", "sub-other")).toBe("sub-a");
      // Someone else holds it
      expect(await sso.bindSubject("bob", "sub-a")).toBeUndefined();
      expect(await sso.bindSubject("nobody", "sub-z")).toBeUndefined();
      expect((await docs.get("users", "bob"))?.ssoSubject).toBeNull();
    });
  });
});
