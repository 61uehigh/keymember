import { Firestore } from "@google-cloud/firestore";
import { afterAll, beforeEach, describe, expect, it } from "vitest";

import {
  DirectDocuments,
  runDocumentTransaction,
} from "../src/firestore/FirestoreDocuments.js";
import { FirestoreAuditRepository } from "../src/firestore/FirestoreAuditRepository.js";
import { FirestoreInviteRepository } from "../src/firestore/FirestoreInviteRepository.js";
import { FirestoreLoginChallengeRepository } from "../src/firestore/FirestoreLoginChallengeRepository.js";
import { FirestoreOrganizationRepository } from "../src/firestore/FirestoreOrganizationRepository.js";
import { FirestoreRecoveryRepository } from "../src/firestore/FirestoreRecoveryRepository.js";
import { FirestoreUserRepository } from "../src/firestore/FirestoreUserRepository.js";
import { DuplicateKeyError } from "../src/repositories/DuplicateKeyError.js";

const emulator = process.env.FIRESTORE_EMULATOR_HOST;
const projectId = "demo-keymember";

describe.skipIf(emulator === undefined)("Firestore documents", () => {
  const db = new Firestore({ projectId });

  beforeEach(async () => {
    await fetch(
      `http://${emulator ?? ""}/emulator/v1/projects/${projectId}/databases/(default)/documents`,
      { method: "DELETE" },
    );
  });

  afterAll(async () => {
    await db.terminate();
  });

  it("lets a transaction read after it writes, seeing its own writes", async () => {
    const seen = await runDocumentTransaction(db, async (docs) => {
      await docs.set("things", "a", { kind: "x", at: new Date(1000) });
      await docs.set("things", "b", { kind: "y", at: new Date(2000) });
      await docs.update("things", "b", { kind: "x" });
      await docs.update("things", "missing", { kind: "x" });

      return {
        a: await docs.get("things", "a"),
        found: (await docs.find("things", [["kind", "x"]]))
          .map((doc) => doc.id)
          .sort(),
        missing: await docs.get("things", "missing"),
      };
    });

    expect(seen.a).toEqual({ kind: "x", at: new Date(1000) });
    expect(seen.found).toEqual(["a", "b"]);
    expect(seen.missing).toBeUndefined();

    const stored = new DirectDocuments(db);

    expect(await stored.get("things", "b")).toEqual({
      kind: "x",
      at: new Date(2000),
    });
  });

  it("finds documents above a number, including the transaction's own writes", async () => {
    const direct = new DirectDocuments(db);

    await direct.set("things", "old", { revision: 1 });
    await direct.set("things", "new", { revision: 5 });
    await direct.set("things", "moved", { revision: 6 });

    const found = await runDocumentTransaction(db, async (docs) => {
      await docs.set("things", "added", { revision: 7 });
      await docs.set("things", "moved", { revision: 2 });

      return docs.findAbove("things", "revision", 4);
    });

    expect(found.map((doc) => doc.id).sort()).toEqual(["added", "new"]);
    expect(
      (await direct.findAbove("things", "revision", 0))
        .map((doc) => doc.id)
        .sort(),
    ).toEqual(["added", "moved", "new", "old"]);
  });

  it("hides deleted documents from later reads in the same transaction", async () => {
    const direct = new DirectDocuments(db);

    await direct.set("things", "a", { kind: "x" });

    const found = await runDocumentTransaction(db, async (docs) => {
      await docs.delete("things", "a");

      return docs.find("things", [["kind", "x"]]);
    });

    expect(found).toEqual([]);
    expect(await direct.get("things", "a")).toBeUndefined();
  });

  it("writes nothing when the transaction throws", async () => {
    await expect(
      runDocumentTransaction(db, async (docs) => {
        await docs.set("things", "a", { kind: "x" });
        throw new Error("abort");
      }),
    ).rejects.toThrow("abort");

    expect(await new DirectDocuments(db).get("things", "a")).toBeUndefined();
  });

  it("round-trips dates and bytes", async () => {
    const direct = new DirectDocuments(db);
    const bytes = new Uint8Array([0, 1, 254, 255]);

    await direct.set("things", "a", {
      at: new Date("2026-10-24T10:00:00.123Z"),
      bytes,
      list: [bytes, "s", 1, null],
    });

    const stored = await direct.get("things", "a");

    expect(stored).toEqual({
      at: new Date("2026-10-24T10:00:00.123Z"),
      bytes,
      list: [bytes, "s", 1, null],
    });
    expect(Object.getPrototypeOf(stored?.bytes)).toBe(Uint8Array.prototype);
  });

  it("creates only one organisation when two bootstraps race", async () => {
    // Neither transaction writes until both have read, so they really overlap
    let arrived = 0;
    let release = (): void => undefined;
    const barrier = new Promise<void>((resolve) => {
      release = resolve;
    });
    const bootstrap = (orgId: string): Promise<string> =>
      runDocumentTransaction(db, async (docs) => {
        const organizations = new FirestoreOrganizationRepository(docs);

        if (await organizations.lockForBootstrap()) {
          return "exists";
        }

        arrived += 1;

        if (arrived === 2) {
          release();
        }

        await barrier;
        await organizations.insert(orgId, orgId);

        return "created";
      });

    const results = await Promise.all([bootstrap("one"), bootstrap("two")]);

    expect(arrived).toBeGreaterThanOrEqual(2);
    expect(results.sort()).toEqual(["created", "exists"]);
    expect(
      await new DirectDocuments(db).find("organizations", []),
    ).toHaveLength(1);
  });

  it("keeps organisation profiles and recovery key copies", async () => {
    const organizations = new FirestoreOrganizationRepository(
      new DirectDocuments(db),
    );

    expect(await organizations.isBootstrapped()).toBe(false);
    await organizations.insert("org", "Acme");
    expect(await organizations.isBootstrapped()).toBe(true);
    expect(await organizations.hasRecoveryKey("org")).toBe(false);

    await organizations.updatePolicies("org", { requireTotp: true });
    await organizations.setRecoveryKey("org", {
      publicKey: new Uint8Array([1]),
      signature: new Uint8Array([2]),
      signerId: "admin",
    });
    await organizations.putRecoveryKeyCopy("org", "admin", new Uint8Array([3]));

    expect(await organizations.profile("org")).toEqual({
      id: "org",
      name: "Acme",
      requireTotp: true,
      requireSso: false,
      recoveryKey: {
        publicKey: new Uint8Array([1]),
        signature: new Uint8Array([2]),
        signerId: "admin",
      },
    });
    expect(await organizations.recoveryKeyCopy("org", "admin")).toEqual(
      new Uint8Array([3]),
    );

    await organizations.removeRecoveryKeyCopies("admin");
    expect(await organizations.recoveryKeyCopy("org", "admin")).toBeUndefined();
    expect(await organizations.profile("missing")).toBeUndefined();
  });

  it("accepts an invite once, until it expires", async () => {
    const invites = new FirestoreInviteRepository(new DirectDocuments(db));
    const now = new Date("2026-10-24T10:00:00Z");
    const later = new Date("2026-10-25T10:00:00Z");
    const invite = (tokenHash: Uint8Array) => ({
      tokenHash,
      orgId: "org",
      email: "bob@example.com",
      role: "member" as const,
      createdBy: "admin",
      expiresAt: later,
      statement: { email: "bob@example.com" },
      signature: new Uint8Array([9]),
    });

    await invites.insert(invite(new Uint8Array([1])));
    await invites.insert(invite(new Uint8Array([2])));

    expect(await invites.lockValid(new Uint8Array([1]), now)).toEqual({
      orgId: "org",
      email: "bob@example.com",
      role: "member",
    });
    expect(await invites.lockValid(new Uint8Array([1]), later)).toBeUndefined();

    await invites.markUsed(new Uint8Array([1]), now);
    expect(await invites.lockValid(new Uint8Array([1]), now)).toBeUndefined();

    await invites.expireAllBy("admin", now);
    expect(await invites.lockValid(new Uint8Array([2]), now)).toBeUndefined();
  });

  it("creates a document only when its id is free, inside a transaction or not", async () => {
    const direct = new DirectDocuments(db);

    expect(await direct.create("things", "a", { n: 1 })).toBe(true);
    expect(await direct.create("things", "a", { n: 2 })).toBe(false);
    expect(
      await runDocumentTransaction(db, (docs) =>
        docs.create("things", "a", { n: 3 }),
      ),
    ).toBe(false);
    expect(await direct.get("things", "a")).toEqual({ n: 1 });
  });

  it("reads expired documents a page at a time and the latest in order", async () => {
    const direct = new DirectDocuments(db);

    for (const n of [5, 1, 4, 2, 3]) {
      await direct.set("things", `t${String(n)}`, { at: new Date(n * 1000) });
    }

    expect(
      (await direct.findBefore("things", "at", new Date(4000), 2)).map(
        (doc) => doc.id,
      ),
    ).toEqual(["t1", "t2"]);
    expect(
      (await direct.findLatest("things", "at", 2)).map((doc) => doc.id),
    ).toEqual(["t5", "t4"]);
  });

  it("lets a login challenge be used once even by two requests at the same moment", async () => {
    const challenges = new FirestoreLoginChallengeRepository(
      new DirectDocuments(db),
    );
    const now = new Date("2026-10-26T10:00:00Z");

    await challenges.issue(
      {
        id: "c1",
        email: "a@example.com",
        challenge: new Uint8Array([1]),
        expiresAt: new Date(now.getTime() + 60_000),
      },
      now,
    );

    const results = await Promise.all([
      challenges.consume("c1", "a@example.com", now),
      challenges.consume("c1", "a@example.com", now),
    ]);

    expect(results.filter((result) => result !== undefined)).toHaveLength(1);
  });

  it("refuses a second record with a taken id, email, or open recovery", async () => {
    const docs = new DirectDocuments(db);
    const organizations = new FirestoreOrganizationRepository(docs);
    const recoveries = new FirestoreRecoveryRepository(docs);
    const snapshot = { vaults: [], groups: [] };
    const recovery = (id: string, userId: string) => ({
      id,
      orgId: "org",
      userId,
      requestedBy: "admin",
      requestSignature: new Uint8Array(64),
      snapshot,
    });
    const at = new Date();

    await organizations.insert("org", "Acme");
    await expect(organizations.insert("org2", "Other")).rejects.toThrow(
      DuplicateKeyError,
    );

    await recoveries.insert(recovery("r1", "u1"), at);
    // The same id for another member would have overwritten r1
    await expect(recoveries.insert(recovery("r1", "u2"), at)).rejects.toThrow(
      DuplicateKeyError,
    );
    await expect(recoveries.insert(recovery("r2", "u1"), at)).rejects.toThrow(
      DuplicateKeyError,
    );

    // Once closed, the member may have a new recovery
    expect(await recoveries.cancel("r1", at)).toBe(true);
    await recoveries.insert(recovery("r3", "u1"), at);
  });

  it("reads documents written before a field existed as having it empty", async () => {
    const docs = new DirectDocuments(db);

    // A user document from before trusted roots were stored
    await docs.set("users", "u1", { id: "u1", email: "a@example.com" });

    expect(
      await new FirestoreUserRepository(docs).trustedRoots("u1"),
    ).toBeUndefined();
  });

  it("returns the newest audit events first, limited", async () => {
    const audit = new FirestoreAuditRepository(new DirectDocuments(db));

    for (const action of ["first", "second", "third"] as const) {
      await audit.record({
        orgId: "org",
        actorId: undefined,
        action: action === "first" ? "user.signed_up" : "auth.login",
        ip: "127.0.0.1",
        detail: { action },
      });
      await new Promise((resolve) => setTimeout(resolve, 2));
    }

    const latest = await audit.latest("org", 2);

    expect(latest.map((event) => event.detail.action)).toEqual([
      "third",
      "second",
    ]);
  });
});
