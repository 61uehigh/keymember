import type {
  AccessSnapshot,
  RecoveryRecord,
  RecoveryRepository,
  RecoveryStatus,
} from "../repositories/RecoveryRepository.js";
import { COLLECTIONS } from "./collections.js";
import type { DocumentData, Documents, StoredDocument } from "./Documents.js";
import {
  CorruptDocumentError,
  date,
  optionalBytes,
  optionalText,
  text,
} from "./fields.js";
import { insertNew } from "./insertNew.js";
import { claimUnique, releaseUnique } from "./uniqueKeys.js";

const RECOVERIES = COLLECTIONS.recoveries;
const USERS = COLLECTIONS.users;
const ORGANIZATIONS = COLLECTIONS.organizations;

/**
 * ### OPEN
 *
 * Statuses of a recovery that has not finished.
 */
const OPEN: ReadonlySet<RecoveryStatus> = new Set([
  "pending",
  "approved",
  "rekeyed",
]);

/**
 * ### FirestoreRecoveryRepository
 *
 * {@link RecoveryRepository} on Firestore. Recoveries are keyed by id; the member's email is
 * joined from their user document in memory.
 */
export class FirestoreRecoveryRepository implements RecoveryRepository {
  readonly #docs: Documents;

  /**
   * ### constructor
   *
   * @param docs Documents to work in, inside a transaction or not
   */
  constructor(docs: Documents) {
    this.#docs = docs;
  }

  /**
   * ### cancelOpen
   *
   * @see {@link RecoveryRepository.cancelOpen}
   */
  async cancelOpen(userId: string, at: Date): Promise<Array<string>> {
    const cancelled = (
      await this.#docs.find(RECOVERIES, [["userId", userId]])
    ).filter(
      (recovery) =>
        recovery.data.status === "pending" ||
        recovery.data.status === "approved",
    );

    for (const recovery of cancelled) {
      await this.#cancel(recovery.id, at);
    }

    return cancelled.map((recovery) => recovery.id);
  }

  /**
   * ### cancelInvolving
   *
   * @see {@link RecoveryRepository.cancelInvolving}
   */
  async cancelInvolving(userId: string, at: Date): Promise<void> {
    const involving = new Map<string, StoredDocument>();

    for (const field of ["userId", "requestedBy"]) {
      for (const recovery of await this.#docs.find(RECOVERIES, [
        [field, userId],
      ])) {
        involving.set(recovery.id, recovery);
      }
    }

    for (const recovery of involving.values()) {
      if (OPEN.has(status(recovery.data))) {
        await this.#cancel(recovery.id, at);
      }
    }
  }

  /**
   * ### find
   *
   * @see {@link RecoveryRepository.find}
   */
  async find(
    orgId: string,
    recoveryId: string,
  ): Promise<RecoveryRecord | undefined> {
    const recovery = await this.#docs.get(RECOVERIES, recoveryId);

    return recovery?.orgId !== orgId
      ? undefined
      : this.#toRecord(recoveryId, recovery);
  }

  /**
   * ### list
   *
   * @see {@link RecoveryRepository.list}
   */
  async list(orgId: string): Promise<Array<RecoveryRecord>> {
    const recoveries = (await this.#docs.find(RECOVERIES, [["orgId", orgId]]))
      .sort(
        (left, right) =>
          date(right.data, "createdAt").getTime() -
          date(left.data, "createdAt").getTime(),
      )
      .slice(0, 100);
    const records: Array<RecoveryRecord> = [];

    for (const recovery of recoveries) {
      const record = await this.#toRecord(recovery.id, recovery.data);

      if (record !== undefined) {
        records.push(record);
      }
    }

    return records;
  }

  /**
   * ### hasOpen
   *
   * @see {@link RecoveryRepository.hasOpen}
   */
  async hasOpen(userId: string): Promise<boolean> {
    return (await this.#docs.find(RECOVERIES, [["userId", userId]])).some(
      (recovery) => OPEN.has(status(recovery.data)),
    );
  }

  /**
   * ### insert
   *
   * @see {@link RecoveryRepository.insert}
   */
  async insert(
    recovery: {
      id: string;
      orgId: string;
      userId: string;
      requestedBy: string;
      requestSignature: Uint8Array;
      snapshot: AccessSnapshot;
    },
    at: Date,
  ): Promise<void> {
    // At most one open recovery per member, as SQL's partial unique index keeps it
    await this.#docs.atomic(async (docs) => {
      await claimUnique(docs, "openRecovery", recovery.userId, recovery.id);
      await insertNew(docs, RECOVERIES, recovery.id, {
        id: recovery.id,
        orgId: recovery.orgId,
        userId: recovery.userId,
        requestedBy: recovery.requestedBy,
        approvedBy: null,
        status: "pending",
        tokenHash: null,
        tokenExpiresAt: null,
        vaultSnapshot: JSON.stringify(recovery.snapshot.vaults),
        groupSnapshot: JSON.stringify(recovery.snapshot.groups),
        requestSignature: recovery.requestSignature,
        createdAt: at,
        updatedAt: at,
      });
    });
  }

  /**
   * ### approve
   *
   * @see {@link RecoveryRepository.approve}
   */
  async approve(
    recoveryId: string,
    approvedBy: string,
    token: { hash: Uint8Array; expiresAt: Date },
    at: Date,
  ): Promise<boolean> {
    return this.#transition(recoveryId, ["pending"], {
      status: "approved",
      approvedBy,
      tokenHash: token.hash,
      tokenExpiresAt: token.expiresAt,
      updatedAt: at,
    });
  }

  /**
   * ### replaceSnapshot
   *
   * @see {@link RecoveryRepository.replaceSnapshot}
   */
  async replaceSnapshot(
    recoveryId: string,
    snapshot: AccessSnapshot,
  ): Promise<void> {
    await this.#docs.update(RECOVERIES, recoveryId, {
      vaultSnapshot: JSON.stringify(snapshot.vaults),
      groupSnapshot: JSON.stringify(snapshot.groups),
    });
  }

  /**
   * ### cancel
   *
   * @see {@link RecoveryRepository.cancel}
   */
  async cancel(recoveryId: string, at: Date): Promise<boolean> {
    return this.#transition(recoveryId, [...OPEN], {
      status: "cancelled",
      tokenHash: null,
      updatedAt: at,
    });
  }

  /**
   * ### approvedByToken
   *
   * @see {@link RecoveryRepository.approvedByToken}
   */
  async approvedByToken(
    tokenHash: Uint8Array,
    now: Date,
  ): Promise<
    (RecoveryRecord & { keysetVersion: number; orgName: string }) | undefined
  > {
    const recovery = (
      await this.#docs.find(RECOVERIES, [
        ["tokenHash", tokenHash],
        ["status", "approved"],
      ])
    ).find((candidate) => date(candidate.data, "tokenExpiresAt") > now);

    if (recovery === undefined) {
      return undefined;
    }

    const record = await this.#toRecord(recovery.id, recovery.data);
    const user = await this.#docs.get(USERS, text(recovery.data, "userId"));
    const org = await this.#docs.get(
      ORGANIZATIONS,
      text(recovery.data, "orgId"),
    );

    if (record === undefined || user === undefined || org === undefined) {
      return undefined;
    }

    const keysetVersion = user.keysetVersion;

    if (typeof keysetVersion !== "number") {
      throw new CorruptDocumentError("keysetVersion", "a number");
    }

    return { ...record, keysetVersion, orgName: text(org, "name") };
  }

  /**
   * ### markRekeyed
   *
   * @see {@link RecoveryRepository.markRekeyed}
   */
  async markRekeyed(recoveryId: string, at: Date): Promise<boolean> {
    return this.#transition(recoveryId, ["approved"], {
      status: "rekeyed",
      tokenHash: null,
      updatedAt: at,
    });
  }

  /**
   * ### complete
   *
   * @see {@link RecoveryRepository.complete}
   */
  async complete(recoveryId: string, at: Date): Promise<boolean> {
    return this.#transition(recoveryId, ["rekeyed"], {
      status: "completed",
      updatedAt: at,
    });
  }

  /**
   * ### #cancel
   *
   * Cancels a recovery without checking its status.
   *
   * @param recoveryId Recovery
   * @param at Time of cancellation
   */
  async #cancel(recoveryId: string, at: Date): Promise<void> {
    await this.#docs.atomic(async (docs) => {
      const recovery = await docs.get(RECOVERIES, recoveryId);

      if (recovery === undefined) {
        return;
      }

      await docs.update(RECOVERIES, recoveryId, {
        status: "cancelled",
        tokenHash: null,
        updatedAt: at,
      });
      await releaseUnique(
        docs,
        "openRecovery",
        text(recovery, "userId"),
        recoveryId,
      );
    });
  }

  /**
   * ### #transition
   *
   * Changes a recovery when it is in one of the given statuses.
   *
   * @param recoveryId Recovery
   * @param from Statuses it may be in
   * @param patch Fields to change
   * @returns Whether it was in one of them and changed
   */
  async #transition(
    recoveryId: string,
    from: ReadonlyArray<RecoveryStatus>,
    patch: DocumentData,
  ): Promise<boolean> {
    // One transaction, so two requests cannot both move it out of the same status
    return this.#docs.atomic(async (docs) => {
      const recovery = await docs.get(RECOVERIES, recoveryId);

      if (recovery === undefined || !from.includes(status(recovery))) {
        return false;
      }

      await docs.update(RECOVERIES, recoveryId, patch);

      // A closed recovery no longer holds the member's one open slot
      if (!OPEN.has(status({ ...recovery, ...patch }))) {
        await releaseUnique(
          docs,
          "openRecovery",
          text(recovery, "userId"),
          recoveryId,
        );
      }

      return true;
    });
  }

  /**
   * ### #toRecord
   *
   * Maps a recovery document to a {@link RecoveryRecord}, joining the member's email.
   *
   * @param id Recovery id
   * @param recovery Recovery fields
   * @returns The record, or `undefined` when the member's user document is missing
   */
  async #toRecord(
    id: string,
    recovery: DocumentData,
  ): Promise<RecoveryRecord | undefined> {
    const userId = text(recovery, "userId");
    const user = await this.#docs.get(USERS, userId);

    if (user === undefined) {
      return undefined;
    }

    return {
      id,
      orgId: text(recovery, "orgId"),
      userId,
      email: text(user, "email"),
      requestedBy: text(recovery, "requestedBy"),
      approvedBy: optionalText(recovery, "approvedBy"),
      status: status(recovery),
      snapshot: {
        // Only this repository writes these fields, from an AccessSnapshot
        vaults: JSON.parse(
          text(recovery, "vaultSnapshot"),
        ) as AccessSnapshot["vaults"],
        groups: JSON.parse(
          text(recovery, "groupSnapshot"),
        ) as AccessSnapshot["groups"],
      },
      requestSignature: optionalBytes(recovery, "requestSignature"),
      createdAt: date(recovery, "createdAt"),
    };
  }
}

/**
 * ### status
 *
 * Reads a recovery's status.
 *
 * @param data Recovery fields
 * @returns The status
 */
function status(data: DocumentData): RecoveryStatus {
  // Only this repository writes the field, always with a RecoveryStatus
  return text(data, "status") as RecoveryStatus;
}
