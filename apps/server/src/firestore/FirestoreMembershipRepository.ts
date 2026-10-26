import type { MembershipRole, MembershipStatus } from "../domain/membership.js";
import type {
  DirectoryEntry,
  MembershipRepository,
  StoredCertificate,
} from "../repositories/MembershipRepository.js";
import { COLLECTIONS, documentId } from "./collections.js";
import type { DocumentData, Documents, StoredDocument } from "./Documents.js";
import {
  bytes,
  compareText,
  date,
  integer,
  optionalBytes,
  optionalDate,
  optionalText,
  text,
} from "./fields.js";
import { insertNew } from "./insertNew.js";

const MEMBERSHIPS = COLLECTIONS.memberships;
const USERS = COLLECTIONS.users;
const INVITES = COLLECTIONS.invites;

/**
 * ### FirestoreMembershipRepository
 *
 * {@link MembershipRepository} on Firestore. Memberships are keyed by `orgId:userId`; the
 * directory joins users and the invites they used in memory.
 */
export class FirestoreMembershipRepository implements MembershipRepository {
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
   * ### isConfirmed
   *
   * @see {@link MembershipRepository.isConfirmed}
   */
  async isConfirmed(orgId: string, userId: string): Promise<boolean> {
    const membership = await this.#docs.get(
      MEMBERSHIPS,
      documentId.membership(orgId, userId),
    );

    return membership?.status === "confirmed";
  }

  /**
   * ### insert
   *
   * @see {@link MembershipRepository.insert}
   */
  async insert(
    orgId: string,
    userId: string,
    role: MembershipRole,
  ): Promise<void> {
    await insertNew(
      this.#docs,
      MEMBERSHIPS,
      documentId.membership(orgId, userId),
      {
        orgId,
        userId,
        role,
        status: "accepted",
        certificate: null,
        certificateSignature: null,
        confirmedBy: null,
        confirmedAt: null,
      },
    );
  }

  /**
   * ### unfreeze
   *
   * @see {@link MembershipRepository.unfreeze}
   */
  async unfreeze(userId: string): Promise<void> {
    for (const membership of await this.#docs.find(MEMBERSHIPS, [
      ["userId", userId],
      ["status", "recovering"],
    ])) {
      await this.#docs.update(MEMBERSHIPS, membership.id, {
        status: "confirmed",
      });
    }
  }

  /**
   * ### directory
   *
   * @see {@link MembershipRepository.directory}
   */
  async directory(orgId: string): Promise<Array<DirectoryEntry>> {
    const memberships = await this.#docs.find(MEMBERSHIPS, [["orgId", orgId]]);
    const invites = await this.#docs.find(INVITES, [["orgId", orgId]]);
    const entries: Array<DirectoryEntry> = [];

    for (const membership of memberships) {
      const userId = text(membership.data, "userId");
      const user = await this.#docs.get(USERS, userId);

      // An inner join: memberships without a user are left out
      if (user === undefined) {
        continue;
      }

      const email = text(user, "email");
      const certificate = optionalText(membership.data, "certificate");
      const invite = lastUsedInvite(invites, email);

      entries.push({
        userId,
        email,
        name: text(user, "name"),
        role: role(membership.data),
        status: status(membership.data),
        encryptionPublicKey: bytes(user, "encryptionPublicKey"),
        signingPublicKey: bytes(user, "signingPublicKey"),
        keysetVersion: integer(user, "keysetVersion"),
        selfSignature: bytes(user, "selfSignature"),
        certificate:
          certificate === undefined
            ? undefined
            : // Only certify writes this field, from a StoredCertificate
              (JSON.parse(certificate) as StoredCertificate),
        certificateSignature: optionalBytes(
          membership.data,
          "certificateSignature",
        ),
        invite,
      });
    }

    return entries.sort((left, right) => compareText(left.email, right.email));
  }

  /**
   * ### lockForCertification
   *
   * @see {@link MembershipRepository.lockForCertification}
   */
  async lockForCertification(userId: string): Promise<
    | {
        email: string;
        orgId: string;
        role: MembershipRole;
        status: MembershipStatus;
        encryptionPublicKey: Uint8Array;
        signingPublicKey: Uint8Array;
        keysetVersion: number;
      }
    | undefined
  > {
    const user = await this.#docs.get(USERS, userId);
    const [membership] = await this.#membershipsOf(userId);

    if (user === undefined || membership === undefined) {
      return undefined;
    }

    return {
      email: text(user, "email"),
      orgId: text(membership.data, "orgId"),
      role: role(membership.data),
      status: status(membership.data),
      encryptionPublicKey: bytes(user, "encryptionPublicKey"),
      signingPublicKey: bytes(user, "signingPublicKey"),
      keysetVersion: integer(user, "keysetVersion"),
    };
  }

  /**
   * ### certify
   *
   * @see {@link MembershipRepository.certify}
   */
  async certify(
    userId: string,
    certificate: StoredCertificate,
    signature: Uint8Array,
    by: string,
    at: Date,
  ): Promise<void> {
    for (const membership of await this.#membershipsOf(userId)) {
      await this.#docs.update(MEMBERSHIPS, membership.id, {
        status: "confirmed",
        certificate: JSON.stringify(certificate),
        certificateSignature: signature,
        confirmedBy: by,
        confirmedAt: at,
      });
    }
  }

  /**
   * ### lockRole
   *
   * @see {@link MembershipRepository.lockRole}
   */
  async lockRole(
    orgId: string,
    userId: string,
  ): Promise<MembershipRole | undefined> {
    const membership = await this.#docs.get(
      MEMBERSHIPS,
      documentId.membership(orgId, userId),
    );

    return membership === undefined ? undefined : role(membership);
  }

  /**
   * ### suspend
   *
   * @see {@link MembershipRepository.suspend}
   */
  async suspend(orgId: string, userId: string): Promise<void> {
    await this.#docs.update(MEMBERSHIPS, documentId.membership(orgId, userId), {
      status: "suspended",
    });
  }

  /**
   * ### lockState
   *
   * @see {@link MembershipRepository.lockState}
   */
  async lockState(
    orgId: string,
    userId: string,
  ): Promise<{ role: MembershipRole; status: MembershipStatus } | undefined> {
    const membership = await this.#docs.get(
      MEMBERSHIPS,
      documentId.membership(orgId, userId),
    );

    return membership === undefined
      ? undefined
      : { role: role(membership), status: status(membership) };
  }

  /**
   * ### status
   *
   * @see {@link MembershipRepository.status}
   */
  async status(userId: string): Promise<MembershipStatus | undefined> {
    const [membership] = await this.#membershipsOf(userId);

    return membership === undefined ? undefined : status(membership.data);
  }

  /**
   * ### confirmation
   *
   * @see {@link MembershipRepository.confirmation}
   */
  async confirmation(userId: string): Promise<{
    confirmedBy: string | undefined;
    confirmedAt: Date | undefined;
  }> {
    const [membership] = await this.#membershipsOf(userId);

    return membership === undefined
      ? { confirmedBy: undefined, confirmedAt: undefined }
      : {
          confirmedBy: optionalText(membership.data, "confirmedBy"),
          confirmedAt: optionalDate(membership.data, "confirmedAt"),
        };
  }

  /**
   * ### freeze
   *
   * @see {@link MembershipRepository.freeze}
   */
  async freeze(userId: string): Promise<boolean> {
    const confirmed = await this.#docs.find(MEMBERSHIPS, [
      ["userId", userId],
      ["status", "confirmed"],
    ]);

    for (const membership of confirmed) {
      await this.#docs.update(MEMBERSHIPS, membership.id, {
        status: "recovering",
      });
    }

    return confirmed.length > 0;
  }

  /**
   * ### resetForRekey
   *
   * @see {@link MembershipRepository.resetForRekey}
   */
  async resetForRekey(userId: string): Promise<void> {
    for (const membership of await this.#membershipsOf(userId)) {
      await this.#docs.update(MEMBERSHIPS, membership.id, {
        status: "accepted",
        certificate: null,
        certificateSignature: null,
      });
    }
  }

  /**
   * ### #membershipsOf
   *
   * A user's memberships. A user belongs to one organisation, so there is at most one.
   *
   * @param userId User
   * @returns Their memberships
   */
  #membershipsOf(userId: string): Promise<Array<StoredDocument>> {
    return this.#docs.find(MEMBERSHIPS, [["userId", userId]]);
  }
}

/**
 * ### lastUsedInvite
 *
 * The signed invite a member most recently joined with.
 *
 * @param invites The organisation's invites
 * @param email Member's email
 * @returns Its statement and signature, or `undefined` when none was used or it was unsigned
 */
function lastUsedInvite(
  invites: ReadonlyArray<StoredDocument>,
  email: string,
): DirectoryEntry["invite"] {
  const [latest] = invites
    .filter(
      (invite) =>
        invite.data.email === email &&
        optionalDate(invite.data, "usedAt") !== undefined,
    )
    .sort(
      (left, right) =>
        date(right.data, "usedAt").getTime() -
        date(left.data, "usedAt").getTime(),
    );
  if (latest === undefined) {
    return undefined;
  }

  const statement = optionalText(latest.data, "statement");
  const signature = optionalBytes(latest.data, "signature");

  return statement === undefined || signature === undefined
    ? undefined
    : {
        // Only the invite repository writes this field, from a JSON object
        statement: JSON.parse(statement) as Record<string, unknown>,
        signature,
        proof: optionalBytes(latest.data, "proof"),
      };
}

/**
 * ### role
 *
 * Reads a membership's role.
 *
 * @param data Membership fields
 * @returns The role
 */
function role(data: DocumentData): MembershipRole {
  // Only this repository writes the field, always with a MembershipRole
  return text(data, "role") as MembershipRole;
}

/**
 * ### status
 *
 * Reads a membership's status.
 *
 * @param data Membership fields
 * @returns The status
 */
function status(data: DocumentData): MembershipStatus {
  // Only this repository writes the field, always with a MembershipStatus
  return text(data, "status") as MembershipStatus;
}
