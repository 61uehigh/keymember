import type {
  GroupKeyChange,
  GroupRecord,
  GroupRepository,
  HeldGroupKey,
  StoredGroupCertificate,
  MembershipSignature,
  StoredGroupMembership,
} from "../repositories/GroupRepository.js";
import { COLLECTIONS, documentId, REVISION_SEQUENCE } from "./collections.js";
import type { DocumentData, Documents } from "./Documents.js";
import {
  bytes,
  compareText,
  integer,
  optionalBytes,
  optionalText,
  optionalDate,
  text,
} from "./fields.js";
import { insertNew } from "./insertNew.js";

const GROUPS = COLLECTIONS.groups;
const GROUP_MEMBERS = COLLECTIONS.groupMembers;

/**
 * ### FirestoreGroupRepository
 *
 * {@link GroupRepository} on Firestore. Groups are keyed by id and members by
 * `groupId:userId`; joins between them happen in memory.
 */
export class FirestoreGroupRepository implements GroupRepository {
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
   * ### liveKeysetVersion
   *
   * @see {@link GroupRepository.liveKeysetVersion}
   */
  async liveKeysetVersion(
    orgId: string,
    groupId: string,
  ): Promise<number | undefined> {
    const group = await this.#liveGroup(orgId, groupId);

    return group === undefined ? undefined : integer(group, "keysetVersion");
  }

  /**
   * ### keysHeldBy
   *
   * @see {@link GroupRepository.keysHeldBy}
   */
  async keysHeldBy(userId: string): Promise<Array<HeldGroupKey>> {
    const held: Array<HeldGroupKey> = [];
    const members = await this.#docs.find(GROUP_MEMBERS, [["userId", userId]]);
    // Read every group at once rather than one after another
    const groups = await Promise.all(
      members.map((member) =>
        this.#docs.get(GROUPS, text(member.data, "groupId")),
      ),
    );

    for (const [index, member] of members.entries()) {
      const groupId = text(member.data, "groupId");
      const group = groups[index];

      if (group === undefined || isDeleted(group)) {
        continue;
      }

      held.push({
        id: groupId,
        name: text(group, "name"),
        encryptionPublicKey: bytes(group, "encryptionPublicKey"),
        keysetVersion: integer(group, "keysetVersion"),
        // Only this repository writes the field, from a JSON object
        certificate: JSON.parse(text(group, "certificate")) as Record<
          string,
          unknown
        >,
        certificateSignature: bytes(group, "certificateSignature"),
        wrappedPrivateKey: bytes(member.data, "wrappedPrivateKey"),
        memberKeysetVersion: integer(member.data, "keysetVersion"),
      });
    }

    return held.sort((left, right) => compareText(left.id, right.id));
  }

  /**
   * ### exists
   *
   * @see {@link GroupRepository.exists}
   */
  async exists(groupId: string): Promise<boolean> {
    return (await this.#docs.get(GROUPS, groupId)) !== undefined;
  }

  /**
   * ### listLive
   *
   * @see {@link GroupRepository.listLive}
   */
  async listLive(orgId: string): Promise<
    Array<
      GroupRecord & {
        members: Array<{ userId: string; keysetVersion: number }>;
      }
    >
  > {
    const groups = (await this.#docs.find(GROUPS, [["orgId", orgId]]))
      .filter((group) => !isDeleted(group.data))
      .map((group) => toGroupRecord(group.id, group.data))
      .sort(
        (left, right) =>
          compareText(left.name, right.name) || compareText(left.id, right.id),
      );
    const listed = [];

    for (const group of groups) {
      const members = (
        await this.#docs.find(GROUP_MEMBERS, [["groupId", group.id]])
      )
        .map((member) => ({
          userId: text(member.data, "userId"),
          keysetVersion: integer(member.data, "keysetVersion"),
        }))
        .sort((left, right) => compareText(left.userId, right.userId));

      listed.push({ ...group, members });
    }

    return listed;
  }

  /**
   * ### lockLive
   *
   * @see {@link GroupRepository.lockLive}
   */
  async lockLive(
    orgId: string,
    groupId: string,
  ): Promise<GroupRecord | undefined> {
    const group = await this.#liveGroup(orgId, groupId);

    return group === undefined ? undefined : toGroupRecord(groupId, group);
  }

  /**
   * ### findLive
   *
   * Firestore reads do not lock outside a read-write transaction, so this is
   * {@link FirestoreGroupRepository.lockLive}.
   *
   * @see {@link GroupRepository.findLive}
   */
  findLive(orgId: string, groupId: string): Promise<GroupRecord | undefined> {
    return this.lockLive(orgId, groupId);
  }

  /**
   * ### insert
   *
   * @see {@link GroupRepository.insert}
   */
  async insert(
    group: GroupKeyChange & { id: string; orgId: string; createdBy: string },
  ): Promise<void> {
    await insertNew(this.#docs, GROUPS, group.id, {
      id: group.id,
      orgId: group.orgId,
      name: group.name,
      encryptionPublicKey: group.encryptionPublicKey,
      keysetVersion: group.keysetVersion,
      certificate: JSON.stringify(group.certificate),
      certificateSignature: group.certificateSignature,
      recoveryWrappedKey: group.recoveryWrappedKey ?? null,
      createdBy: group.createdBy,
      createdAt: new Date(),
      deletedAt: null,
      revision: await this.#docs.nextSequence(REVISION_SEQUENCE),
    });
  }

  /**
   * ### changeKey
   *
   * @see {@link GroupRepository.changeKey}
   */
  async changeKey(groupId: string, key: GroupKeyChange): Promise<void> {
    if ((await this.#docs.get(GROUPS, groupId)) === undefined) {
      return;
    }

    await this.#docs.update(GROUPS, groupId, {
      name: key.name,
      encryptionPublicKey: key.encryptionPublicKey,
      keysetVersion: key.keysetVersion,
      certificate: JSON.stringify(key.certificate),
      certificateSignature: key.certificateSignature,
      recoveryWrappedKey: key.recoveryWrappedKey ?? null,
      revision: await this.#docs.nextSequence(REVISION_SEQUENCE),
    });
  }

  /**
   * ### putMember
   *
   * @see {@link GroupRepository.putMember}
   */
  async putMember(
    groupId: string,
    userId: string,
    wrappedPrivateKey: Uint8Array,
    keysetVersion: number,
    signed: MembershipSignature,
  ): Promise<void> {
    await this.#docs.set(
      GROUP_MEMBERS,
      documentId.groupMember(groupId, userId),
      {
        groupId,
        userId,
        wrappedPrivateKey,
        keysetVersion,
        grantedBy: signed.grantedBy,
        membershipSignature: signed.signature,
        revision: await this.#docs.nextSequence(REVISION_SEQUENCE),
      },
    );
  }

  /**
   * ### memberships
   *
   * Copies stored before membership signatures lack both fields and read as unsigned.
   *
   * @see {@link GroupRepository.memberships}
   */
  async memberships(groupId: string): Promise<Array<StoredGroupMembership>> {
    return (await this.#docs.find(GROUP_MEMBERS, [["groupId", groupId]]))
      .map((member) => ({
        userId: text(member.data, "userId"),
        wrappedPrivateKey: bytes(member.data, "wrappedPrivateKey"),
        keysetVersion: integer(member.data, "keysetVersion"),
        grantedBy: optionalText(member.data, "grantedBy"),
        signature: optionalBytes(member.data, "membershipSignature"),
      }))
      .sort((left, right) => compareText(left.userId, right.userId));
  }

  /**
   * ### memberKey
   *
   * @see {@link GroupRepository.memberKey}
   */
  async memberKey(
    groupId: string,
    userId: string,
  ): Promise<
    { wrappedPrivateKey: Uint8Array; keysetVersion: number } | undefined
  > {
    const member = await this.#docs.get(
      GROUP_MEMBERS,
      documentId.groupMember(groupId, userId),
    );

    return member === undefined
      ? undefined
      : {
          wrappedPrivateKey: bytes(member, "wrappedPrivateKey"),
          keysetVersion: integer(member, "keysetVersion"),
        };
  }

  /**
   * ### removeAllMembers
   *
   * @see {@link GroupRepository.removeAllMembers}
   */
  async removeAllMembers(groupId: string): Promise<void> {
    for (const member of await this.#docs.find(GROUP_MEMBERS, [
      ["groupId", groupId],
    ])) {
      await this.#docs.delete(GROUP_MEMBERS, member.id);
    }
  }

  /**
   * ### markDeleted
   *
   * @see {@link GroupRepository.markDeleted}
   */
  async markDeleted(groupId: string, at: Date): Promise<void> {
    if ((await this.#docs.get(GROUPS, groupId)) === undefined) {
      return;
    }

    await this.#docs.update(GROUPS, groupId, {
      deletedAt: at,
      revision: await this.#docs.nextSequence(REVISION_SEQUENCE),
    });
  }

  /**
   * ### liveGroupsOf
   *
   * @see {@link GroupRepository.liveGroupsOf}
   */
  async liveGroupsOf(userId: string): Promise<Array<string>> {
    const live: Array<string> = [];

    for (const member of await this.#docs.find(GROUP_MEMBERS, [
      ["userId", userId],
    ])) {
      const groupId = text(member.data, "groupId");
      const group = await this.#docs.get(GROUPS, groupId);

      if (group !== undefined && !isDeleted(group)) {
        live.push(groupId);
      }
    }

    return live.sort(compareText);
  }

  /**
   * ### removeFromAll
   *
   * @see {@link GroupRepository.removeFromAll}
   */
  async removeFromAll(userId: string): Promise<void> {
    for (const member of await this.#docs.find(GROUP_MEMBERS, [
      ["userId", userId],
    ])) {
      await this.#docs.delete(GROUP_MEMBERS, member.id);
    }
  }

  /**
   * ### recoveryCopies
   *
   * @see {@link GroupRepository.recoveryCopies}
   */
  async recoveryCopies(groupIds: ReadonlyArray<string>): Promise<
    Array<{
      groupId: string;
      keysetVersion: number;
      encryptionPublicKey: Uint8Array;
      recoveryWrappedKey: Uint8Array;
    }>
  > {
    const copies = [];

    for (const groupId of new Set(groupIds)) {
      const group = await this.#docs.get(GROUPS, groupId);
      const recoveryWrappedKey =
        group === undefined
          ? undefined
          : optionalBytes(group, "recoveryWrappedKey");

      if (
        group === undefined ||
        isDeleted(group) ||
        recoveryWrappedKey === undefined
      ) {
        continue;
      }

      copies.push({
        groupId,
        keysetVersion: integer(group, "keysetVersion"),
        encryptionPublicKey: bytes(group, "encryptionPublicKey"),
        recoveryWrappedKey,
      });
    }

    return copies;
  }

  /**
   * ### #liveGroup
   *
   * A live group of an organisation.
   *
   * @param orgId Organisation
   * @param groupId Group
   * @returns Its fields, or `undefined` when there is no such live group
   */
  async #liveGroup(
    orgId: string,
    groupId: string,
  ): Promise<DocumentData | undefined> {
    const group = await this.#docs.get(GROUPS, groupId);

    return group?.orgId !== orgId || isDeleted(group) ? undefined : group;
  }
}

/**
 * ### isDeleted
 *
 * Whether a group was deleted.
 *
 * @param group Group fields
 * @returns Whether `deletedAt` is set
 */
function isDeleted(group: DocumentData): boolean {
  return optionalDate(group, "deletedAt") !== undefined;
}

/**
 * ### toGroupRecord
 *
 * Maps a group document to a {@link GroupRecord}.
 *
 * @param id Group id
 * @param group Group fields
 * @returns The record
 */
function toGroupRecord(id: string, group: DocumentData): GroupRecord {
  return {
    id,
    name: text(group, "name"),
    encryptionPublicKey: bytes(group, "encryptionPublicKey"),
    keysetVersion: integer(group, "keysetVersion"),
    // Only this repository writes the field, from a StoredGroupCertificate
    certificate: JSON.parse(
      text(group, "certificate"),
    ) as StoredGroupCertificate,
    certificateSignature: bytes(group, "certificateSignature"),
    recoveryWrappedKey: optionalBytes(group, "recoveryWrappedKey"),
  };
}
