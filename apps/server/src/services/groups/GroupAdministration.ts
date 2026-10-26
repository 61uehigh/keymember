import type { Caller } from "../../domain/Caller.js";
import { DomainError } from "../../domain/DomainError.js";
import type {
  GroupRecord,
  StoredGroupMembership,
} from "../../repositories/GroupRepository.js";
import type { VaultPermission } from "../../repositories/VaultRepository.js";
import type { ServiceContext } from "../ServiceContext.js";
import {
  checkCertificate,
  findGroup,
  insertMembers,
  storedKey,
} from "./groupKeys.js";
import type { MemberCopy, SignedGroupKey } from "./groupKeys.js";

/**
 * ### GroupKeyMaterial
 *
 * What an admin needs to add members to a group or rotate it: the current key and its copies,
 * and every vault key wrapped to the group.
 */
export interface GroupKeyMaterial {
  readonly group: GroupRecord;
  readonly memberWrappedKey: Uint8Array | undefined;
  readonly memberships: ReadonlyArray<StoredGroupMembership>;
  readonly access: ReadonlyArray<{
    vaultId: string;
    wrappedKey: Uint8Array;
    keyGeneration: number;
    permission: VaultPermission;
  }>;
}

/**
 * ### GroupAdministration
 *
 * Creating and deleting groups and adding members (admins). A group is a principal with its own
 * key pair: vault keys are wrapped to the group, and the group's private key is wrapped to each
 * member, with the handing admin's signature over each copy.
 */
export class GroupAdministration {
  readonly #context: ServiceContext;

  /**
   * ### constructor
   *
   * @param context Where data is kept, and the clock
   */
  constructor(context: ServiceContext) {
    this.#context = context;
  }

  /**
   * ### create
   *
   * Creates a group at key version 1 with its first members.
   *
   * @param caller Admin creating the group
   * @param key The signed group key
   * @param members Members' copies of the group key
   */
  async create(
    caller: Caller,
    key: SignedGroupKey,
    members: ReadonlyArray<MemberCopy>,
  ): Promise<void> {
    const { groupId } = key.certificate;

    await this.#context.store.transaction(async (repos) => {
      await checkCertificate(repos, key, {
        orgId: caller.orgId,
        groupId,
        issuerId: caller.userId,
        keysetVersion: 1,
      });

      if (await repos.groups.exists(groupId)) {
        throw new DomainError(
          "conflict",
          "conflict",
          "Group id already exists",
        );
      }

      await repos.groups.insert({
        id: groupId,
        orgId: caller.orgId,
        createdBy: caller.userId,
        ...storedKey(key),
      });
      await insertMembers(repos, caller, groupId, 1, members);
      await repos.audit.record({
        orgId: caller.orgId,
        actorId: caller.userId,
        action: "group.created",
        targetId: groupId,
        detail: { name: key.certificate.name, members: members.length },
        ip: caller.ip,
      });
    });
  }

  /**
   * ### addMember
   *
   * Hands a member a copy of the group's current key.
   *
   * @param caller Admin adding the member
   * @param groupId Group
   * @param copy The member's copy and its signature
   * @param keysetVersion Group key version the copy belongs to
   */
  async addMember(
    caller: Caller,
    groupId: string,
    copy: MemberCopy,
    keysetVersion: number,
  ): Promise<void> {
    await this.#context.store.transaction(async (repos) => {
      const group = await findGroup(repos.groups, caller.orgId, groupId);

      // A copy of a superseded key would hand out a key nothing uses any more
      if (group.keysetVersion !== keysetVersion) {
        throw new DomainError(
          "conflict",
          "revision_conflict",
          "The group key changed; sync and wrap the current key",
        );
      }

      await insertMembers(repos, caller, groupId, keysetVersion, [copy]);
      await repos.audit.record({
        orgId: caller.orgId,
        actorId: caller.userId,
        action: "group.member_added",
        targetId: groupId,
        detail: { userId: copy.userId },
        ip: caller.ip,
      });
    });
  }

  /**
   * ### delete
   *
   * Deletes a group and the vault access it carried.
   *
   * @param caller Admin deleting the group
   * @param groupId Group
   */
  async delete(caller: Caller, groupId: string): Promise<void> {
    await this.#context.store.transaction(async (repos) => {
      // Serialises access changes, so the manager check below sees every concurrent change
      await repos.changeFeed.lock();

      const { audit, groups, vaults } = repos;

      await findGroup(groups, caller.orgId, groupId);

      // A vault managed only through this group would be left without a manager
      if ((await vaults.leftWithoutManager(groupId)).length > 0) {
        throw new DomainError(
          "conflict",
          "conflict",
          "Give another member manage access to the group's vaults first",
        );
      }

      await groups.markDeleted(groupId, this.#context.now());
      await groups.removeAllMembers(groupId);
      await vaults.removeGroupGrants(groupId);
      await audit.record({
        orgId: caller.orgId,
        actorId: caller.userId,
        action: "group.deleted",
        targetId: groupId,
        ip: caller.ip,
      });
    });
  }

  /**
   * ### keyMaterial
   *
   * The group's current key, the caller's own copy, every member's signed copy and the vault
   * keys wrapped to the group, read from one snapshot so they agree.
   *
   * @param caller Admin
   * @param groupId Group
   * @returns The key material
   */
  keyMaterial(caller: Caller, groupId: string): Promise<GroupKeyMaterial> {
    return this.#context.store.snapshot(async (repos) => {
      const { groups, vaults } = repos;
      const group = await groups.findLive(caller.orgId, groupId);

      if (group === undefined) {
        throw new DomainError("not_found", "not_found", "No such group");
      }

      const own = await groups.memberKey(groupId, caller.userId);

      return {
        group,
        memberWrappedKey:
          own?.keysetVersion === group.keysetVersion
            ? own.wrappedPrivateKey
            : undefined,
        memberships: (await groups.memberships(groupId)).filter(
          (membership) => membership.keysetVersion === group.keysetVersion,
        ),
        access: await vaults.grantsToGroup(groupId),
      };
    });
  }
}
