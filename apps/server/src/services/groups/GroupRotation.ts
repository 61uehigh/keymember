import type { Caller } from "../../domain/Caller.js";
import { DomainError } from "../../domain/DomainError.js";
import { requireGrantSignature } from "../grants.js";
import type { ServiceContext } from "../ServiceContext.js";
import {
  checkCertificate,
  findGroup,
  insertMembers,
  storedKey,
} from "./groupKeys.js";
import type { MemberCopy, SignedGroupKey } from "./groupKeys.js";

/**
 * ### GroupRotation
 *
 * Replacing a group's key, which is how a member leaves a group: the new key goes only to the
 * members listed, and every vault key the group carries is re-wrapped to it. The vault keys
 * themselves stay until a manager rotates them (crypto.md §5).
 */
export class GroupRotation {
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
   * ### rotate
   *
   * Moves a group to its next key version.
   *
   * @param caller Admin rotating the group
   * @param groupId Group
   * @param key The next signed group key
   * @param members Members' copies of the next key; anyone left out loses the group
   * @param access Every vault key the group carries, re-wrapped to the next key and signed
   */
  async rotate(
    caller: Caller,
    groupId: string,
    key: SignedGroupKey,
    members: ReadonlyArray<MemberCopy>,
    access: ReadonlyArray<{
      vaultId: string;
      wrappedKey: Uint8Array;
      grantSignature: Uint8Array;
      keyGeneration: number;
    }>,
  ): Promise<void> {
    await this.#context.store.transaction(async (repos) => {
      // Serialises against vault rotations and grants, so the generations checked below hold
      await repos.changeFeed.lock();

      const { audit, groups, users, vaults } = repos;
      const group = await findGroup(groups, caller.orgId, groupId);
      const nextVersion = group.keysetVersion + 1;

      await checkCertificate(repos, key, {
        orgId: caller.orgId,
        groupId,
        issuerId: caller.userId,
        keysetVersion: nextVersion,
      });

      const current = await vaults.grantsToGroup(groupId);
      const submitted = new Map(access.map((entry) => [entry.vaultId, entry]));

      // Every vault the group reaches must move to the new key, at its current generation
      if (
        submitted.size !== access.length ||
        submitted.size !== current.length ||
        current.some(
          (grant) =>
            submitted.get(grant.vaultId)?.keyGeneration !==
            grant.vaultKeyGeneration,
        )
      ) {
        throw new DomainError(
          "conflict",
          "revision_conflict",
          "Re-wrap the current key of every vault the group can access",
        );
      }

      await groups.changeKey(groupId, storedKey(key));

      // The member list is replaced as a whole: anyone left out loses the group from now on
      await groups.removeAllMembers(groupId);
      await insertMembers(repos, caller, groupId, nextVersion, members);

      for (const entry of access) {
        await requireGrantSignature(
          users,
          caller.userId,
          {
            vaultId: entry.vaultId,
            keyGeneration: entry.keyGeneration,
            principalType: "group",
            principalId: groupId,
            wrappedKey: entry.wrappedKey,
          },
          entry.grantSignature,
        );
        await vaults.rewrapForGroup(
          entry.vaultId,
          groupId,
          entry,
          caller.userId,
        );
      }

      await audit.record({
        orgId: caller.orgId,
        actorId: caller.userId,
        action: "group.rotated",
        targetId: groupId,
        detail: {
          keysetVersion: nextVersion,
          members: members.length,
          vaults: access.length,
        },
        ip: caller.ip,
      });
    });
  }
}
