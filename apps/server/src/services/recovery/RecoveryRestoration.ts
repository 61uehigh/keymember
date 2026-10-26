import { DomainError } from "../../domain/DomainError.js";
import type { GroupRepository } from "../../repositories/GroupRepository.js";
import type { RecoveryRecord } from "../../repositories/RecoveryRepository.js";
import type {
  VaultPermission,
  VaultRepository,
} from "../../repositories/VaultRepository.js";

import {
  requireGrantSignature,
  requireMembershipSignature,
} from "../grants.js";
import { findRecovery, permissionsOf } from "./shared.js";
import type { Caller } from "../../domain/Caller.js";
import type { ServiceContext } from "../ServiceContext.js";

/**
 * ### VaultRecoveryCopy
 *
 * A vault key wrapped to the organisation's recovery key.
 */
type VaultRecoveryCopy = Awaited<
  ReturnType<VaultRepository["recoveryCopies"]>
>[number];

/**
 * ### GroupRecoveryCopy
 *
 * A group private key wrapped to the organisation's recovery key.
 */
type GroupRecoveryCopy = Awaited<
  ReturnType<GroupRepository["recoveryCopies"]>
>[number];

/**
 * ### RecoveryKeys
 *
 * What the completing admin needs to restore a member's access: the recovery-key copies of the
 * vault and group keys the member had, and the permission to restore for each vault.
 */
export interface RecoveryKeys {
  readonly recovery: RecoveryRecord;
  readonly vaults: ReadonlyArray<
    VaultRecoveryCopy & { permission: VaultPermission | undefined }
  >;
  readonly groups: ReadonlyArray<GroupRecoveryCopy>;
}

/**
 * ### RestoredAccess
 *
 * Keys the completing admin re-wrapped for the member's new keys.
 */
export interface RestoredAccess {
  readonly access: ReadonlyArray<{
    vaultId: string;
    wrappedKey: Uint8Array;
    grantSignature: Uint8Array;
    keyGeneration: number;
  }>;
  readonly groups: ReadonlyArray<{
    groupId: string;
    wrappedPrivateKey: Uint8Array;
    keysetVersion: number;
    membershipSignature: Uint8Array;
  }>;
}

/**
 * ### RecoveryRestoration
 *
 * The completing admin's side: once the member re-enrolled and their new keys are certified,
 * re-wraps the keys they had from the recovery key, restoring exactly the recorded access.
 */
export class RecoveryRestoration {
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
   * ### keysToRestore
   *
   * The recovery-key copies of the keys a re-enrolled member had, for the completing admin to
   * re-wrap.
   *
   * @param orgId Admin's organisation
   * @param recoveryId Recovery being completed
   * @returns The recovery and the key copies
   */
  async keysToRestore(
    orgId: string,
    recoveryId: string,
  ): Promise<RecoveryKeys> {
    const recovery = await findRecovery(this.#context.store, orgId, recoveryId);

    if (recovery.status !== "rekeyed") {
      throw new DomainError(
        "conflict",
        "conflict",
        "The user has not re-enrolled yet",
      );
    }

    const { groups, vaults } = this.#context.store.repositories();
    const permissions = permissionsOf(recovery);
    const vaultCopies = await vaults.recoveryCopies(
      recovery.snapshot.vaults.map((entry) => entry.vaultId),
    );

    return {
      recovery,
      vaults: vaultCopies.map((copy) => ({
        ...copy,
        permission: permissions.get(copy.vaultId),
      })),
      groups: await groups.recoveryCopies(recovery.snapshot.groups),
    };
  }

  /**
   * ### complete
   *
   * Restores exactly the access in the recovery's snapshot to the member's certified new keys,
   * with each vault key grant signed by the completing admin, and closes the recovery.
   *
   * @param actor Completing admin
   * @param recoveryId Recovery to complete
   * @param restored Keys the admin re-wrapped for the member
   */
  async complete(
    actor: Caller,
    recoveryId: string,
    restored: RestoredAccess,
  ): Promise<void> {
    const recovery = await findRecovery(
      this.#context.store,
      actor.orgId,
      recoveryId,
    );
    const permissions = permissionsOf(recovery);

    await this.#context.store.transaction(async (repos) => {
      await repos.changeFeed.lock();

      if (
        recovery.status !== "rekeyed" ||
        (await repos.memberships.status(recovery.userId)) !== "confirmed"
      ) {
        throw new DomainError(
          "conflict",
          "conflict",
          "Certify the member's new keys before completing the recovery",
        );
      }

      for (const entry of restored.access) {
        const permission = permissions.get(entry.vaultId);

        // Restores exactly what the member had; recovery is never a way to widen access
        if (
          permission === undefined ||
          (await repos.vaults.liveKeyGeneration(entry.vaultId)) !==
            entry.keyGeneration
        ) {
          throw new DomainError(
            "invalid",
            "bad_request",
            `Vault ${entry.vaultId} is not restorable at that generation`,
          );
        }

        await requireGrantSignature(
          repos.users,
          actor.userId,
          {
            vaultId: entry.vaultId,
            keyGeneration: entry.keyGeneration,
            principalType: "user",
            principalId: recovery.userId,
            wrappedKey: entry.wrappedKey,
          },
          entry.grantSignature,
        );
        await repos.vaults.putGrant(
          entry.vaultId,
          {
            principalType: "user",
            principalId: recovery.userId,
            wrappedKey: entry.wrappedKey,
            permission,
            grantSignature: entry.grantSignature,
          },
          entry.keyGeneration,
          actor.userId,
        );
      }

      for (const entry of restored.groups) {
        if (
          !recovery.snapshot.groups.includes(entry.groupId) ||
          (await repos.groups.liveKeysetVersion(actor.orgId, entry.groupId)) !==
            entry.keysetVersion
        ) {
          throw new DomainError(
            "invalid",
            "bad_request",
            `Group ${entry.groupId} is not restorable at that version`,
          );
        }

        await requireMembershipSignature(
          repos.users,
          actor.userId,
          {
            groupId: entry.groupId,
            keysetVersion: entry.keysetVersion,
            userId: recovery.userId,
            wrappedPrivateKey: entry.wrappedPrivateKey,
          },
          entry.membershipSignature,
        );
        await repos.groups.putMember(
          entry.groupId,
          recovery.userId,
          entry.wrappedPrivateKey,
          entry.keysetVersion,
          { grantedBy: actor.userId, signature: entry.membershipSignature },
        );
      }

      // Re-read inside the transaction: a concurrent cancel or completion wins
      if (!(await repos.recoveries.complete(recoveryId, this.#context.now()))) {
        throw new DomainError(
          "conflict",
          "conflict",
          "The recovery is no longer open",
        );
      }

      await repos.audit.record({
        orgId: actor.orgId,
        actorId: actor.userId,
        action: "recovery.completed",
        targetId: recovery.userId,
        detail: {
          recoveryId,
          vaults: restored.access.length,
          groups: restored.groups.length,
        },
        ip: actor.ip,
      });
    });
  }
}
