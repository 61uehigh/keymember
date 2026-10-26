import { DomainError } from "../../domain/DomainError.js";
import type {
  AccessSnapshot,
  RecoveryRecord,
} from "../../repositories/RecoveryRepository.js";

import type { Repositories } from "../../repositories/Repositories.js";
import type { Store } from "../../repositories/Store.js";
import type { VaultPermission } from "../../repositories/VaultRepository.js";

/**
 * ### findRecovery
 *
 * Loads a recovery of the caller's organisation or answers 404.
 *
 * @param store Where data is kept
 * @param orgId Caller's organisation
 * @param recoveryId Recovery to load
 * @returns The recovery
 */
export async function findRecovery(
  store: Pick<Store, "repositories">,
  orgId: string,
  recoveryId: string,
): Promise<RecoveryRecord> {
  const recovery = await store
    .repositories()
    .recoveries.find(orgId, recoveryId);

  if (recovery === undefined) {
    throw new DomainError("not_found", "not_found", "No such recovery");
  }

  return recovery;
}

/**
 * ### takeSnapshot
 *
 * Records the vault access and group memberships a member has right now; a completed recovery
 * restores exactly these.
 *
 * @param repositories Vault and group storage
 * @param userId Member being recovered
 * @returns The snapshot
 */
export async function takeSnapshot(
  repositories: Pick<Repositories, "groups" | "vaults">,
  userId: string,
): Promise<AccessSnapshot> {
  return {
    vaults: await repositories.vaults.userGrants(userId),
    groups: await repositories.groups.liveGroupsOf(userId),
  };
}

/**
 * ### permissionsOf
 *
 * The permission the member had on each vault in a recovery's snapshot.
 *
 * @param recovery Recovery
 * @returns Permission by vault id
 */
export function permissionsOf(
  recovery: RecoveryRecord,
): Map<string, VaultPermission> {
  return new Map(
    recovery.snapshot.vaults.map((entry) => [entry.vaultId, entry.permission]),
  );
}
