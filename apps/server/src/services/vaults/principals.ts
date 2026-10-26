import { DomainError } from "../../domain/DomainError.js";
import type { Repositories } from "../../repositories/Repositories.js";
import type { PrincipalType } from "../../repositories/VaultRepository.js";

/**
 * ### GrantTarget
 *
 * Who a vault key is wrapped to: a member, or a group at the keyset version the wrap targets.
 */
export interface GrantTarget {
  readonly principalType: PrincipalType;
  readonly principalId: string;
  readonly groupKeysetVersion?: number | undefined;
}

/**
 * ### requirePrincipal
 *
 * Checks that a principal can receive a vault key: a confirmed member, or a live group of the
 * caller's organisation at the keyset version the wrap targets.
 *
 * @param repositories Membership and group storage
 * @param orgId Organisation of the caller
 * @param target Principal receiving the key
 */
export async function requirePrincipal(
  repositories: Pick<Repositories, "groups" | "memberships">,
  orgId: string,
  target: GrantTarget,
): Promise<void> {
  if (target.principalType === "user") {
    if (
      !(await repositories.memberships.isConfirmed(orgId, target.principalId))
    ) {
      throw new DomainError(
        "invalid",
        "bad_request",
        "Vault access can only be granted to confirmed members",
      );
    }

    return;
  }

  const keysetVersion = await repositories.groups.liveKeysetVersion(
    orgId,
    target.principalId,
  );

  if (keysetVersion === undefined) {
    throw new DomainError("invalid", "bad_request", "No such group");
  }

  // The wrap targets one group key; a key rotated meanwhile would make it unreadable to members
  if (keysetVersion !== target.groupKeysetVersion) {
    throw new DomainError(
      "conflict",
      "revision_conflict",
      "The group key changed; sync and wrap to the current group key",
    );
  }
}

/**
 * ### storeRecoveryWrap
 *
 * Stores a vault key's copy for the recovery key. Once the organisation has a recovery key,
 * every vault key generation must come with one, or that vault would be unrecoverable.
 *
 * @param repositories Organisation and vault storage
 * @param orgId Organisation of the vault
 * @param vaultId Vault the key belongs to
 * @param keyGeneration Generation of the wrapped key
 * @param wrappedKey Vault key wrapped to the recovery public key, if supplied
 */
export async function storeRecoveryWrap(
  repositories: Pick<Repositories, "organizations" | "vaults">,
  orgId: string,
  vaultId: string,
  keyGeneration: number,
  wrappedKey: Uint8Array | undefined,
): Promise<void> {
  if (wrappedKey === undefined) {
    if (await repositories.organizations.hasRecoveryKey(orgId)) {
      throw new DomainError(
        "invalid",
        "bad_request",
        "The vault key must also be wrapped to the organisation's recovery key",
      );
    }

    return;
  }

  await repositories.vaults.storeRecoveryWrap(
    vaultId,
    wrappedKey,
    keyGeneration,
  );
}
