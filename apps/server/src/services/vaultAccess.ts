import { DomainError } from "../domain/DomainError.js";
import type {
  VaultKind,
  VaultPermission,
  VaultRepository,
} from "../repositories/VaultRepository.js";

export type {
  PrincipalType,
  VaultPermission,
} from "../repositories/VaultRepository.js";

const PERMISSION_RANK: Readonly<Record<VaultPermission, number>> = {
  view: 0,
  edit: 1,
  manage: 2,
};

/**
 * ### requireVaultPermission
 *
 * Checks that a user holds at least the needed permission on a live vault, counting direct
 * access and access through any live group; the strongest wins. Answers 404 rather than 403
 * when the user has no access at all, so vault ids cannot be probed.
 *
 * @param vaults Vault storage
 * @param vaultId Vault to check
 * @param userId User to check
 * @param needed Minimum permission
 * @returns The vault's kind and current key generation
 */
export async function requireVaultPermission(
  vaults: Pick<VaultRepository, "accessOf">,
  vaultId: string,
  userId: string,
  needed: VaultPermission,
): Promise<{ kind: VaultKind; keyGeneration: number }> {
  const [best] = (await vaults.accessOf(vaultId, userId)).sort(
    (a, b) => PERMISSION_RANK[b.permission] - PERMISSION_RANK[a.permission],
  );

  if (best === undefined) {
    throw new DomainError("not_found", "not_found", "No such vault");
  }

  if (PERMISSION_RANK[best.permission] < PERMISSION_RANK[needed]) {
    throw new DomainError(
      "forbidden",
      "forbidden",
      `Requires ${needed} permission on this vault`,
    );
  }

  return { kind: best.kind, keyGeneration: best.keyGeneration };
}
