import type { Caller } from "../../domain/Caller.js";
import { DomainError } from "../../domain/DomainError.js";
import { requireGrantSignature } from "../grants.js";
import type { ServiceContext } from "../ServiceContext.js";
import { requireVaultPermission } from "../vaultAccess.js";
import { requirePrincipal, storeRecoveryWrap } from "./principals.js";
import type { NewGrant } from "./VaultAccessControl.js";

/**
 * ### RotatedVault
 *
 * A vault's next key generation: its sealed name, the new grants, the recovery copy, and every
 * live item re-encrypted under it.
 */
export interface RotatedVault {
  readonly keyGeneration: number;
  readonly encryptedName: Uint8Array;
  readonly access: ReadonlyArray<NewGrant>;
  readonly recoveryWrappedKey: Uint8Array | undefined;
  readonly items: ReadonlyArray<{
    id: string;
    baseRevision: number;
    encryptedItemKey: Uint8Array;
    encryptedOverview: Uint8Array;
    encryptedDetails: Uint8Array;
  }>;
}

/**
 * ### VaultRotation
 *
 * Replacing a vault's key: everyone keeps or loses access in one step, and every live item is
 * re-encrypted, so whoever kept the old key cannot read anything written afterwards.
 */
export class VaultRotation {
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
   * Moves a vault the caller manages to its next key generation.
   *
   * @param caller Managing member, who must keep manage access
   * @param vaultId Vault
   * @param next The next generation
   */
  async rotate(
    caller: Caller,
    vaultId: string,
    next: RotatedVault,
  ): Promise<void> {
    if (
      next.access.find(
        (entry) =>
          entry.principalType === "user" && entry.principalId === caller.userId,
      )?.permission !== "manage"
    ) {
      throw new DomainError(
        "invalid",
        "bad_request",
        "The rotating manager must keep manage access",
      );
    }

    await this.#context.store.transaction(async (repos) => {
      // Serialises against other rotations and grants, so the generation check below holds
      await repos.changeFeed.lock();

      const { audit, items, users, vaults } = repos;
      const vault = await requireVaultPermission(
        vaults,
        vaultId,
        caller.userId,
        "manage",
      );

      if (next.keyGeneration !== vault.keyGeneration + 1) {
        throw new DomainError(
          "conflict",
          "conflict",
          "Key generation must advance by one",
          { keyGeneration: vault.keyGeneration },
        );
      }

      const live = await items.lockLiveInVault(vaultId);
      const submitted = new Map(next.items.map((item) => [item.id, item]));

      // Every live item must be re-encrypted, or it would stay readable with the old key only
      if (
        live.length !== submitted.size ||
        live.some(
          (item) => submitted.get(item.id)?.baseRevision !== item.revision,
        )
      ) {
        throw new DomainError(
          "conflict",
          "revision_conflict",
          "Items changed while rotating; sync and retry",
        );
      }

      // Rotation re-lists everyone; for a personal vault that may only ever be its owner
      if (vault.kind === "personal" && next.access.length !== 1) {
        throw new DomainError(
          "invalid",
          "bad_request",
          "A personal vault has exactly one member",
        );
      }

      for (const entry of next.access) {
        await requirePrincipal(repos, caller.orgId, entry);
        await requireGrantSignature(
          users,
          caller.userId,
          { ...entry, vaultId, keyGeneration: next.keyGeneration },
          entry.grantSignature,
        );
      }

      await vaults.replaceGrants(
        vaultId,
        next.access,
        next.keyGeneration,
        caller.userId,
      );

      for (const item of next.items) {
        await items.reencrypt(item, caller.userId, this.#context.now());
      }

      await vaults.advanceKey(vaultId, next.keyGeneration, next.encryptedName);
      await storeRecoveryWrap(
        repos,
        caller.orgId,
        vaultId,
        next.keyGeneration,
        next.recoveryWrappedKey,
      );
      await audit.record({
        orgId: caller.orgId,
        actorId: caller.userId,
        action: "vault.key_rotated",
        targetId: vaultId,
        detail: {
          keyGeneration: next.keyGeneration,
          members: next.access.length,
          items: next.items.length,
        },
        ip: caller.ip,
      });
    });
  }
}
