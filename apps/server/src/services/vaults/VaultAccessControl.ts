import type { Caller } from "../../domain/Caller.js";
import { DomainError } from "../../domain/DomainError.js";
import type {
  VaultGrant,
  VaultKind,
  VaultPermission,
} from "../../repositories/VaultRepository.js";
import { requireGrantSignature } from "../grants.js";
import type { ServiceContext } from "../ServiceContext.js";
import { requireVaultPermission } from "../vaultAccess.js";
import { requirePrincipal, storeRecoveryWrap } from "./principals.js";
import type { GrantTarget } from "./principals.js";

/**
 * ### NewGrant
 *
 * A wrapped vault key for one principal, signed by the member handing it out.
 */
export type NewGrant = VaultGrant & GrantTarget;

/**
 * ### VaultAccessControl
 *
 * Creating vaults and deciding who can open them. Every key handed out carries the granting
 * member's signature, and a vault always keeps at least one manager.
 */
export class VaultAccessControl {
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
   * Creates a vault with its first grants. The creator must hold manage access, and a personal
   * vault has exactly one member.
   *
   * @param caller Member creating the vault
   * @param vault Id, kind, sealed name, grants and the recovery copy of the key
   */
  async create(
    caller: Caller,
    vault: {
      id: string;
      kind: VaultKind;
      encryptedName: Uint8Array;
      access: ReadonlyArray<NewGrant>;
      recoveryWrappedKey: Uint8Array | undefined;
    },
  ): Promise<void> {
    const own = vault.access.find(
      (entry) =>
        entry.principalType === "user" && entry.principalId === caller.userId,
    );

    if (own?.permission !== "manage") {
      throw new DomainError(
        "invalid",
        "bad_request",
        "The creator must hold manage access",
      );
    }

    if (vault.kind === "personal" && vault.access.length !== 1) {
      throw new DomainError(
        "invalid",
        "bad_request",
        "A personal vault has exactly one member",
      );
    }

    await this.#context.store.transaction(async (repos) => {
      const { audit, users, vaults } = repos;

      if (await vaults.exists(vault.id)) {
        throw new DomainError(
          "conflict",
          "conflict",
          "Vault id already exists",
        );
      }

      await vaults.insert({
        id: vault.id,
        orgId: caller.orgId,
        kind: vault.kind,
        encryptedName: vault.encryptedName,
        createdBy: caller.userId,
      });

      for (const entry of vault.access) {
        await requirePrincipal(repos, caller.orgId, entry);
        await requireGrantSignature(
          users,
          caller.userId,
          { ...entry, vaultId: vault.id, keyGeneration: 1 },
          entry.grantSignature,
        );
        await vaults.putGrant(vault.id, entry, 1, caller.userId);
      }

      await storeRecoveryWrap(
        repos,
        caller.orgId,
        vault.id,
        1,
        vault.recoveryWrappedKey,
      );
      await audit.record({
        orgId: caller.orgId,
        actorId: caller.userId,
        action: "vault.created",
        targetId: vault.id,
        detail: { kind: vault.kind, members: vault.access.length },
        ip: caller.ip,
      });
    });
  }

  /**
   * ### grant
   *
   * Grants or changes one principal's access to a shared vault the caller manages.
   *
   * @param caller Managing member
   * @param vaultId Vault
   * @param grant The wrapped key, permission and signature
   * @param keyGeneration Key generation the wrap belongs to
   */
  async grant(
    caller: Caller,
    vaultId: string,
    grant: NewGrant,
    keyGeneration: number,
  ): Promise<void> {
    await this.#context.store.transaction(async (repos) => {
      // Serialises access changes, so the manager check below sees every concurrent change
      await repos.changeFeed.lock();

      const { audit, users, vaults } = repos;
      const vault = await requireVaultPermission(
        vaults,
        vaultId,
        caller.userId,
        "manage",
      );

      if (vault.kind === "personal") {
        throw new DomainError(
          "invalid",
          "bad_request",
          "Personal vaults cannot be shared",
        );
      }

      if (keyGeneration !== vault.keyGeneration) {
        throw new DomainError(
          "conflict",
          "conflict",
          "Key generation is stale",
          {
            keyGeneration: vault.keyGeneration,
          },
        );
      }

      await requirePrincipal(repos, caller.orgId, grant);
      await requireGrantSignature(
        users,
        caller.userId,
        { ...grant, vaultId, keyGeneration },
        grant.grantSignature,
      );
      await vaults.putGrant(vaultId, grant, keyGeneration, caller.userId);

      // Downgrading the last manager would leave the vault with nobody able to manage it
      if (!(await vaults.hasManager(vaultId))) {
        throw new DomainError(
          "conflict",
          "conflict",
          "A vault must keep at least one manager",
        );
      }

      await audit.record({
        orgId: caller.orgId,
        actorId: caller.userId,
        action: "vault.access_granted",
        targetId: vaultId,
        detail: {
          principalId: grant.principalId,
          principalType: grant.principalType,
          permission: grant.permission,
        },
        ip: caller.ip,
      });
    });
  }

  /**
   * ### revoke
   *
   * Removes one principal's access without rotating the key.
   *
   * @param caller Managing member
   * @param vaultId Vault
   * @param principalId Member or group losing access
   */
  async revoke(
    caller: Caller,
    vaultId: string,
    principalId: string,
  ): Promise<void> {
    await this.#context.store.transaction(async (repos) => {
      // Serialises access changes, so the manager check below sees every concurrent change
      await repos.changeFeed.lock();

      const { audit, vaults } = repos;

      await requireVaultPermission(vaults, vaultId, caller.userId, "manage");

      if (
        (await vaults.leftWithoutManager(principalId, [vaultId])).length > 0
      ) {
        throw new DomainError(
          "conflict",
          "conflict",
          "A vault must keep at least one manager",
        );
      }

      await vaults.removeGrant(vaultId, principalId);
      await audit.record({
        orgId: caller.orgId,
        actorId: caller.userId,
        action: "vault.access_revoked",
        targetId: vaultId,
        detail: { principalId },
        ip: caller.ip,
      });
    });
  }

  /**
   * ### access
   *
   * Who can open a vault the caller manages, with each grant's wrap and signature so the
   * manager's client can tell grants it trusts from ones the server may have added.
   *
   * @param caller Managing member
   * @param vaultId Vault
   * @returns The grants
   */
  async access(
    caller: Caller,
    vaultId: string,
  ): Promise<
    Array<{
      principalType: VaultGrant["principalType"];
      principalId: string;
      permission: VaultPermission;
      wrappedKey: Uint8Array;
      keyGeneration: number;
      grantedBy: string | undefined;
      grantSignature: Uint8Array | undefined;
    }>
  > {
    const { vaults } = this.#context.store.repositories();

    await requireVaultPermission(vaults, vaultId, caller.userId, "manage");

    return vaults.grants(vaultId);
  }
}
