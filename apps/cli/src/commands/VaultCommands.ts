import type { VaultPermission } from "@keymember/client";

import type { CommandDeps } from "./CommandDeps.js";
import {
  findMember,
  isPermission,
  resolveGroup,
  resolveVault,
} from "../lookups.js";

/**
 * ### VaultCommands
 *
 * Commands that list, create and share vaults and rotate their keys.
 */
export class VaultCommands {
  readonly #deps: CommandDeps;

  /**
   * ### constructor
   *
   * @param deps Terminal and session access
   */
  constructor(deps: CommandDeps) {
    this.#deps = deps;
  }

  /**
   * ### list
   *
   * Lists the vaults this user can open, then warns about managed vaults that need a new key.
   */
  async list(): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      await session.sync();

      const vaults = session.listVaults();

      for (const vault of vaults) {
        this.#deps.io.print(
          `${vault.id}\t${vault.kind}\t${vault.permission}\t${vault.name}`,
        );
      }

      for (const vault of vaults) {
        if (vault.rotationDue && vault.permission === "manage") {
          this.#deps.io.print(
            `! ${vault.name}: someone who could open it left; run \`keymember vault rotate ${vault.id}\``,
          );
        }
      }
    });
  }

  /**
   * ### create
   *
   * Creates a vault, optionally shared with members given as `email:permission` and groups
   * given as `group:permission`. A vault shared with nobody is personal.
   *
   * @param name Vault name
   * @param shares Members to share with, as `email:view|edit|manage`
   * @param groupShares Groups to share with, as `group name or id:view|edit|manage`
   */
  async create(
    name: string,
    shares: ReadonlyArray<string>,
    groupShares: ReadonlyArray<string> = [],
  ): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      const directory = await session.directory();
      const members = shares.map((share) => {
        const [email = "", permission = ""] = share.split(":");
        const member = directory.find(
          (candidate) => candidate.email === email.toLowerCase(),
        );

        if (member === undefined || !isPermission(permission)) {
          throw new Error(
            `Invalid share "${share}"; expected <member email>:view|edit|manage`,
          );
        }

        return { userId: member.userId, permission };
      });
      const groups = [];

      for (const share of groupShares) {
        const separator = share.lastIndexOf(":");
        const permission = share.slice(separator + 1);

        if (separator <= 0 || !isPermission(permission)) {
          throw new Error(
            `Invalid group share "${share}"; expected <group>:view|edit|manage`,
          );
        }

        groups.push({
          groupId: (await resolveGroup(session, share.slice(0, separator))).id,
          permission,
        });
      }

      const vaultId = await session.createVault(
        name,
        members.length === 0 && groups.length === 0 ? "personal" : "shared",
        members,
        groups,
      );

      this.#deps.io.print(vaultId);
    });
  }

  /**
   * ### share
   *
   * Grants or changes a member's or group's access to a vault.
   *
   * @param vaultRef Vault name or id
   * @param target Member's email, or the group name or id when `toGroup` is set
   * @param permission Access level
   * @param toGroup Whether `target` names a group
   */
  async share(
    vaultRef: string,
    target: string,
    permission: VaultPermission,
    toGroup = false,
  ): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      await session.sync();

      const vaultId = resolveVault(session, vaultRef);

      if (toGroup) {
        const group = await resolveGroup(session, target);

        await session.grantGroupAccess(vaultId, group.id, permission);
        this.#deps.io.print(`Shared with group ${group.name} (${permission})`);

        return;
      }

      const member = findMember(await session.directory(), target);

      await session.grantAccess(vaultId, member.userId, permission);
      this.#deps.io.print(`Shared with ${target} (${permission})`);
    });
  }

  /**
   * ### rotate
   *
   * Rotates a vault's key, optionally removing members in the same step.
   *
   * @param vaultRef Vault name or id
   * @param removeRefs Members (by email) or groups (by name or id) to remove
   */
  async rotate(
    vaultRef: string,
    removeRefs: ReadonlyArray<string>,
  ): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      await session.sync();

      const vaultId = resolveVault(session, vaultRef);
      const directory = await session.directory();
      const groups = await session.groups();
      const removeIds = removeRefs.map((ref) => {
        const id =
          directory.find((candidate) => candidate.email === ref.toLowerCase())
            ?.userId ??
          groups.find((group) => group.id === ref || group.name === ref)?.id;

        if (id === undefined) {
          throw new Error(`No member or group ${ref}`);
        }

        return id;
      });

      await session.rotateVaultKey(vaultId, removeIds);
      this.#deps.io.print("Vault key rotated");
    });
  }
}
