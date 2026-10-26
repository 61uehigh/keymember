import type { Caller } from "../../domain/Caller.js";
import { DomainError } from "../../domain/DomainError.js";
import type { ServiceContext } from "../ServiceContext.js";

/**
 * ### Exposure
 *
 * What a suspended member could open, so admins know which keys to rotate: each shared vault
 * with the members who can rotate it, and each group.
 */
export interface Exposure {
  readonly vaults: Array<{ vaultId: string; managerIds: Array<string> }>;
  readonly groups: Array<string>;
}

/**
 * ### Offboarding
 *
 * Cutting a member off: their logins, access, group copies, recoveries, invites and share links
 * end at once. Rotating the keys they held is left to the vault managers and admins.
 */
export class Offboarding {
  readonly #context: ServiceContext;

  /**
   * ### constructor
   *
   * @param context Storage and clock
   */
  constructor(context: ServiceContext) {
    this.#context = context;
  }

  /**
   * ### suspend
   *
   * Suspends a member of the caller's organisation other than the owner and the caller.
   *
   * @param caller Suspending admin
   * @param userId Member to suspend
   * @returns What the member could open
   */
  async suspend(caller: Caller, userId: string): Promise<Exposure> {
    if (userId === caller.userId) {
      throw new DomainError(
        "invalid",
        "bad_request",
        "Admins cannot suspend themselves",
      );
    }

    return this.#context.store.transaction(async (repositories) => {
      const now = this.#context.now();
      const role = await repositories.memberships.lockRole(
        caller.orgId,
        userId,
      );

      if (role === undefined) {
        throw new DomainError("not_found", "not_found", "No such member");
      }

      if (role === "owner") {
        throw new DomainError(
          "forbidden",
          "forbidden",
          "The owner cannot be suspended",
        );
      }

      await repositories.memberships.suspend(caller.orgId, userId);
      await repositories.sessions.revokeAll(userId, now);

      // What the member could open, recorded before their access rows go away. Their own
      // personal vault is left out: nobody else can open it, so there is nothing to rotate
      const groups = await repositories.groups.liveGroupsOf(userId);
      const vaults = await repositories.vaults.flagForRotation(
        userId,
        groups,
        now,
      );
      const managers = await repositories.vaults.managers(vaults, userId);

      // Removing access stops delivery; rotating the vault keys afterwards is the managers' job (crypto.md §5)
      await repositories.vaults.removeUserGrants(userId);
      // Their group copies go too; rotating those groups' keys is likewise the admins' job
      await repositories.groups.removeFromAll(userId);
      // Recoveries for them must not bring them back, and ones they started as an admin end too
      await repositories.recoveries.cancelInvolving(userId, now);
      // Invites they made that nobody used yet stop working
      await repositories.invites.expireAllBy(userId, now);

      // Links they sent that nobody opened yet close too
      const sharesClosed = await repositories.shares.revokeAllBy(userId, now);

      await repositories.audit.record({
        orgId: caller.orgId,
        actorId: caller.userId,
        action: "org.member_suspended",
        targetId: userId,
        detail: {
          vaults: vaults.length,
          groups: groups.length,
          shares: sharesClosed,
        },
        ip: caller.ip,
      });

      return {
        vaults: vaults
          .map((vaultId) => ({
            vaultId,
            managerIds: managers
              .filter((manager) => manager.vaultId === vaultId)
              .map((manager) => manager.userId)
              .sort(),
          }))
          .sort((a, b) => a.vaultId.localeCompare(b.vaultId)),
        groups,
      };
    });
  }
}
