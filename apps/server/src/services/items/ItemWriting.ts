import type { Caller } from "../../domain/Caller.js";
import { DomainError } from "../../domain/DomainError.js";
import type { ItemCiphertext } from "../../repositories/ItemRepository.js";
import type { ServiceContext } from "../ServiceContext.js";
import { requireVaultPermission } from "../vaultAccess.js";

/**
 * ### ItemWriting
 *
 * Creating, changing and deleting items. Changes and deletions carry the revision the client
 * last saw and fail with a revision conflict when someone else changed the item first (ADR-008).
 */
export class ItemWriting {
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
   * Stores a new item in a vault the caller may edit.
   *
   * @param caller Member creating the item
   * @param item The encrypted item, with its client-chosen id
   * @returns The item's revision
   */
  create(caller: Caller, item: ItemCiphertext): Promise<number> {
    return this.#context.store.transaction(async (repos) => {
      const { audit, items, vaults } = repos;

      await requireVaultPermission(vaults, item.vaultId, caller.userId, "edit");

      if (await items.exists(item.id)) {
        throw new DomainError("conflict", "conflict", "Item id already exists");
      }

      const revision = await items.insert(
        item,
        caller.userId,
        this.#context.now(),
      );

      await audit.record({
        orgId: caller.orgId,
        actorId: caller.userId,
        action: "item.created",
        targetId: item.id,
        detail: { vaultId: item.vaultId },
        ip: caller.ip,
      });

      return revision;
    });
  }

  /**
   * ### update
   *
   * Replaces an item, possibly moving it to another vault the caller may edit.
   *
   * @param caller Member changing the item
   * @param item The new encrypted item
   * @param baseRevision Revision the caller last saw
   * @returns The item's new revision
   */
  update(
    caller: Caller,
    item: ItemCiphertext,
    baseRevision: number,
  ): Promise<number> {
    return this.#context.store.transaction(async (repos) => {
      const { audit, items, vaults } = repos;
      const current = await items.lockLive(item.id);

      if (current === undefined) {
        throw new DomainError("not_found", "not_found", "No such item");
      }

      await requireVaultPermission(
        vaults,
        current.vaultId,
        caller.userId,
        "edit",
      );

      // Moving an item needs edit rights on the destination as well
      if (item.vaultId !== current.vaultId) {
        await requireVaultPermission(
          vaults,
          item.vaultId,
          caller.userId,
          "edit",
        );
      }

      requireRevision(current.revision, baseRevision);

      const revision = await items.replace(
        item,
        caller.userId,
        this.#context.now(),
      );

      await audit.record({
        orgId: caller.orgId,
        actorId: caller.userId,
        action: "item.updated",
        targetId: item.id,
        detail: {
          vaultId: item.vaultId,
          moved: item.vaultId !== current.vaultId,
        },
        ip: caller.ip,
      });

      return revision;
    });
  }

  /**
   * ### delete
   *
   * Moves an item to the trash.
   *
   * @param caller Member deleting the item
   * @param itemId Item to delete
   * @param baseRevision Revision the caller last saw
   */
  async delete(
    caller: Caller,
    itemId: string,
    baseRevision: number,
  ): Promise<void> {
    await this.#context.store.transaction(async (repos) => {
      const { audit, items, vaults } = repos;
      const current = await items.lockLive(itemId);

      if (current === undefined) {
        throw new DomainError("not_found", "not_found", "No such item");
      }

      await requireVaultPermission(
        vaults,
        current.vaultId,
        caller.userId,
        "edit",
      );
      requireRevision(current.revision, baseRevision);
      await items.markDeleted(itemId, this.#context.now());
      await audit.record({
        orgId: caller.orgId,
        actorId: caller.userId,
        action: "item.deleted",
        targetId: itemId,
        detail: { vaultId: current.vaultId },
        ip: caller.ip,
      });
    });
  }
}

/**
 * ### requireRevision
 *
 * Refuses a change made against a revision that is no longer current.
 *
 * @param current The item's current revision
 * @param base Revision the caller last saw
 */
function requireRevision(current: number, base: number): void {
  if (current !== base) {
    throw new DomainError(
      "conflict",
      "revision_conflict",
      "Item was changed by someone else; sync and retry",
      { currentRevision: current },
    );
  }
}
