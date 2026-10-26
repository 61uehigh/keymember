import { encryptItem, openItemKey } from "@keymember/core";
import type { ItemDetails, ItemOverview } from "@keymember/core";

import type { AuthorizedRequest } from "./AuthorizedApi.js";
import { itemRequestBody } from "./VaultCache.js";
import type { VaultCache } from "./VaultCache.js";

/**
 * ### ItemWriter
 *
 * Creates, changes and deletes items: encrypts them under their vault's key, uploads them
 * against the revision last synced, and syncs again so the cache shows the result.
 */
export class ItemWriter {
  readonly #request: AuthorizedRequest;
  readonly #cache: Pick<VaultCache, "item" | "sync" | "vault">;

  /**
   * ### constructor
   *
   * @param request Authenticated requests to the server
   * @param cache The session's vaults and items
   */
  constructor(
    request: AuthorizedRequest,
    cache: Pick<VaultCache, "item" | "sync" | "vault">,
  ) {
    this.#request = request;
    this.#cache = cache;
  }

  /**
   * ### create
   *
   * Encrypts and uploads a new item.
   *
   * @param vaultId Vault to store the item in
   * @param overview Listing fields
   * @param details Secret fields
   * @returns The new item id
   */
  async create(
    vaultId: string,
    overview: ItemOverview,
    details: ItemDetails,
  ): Promise<string> {
    const itemId = crypto.randomUUID();
    const encrypted = encryptItem(
      this.#cache.vault(vaultId).key,
      { vaultId, itemId },
      overview,
      details,
    );

    await this.#request({
      method: "POST",
      path: "/api/items",
      body: itemRequestBody(encrypted),
    });
    await this.#cache.sync();

    return itemId;
  }

  /**
   * ### update
   *
   * Re-encrypts and uploads an item, optionally moving it to another vault. Fails with an
   * `ApiError` coded `revision_conflict` when someone else changed it since the last sync.
   *
   * @param itemId Item to update
   * @param overview New listing fields
   * @param details New secret fields
   * @param targetVaultId Vault to move the item to; omit to keep it where it is
   */
  async update(
    itemId: string,
    overview: ItemOverview,
    details: ItemDetails,
    targetVaultId?: string,
  ): Promise<void> {
    const item = this.#cache.item(itemId);
    const itemKey = openItemKey(
      this.#cache.vault(item.encrypted.vaultId).key,
      item.encrypted,
    );
    const vaultId = targetVaultId ?? item.encrypted.vaultId;
    // Moving to another vault gets a fresh item key: members of the old vault may know the old one
    const moving = vaultId !== item.encrypted.vaultId;
    const encrypted = encryptItem(
      this.#cache.vault(vaultId).key,
      { vaultId, itemId },
      overview,
      details,
      moving ? undefined : itemKey,
    );

    await this.#request({
      method: "PUT",
      path: `/api/items/${itemId}`,
      body: { ...itemRequestBody(encrypted), baseRevision: item.revision },
    });
    await this.#cache.sync();
  }

  /**
   * ### delete
   *
   * Moves an item to the trash.
   *
   * @param itemId Item to delete
   */
  async delete(itemId: string): Promise<void> {
    const item = this.#cache.item(itemId);

    await this.#request({
      method: "DELETE",
      path: `/api/items/${itemId}?baseRevision=${String(item.revision)}`,
    });
    await this.#cache.sync();
  }
}
