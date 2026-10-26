/**
 * ### ItemCiphertext
 *
 * An item as the client uploads it: everything but the ids is ciphertext the server cannot read.
 */
export interface ItemCiphertext {
  readonly id: string;
  readonly vaultId: string;
  readonly encryptedItemKey: Uint8Array;
  readonly encryptedOverview: Uint8Array;
  readonly encryptedDetails: Uint8Array;
}

/**
 * ### ItemVersion
 *
 * Where a live item is and which change-feed revision it is at.
 */
export interface ItemVersion {
  readonly vaultId: string;
  readonly revision: number;
}

/**
 * ### SyncedItem
 *
 * An item as sync reports it: its ciphertext, or `deleted` when it went to the trash.
 */
export type SyncedItem =
  | ({ readonly deleted: false; readonly revision: number } & ItemCiphertext)
  | {
      readonly deleted: true;
      readonly id: string;
      readonly vaultId: string;
      readonly revision: number;
    };

/**
 * ### ItemRepository
 *
 * Storage of encrypted items. Every write takes a new change-feed revision, so clients can
 * sync from the last one they saw and edits can be checked against the revision they started
 * from.
 */
export interface ItemRepository {
  /**
   * ### exists
   *
   * Whether an item id is taken, by a live or a deleted item.
   *
   * @param itemId Item id
   * @returns Whether it exists
   */
  exists(itemId: string): Promise<boolean>;

  /**
   * ### isLiveIn
   *
   * Whether a live (not deleted) item is in the given vault.
   *
   * @param itemId Item id
   * @param vaultId Vault it must be in
   * @returns Whether it is
   */
  isLiveIn(itemId: string, vaultId: string): Promise<boolean>;

  /**
   * ### insert
   *
   * Stores a new item.
   *
   * @param item Ciphertext and ids
   * @param by User creating it
   * @param at Time of creation
   * @returns The item's revision
   */
  insert(item: ItemCiphertext, by: string, at: Date): Promise<number>;

  /**
   * ### lockLive
   *
   * Locks a live item for a change within the current transaction.
   *
   * @param itemId Item id
   * @returns Its vault and revision, or `undefined` when missing or deleted
   */
  lockLive(itemId: string): Promise<ItemVersion | undefined>;

  /**
   * ### replace
   *
   * Overwrites an item's ciphertext, possibly in another vault.
   *
   * @param item New ciphertext and target vault
   * @param by User changing it
   * @param at Time of the change
   * @returns The item's new revision
   */
  replace(item: ItemCiphertext, by: string, at: Date): Promise<number>;

  /**
   * ### markDeleted
   *
   * Moves an item to the trash; sync reports it as deleted.
   *
   * @param itemId Item id
   * @param at Time of deletion
   */
  markDeleted(itemId: string, at: Date): Promise<void>;

  /**
   * ### lockLiveInVault
   *
   * Locks every live item of a vault, as a key rotation must re-encrypt them all.
   *
   * @param vaultId Vault
   * @returns Their ids and revisions
   */
  lockLiveInVault(
    vaultId: string,
  ): Promise<Array<{ id: string; revision: number }>>;

  /**
   * ### reencrypt
   *
   * Replaces an item's ciphertext in place, as a key rotation does.
   *
   * @param item New ciphertext
   * @param by User rotating
   * @param at Time of the rotation
   */
  reencrypt(
    item: Omit<ItemCiphertext, "vaultId">,
    by: string,
    at: Date,
  ): Promise<void>;

  /**
   * ### changesForSync
   *
   * Items of the given vaults changed after a revision, plus every item of the vaults the
   * caller has only just gained access to, in revision order.
   *
   * @param vaultIds Vaults the caller can open
   * @param since Revision the caller last saw
   * @param wholeVaultIds Vaults to send in full
   * @returns The items, deleted ones without ciphertext
   */
  changesForSync(
    vaultIds: ReadonlyArray<string>,
    since: number,
    wholeVaultIds: ReadonlyArray<string>,
  ): Promise<Array<SyncedItem>>;
}
