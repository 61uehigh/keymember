import type { Queryable } from "../../db/Database.js";
import { lockChangeFeed } from "./changeFeedLock.js";
import type {
  ItemCiphertext,
  ItemVersion,
  SyncedItem,
  ItemRepository,
} from "../ItemRepository.js";

/**
 * ### PgItemRepository
 *
 * {@link ItemRepository} on PostgreSQL.
 */
export class PgItemRepository implements ItemRepository {
  readonly #db: Queryable;

  /**
   * ### constructor
   *
   * @param db Connection or transaction to work in
   */
  constructor(db: Queryable) {
    this.#db = db;
  }

  /**
   * ### exists
   *
   * @see {@link ItemRepository.exists}
   */
  async exists(itemId: string): Promise<boolean> {
    return (
      (await this.#db.query("SELECT 1 FROM items WHERE id = $1", [itemId]))
        .length > 0
    );
  }

  /**
   * ### isLiveIn
   *
   * @see {@link ItemRepository.isLiveIn}
   */
  async isLiveIn(itemId: string, vaultId: string): Promise<boolean> {
    return (
      (
        await this.#db.query(
          "SELECT 1 FROM items WHERE id = $1 AND vault_id = $2 AND deleted_at IS NULL",
          [itemId, vaultId],
        )
      ).length > 0
    );
  }

  /**
   * ### insert
   *
   * @see {@link ItemRepository.insert}
   */
  async insert(item: ItemCiphertext, by: string, at: Date): Promise<number> {
    await lockChangeFeed(this.#db);

    const [row] = await this.#db.query<{ revision: string }>(
      `INSERT INTO items (id, vault_id, enc_item_key, enc_overview, enc_details, created_by, updated_by, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $6, $7)
       RETURNING revision`,
      [
        item.id,
        item.vaultId,
        item.encryptedItemKey,
        item.encryptedOverview,
        item.encryptedDetails,
        by,
        at,
      ],
    );

    return Number(row?.revision);
  }

  /**
   * ### lockLive
   *
   * @see {@link ItemRepository.lockLive}
   */
  async lockLive(itemId: string): Promise<ItemVersion | undefined> {
    const [row] = await this.#db.query<{
      vault_id: string;
      revision: string;
      deleted_at: Date | null;
    }>(
      "SELECT vault_id, revision, deleted_at FROM items WHERE id = $1 FOR UPDATE",
      [itemId],
    );

    // A missing row has no deleted_at, so this also covers an unknown id
    return row?.deleted_at !== null
      ? undefined
      : { vaultId: row.vault_id, revision: Number(row.revision) };
  }

  /**
   * ### replace
   *
   * @see {@link ItemRepository.replace}
   */
  async replace(item: ItemCiphertext, by: string, at: Date): Promise<number> {
    await lockChangeFeed(this.#db);

    // Members who see only the old vault learn from this row to drop their copy
    await this.#db.query(
      `INSERT INTO item_moves (item_id, from_vault_id)
       SELECT id, vault_id FROM items WHERE id = $1 AND vault_id <> $2`,
      [item.id, item.vaultId],
    );

    const [row] = await this.#db.query<{ revision: string }>(
      `UPDATE items
          SET vault_id = $2, enc_item_key = $3, enc_overview = $4, enc_details = $5,
              updated_by = $6, updated_at = $7, revision = nextval('change_seq')
        WHERE id = $1
        RETURNING revision`,
      [
        item.id,
        item.vaultId,
        item.encryptedItemKey,
        item.encryptedOverview,
        item.encryptedDetails,
        by,
        at,
      ],
    );

    return Number(row?.revision);
  }

  /**
   * ### markDeleted
   *
   * @see {@link ItemRepository.markDeleted}
   */
  async markDeleted(itemId: string, at: Date): Promise<void> {
    await lockChangeFeed(this.#db);

    await this.#db.query(
      "UPDATE items SET deleted_at = $2, revision = nextval('change_seq') WHERE id = $1",
      [itemId, at],
    );
  }

  /**
   * ### lockLiveInVault
   *
   * @see {@link ItemRepository.lockLiveInVault}
   */
  async lockLiveInVault(
    vaultId: string,
  ): Promise<Array<{ id: string; revision: number }>> {
    const rows = await this.#db.query<{ id: string; revision: string }>(
      "SELECT id, revision FROM items WHERE vault_id = $1 AND deleted_at IS NULL FOR UPDATE",
      [vaultId],
    );

    return rows.map((row) => ({ id: row.id, revision: Number(row.revision) }));
  }

  /**
   * ### reencrypt
   *
   * @see {@link ItemRepository.reencrypt}
   */
  async reencrypt(
    item: Omit<ItemCiphertext, "vaultId">,
    by: string,
    at: Date,
  ): Promise<void> {
    await lockChangeFeed(this.#db);

    await this.#db.query(
      `UPDATE items
          SET enc_item_key = $2, enc_overview = $3, enc_details = $4,
              updated_by = $5, updated_at = $6, revision = nextval('change_seq')
        WHERE id = $1`,
      [
        item.id,
        item.encryptedItemKey,
        item.encryptedOverview,
        item.encryptedDetails,
        by,
        at,
      ],
    );
  }

  /**
   * ### changesForSync
   *
   * @see {@link ItemRepository.changesForSync}
   */
  async changesForSync(
    vaultIds: ReadonlyArray<string>,
    since: number,
    wholeVaultIds: ReadonlyArray<string>,
  ): Promise<Array<SyncedItem>> {
    const rows = await this.#db.query<{
      id: string;
      vault_id: string;
      enc_item_key: Uint8Array;
      enc_overview: Uint8Array;
      enc_details: Uint8Array;
      revision: string;
      deleted_at: Date | null;
    }>(
      `SELECT id, vault_id, enc_item_key, enc_overview, enc_details, revision, deleted_at
         FROM items
        WHERE vault_id = ANY($1::text[]) AND (revision > $2 OR vault_id = ANY($3::text[]))
        ORDER BY revision`,
      [[...vaultIds], since, [...wholeVaultIds]],
    );

    const changed = rows.map((row): SyncedItem =>
      row.deleted_at === null
        ? {
            deleted: false,
            id: row.id,
            vaultId: row.vault_id,
            revision: Number(row.revision),
            encryptedItemKey: row.enc_item_key,
            encryptedOverview: row.enc_overview,
            encryptedDetails: row.enc_details,
          }
        : {
            deleted: true,
            id: row.id,
            vaultId: row.vault_id,
            revision: Number(row.revision),
          },
    );
    const moved = await this.#db.query<{
      item_id: string;
      from_vault_id: string;
      revision: string;
    }>(
      `SELECT DISTINCT ON (m.item_id) m.item_id, m.from_vault_id, m.revision
         FROM item_moves m JOIN items i ON i.id = m.item_id
        WHERE m.from_vault_id = ANY($1::text[]) AND m.revision > $2
          AND NOT (i.vault_id = ANY($1::text[]))
        ORDER BY m.item_id, m.revision DESC`,
      [[...vaultIds], since],
    );

    // An item moved into a vault the caller cannot see is, for the caller, deleted
    return [
      ...changed,
      ...moved.map((row): SyncedItem => ({
        deleted: true,
        id: row.item_id,
        vaultId: row.from_vault_id,
        revision: Number(row.revision),
      })),
    ].sort((left, right) => left.revision - right.revision);
  }
}
