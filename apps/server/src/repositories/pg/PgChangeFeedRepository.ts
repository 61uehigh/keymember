import type { Queryable } from "../../db/Database.js";
import type { ChangeFeedRepository } from "../ChangeFeedRepository.js";
import { lockChangeFeed } from "./changeFeedLock.js";

/**
 * ### PgChangeFeedRepository
 *
 * {@link ChangeFeedRepository} on PostgreSQL.
 */
export class PgChangeFeedRepository implements ChangeFeedRepository {
  readonly #db: Queryable;

  /**
   * ### constructor
   *
   * @param db Transaction to work in
   */
  constructor(db: Queryable) {
    this.#db = db;
  }

  /**
   * ### lock
   *
   * @see {@link ChangeFeedRepository.lock}
   */
  async lock(): Promise<void> {
    await lockChangeFeed(this.#db);
  }

  /**
   * ### latestRevision
   *
   * @see {@link ChangeFeedRepository.latestRevision}
   */
  async latestRevision(): Promise<number> {
    const [row] = await this.#db.query<{ revision: string }>(
      `SELECT GREATEST(
         COALESCE((SELECT MAX(revision) FROM items), 0),
         COALESCE((SELECT MAX(revision) FROM vault_access), 0),
         COALESCE((SELECT MAX(revision) FROM group_members), 0),
         COALESCE((SELECT MAX(revision) FROM groups), 0),
         COALESCE((SELECT MAX(revision) FROM vaults), 0),
         COALESCE((SELECT MAX(revision) FROM item_moves), 0)
       ) AS revision`,
    );

    return Number(row?.revision ?? "0");
  }
}
