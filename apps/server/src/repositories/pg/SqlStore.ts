import type { Database } from "../../db/Database.js";
import type { Repositories } from "../Repositories.js";
import type { Store } from "../Store.js";
import { pgRepositories } from "./pgRepositories.js";

/**
 * ### SqlStore
 *
 * {@link Store} on PostgreSQL or PGlite. The caller migrates and closes the database.
 */
export class SqlStore implements Store {
  readonly #db: Database;

  /**
   * ### constructor
   *
   * @param db Migrated database
   */
  constructor(db: Database) {
    this.#db = db;
  }

  /**
   * ### repositories
   *
   * @see {@link Store.repositories}
   */
  repositories(): Repositories {
    return pgRepositories(this.#db);
  }

  /**
   * ### transaction
   *
   * @see {@link Store.transaction}
   */
  transaction<T>(work: (repositories: Repositories) => Promise<T>): Promise<T> {
    return this.#db.transaction((tx) => work(pgRepositories(tx)));
  }

  /**
   * ### snapshot
   *
   * @see {@link Store.snapshot}
   */
  snapshot<T>(work: (repositories: Repositories) => Promise<T>): Promise<T> {
    return this.#db.snapshot((tx) => work(pgRepositories(tx)));
  }
}
