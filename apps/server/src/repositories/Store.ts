import type { Repositories } from "./Repositories.js";

/**
 * ### Store
 *
 * Where the server keeps its data. Routes reach every table through the repositories a store
 * hands out, so the same routes run on PostgreSQL, PGlite or Firestore.
 */
export interface Store {
  /**
   * ### repositories
   *
   * Repositories outside any transaction, for single reads and writes that need no atomicity.
   *
   * @returns The repositories
   */
  repositories(): Repositories;

  /**
   * ### transaction
   *
   * Runs `work` atomically: every write through the given repositories commits together when it
   * resolves and none does when it throws. A store may run `work` more than once when it
   * conflicts with another transaction, so `work` must not have effects outside the store.
   *
   * @param work Work to run against the transaction's repositories
   * @returns Whatever `work` resolves to
   */
  transaction<T>(work: (repositories: Repositories) => Promise<T>): Promise<T>;

  /**
   * ### snapshot
   *
   * Runs read-only `work` against one consistent, committed state of the store, without
   * holding up writers. For reads that must agree with each other, such as a sync's revision
   * and its rows. `work` must not write.
   *
   * @param work Reads to run against the snapshot's repositories
   * @returns Whatever `work` resolves to
   */
  snapshot<T>(work: (repositories: Repositories) => Promise<T>): Promise<T>;
}
