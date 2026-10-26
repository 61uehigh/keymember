import type { Store } from "../repositories/Store.js";

/**
 * ### ServiceContext
 *
 * What every service needs: where data is kept, and the clock.
 */
export interface ServiceContext {
  /**
   * ### store
   *
   * Where the server keeps its data.
   */
  readonly store: Store;

  /**
   * ### now
   *
   * Clock, injectable so tests can control time.
   */
  readonly now: () => Date;
}
