/**
 * ### ChangeFeedRepository
 *
 * The change feed sync reads from: every write to items, grants, groups and group members
 * takes a new revision from one sequence. Every repository method that writes a revision takes
 * the ordering lock itself, so callers cannot forget it.
 */
export interface ChangeFeedRepository {
  /**
   * ### lock
   *
   * Takes the transaction-scoped lock that orders every write drawing from the change feed.
   * Writers holding it commit in revision order, so once a reader sees revision N committed,
   * every revision below N is committed too and `sync?since=N` can never skip a change.
   * Writes that take a revision take it themselves; call it first only to make earlier reads
   * in the transaction (such as permission checks) part of the same ordered section.
   */
  lock(): Promise<void>;

  /**
   * ### latestRevision
   *
   * The highest committed revision. Writers commit in revision order, so nothing below it is
   * still pending.
   *
   * @returns The revision
   */
  latestRevision(): Promise<number>;
}
