import type { Queryable } from "../../db/Database.js";

/**
 * ### CHANGE_FEED_LOCK
 *
 * Advisory lock key that orders every write sync can see.
 */
export const CHANGE_FEED_LOCK = 7311;

/**
 * ### lockChangeFeed
 *
 * Takes the transaction-scoped lock that orders writes drawing revisions from `change_seq`, so
 * they commit in revision order and `sync?since=N` can never skip a change. Every repository
 * method that writes a revision, or changes who can open a vault, takes it itself; taking it
 * again in the same transaction is free.
 *
 * @param db Transaction to lock in
 */
export async function lockChangeFeed(db: Queryable): Promise<void> {
  await db.query("SELECT pg_advisory_xact_lock($1)", [CHANGE_FEED_LOCK]);
}
