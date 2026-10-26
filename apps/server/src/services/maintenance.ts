import type { Store } from "../repositories/Store.js";

/**
 * ### MAINTENANCE_INTERVAL_MS
 *
 * How often expired records are removed: hourly.
 */
const MAINTENANCE_INTERVAL_MS = 60 * 60 * 1000;

/**
 * ### PURGE_PAGE
 *
 * Records removed per batch, so one run never holds a long transaction.
 */
const PURGE_PAGE = 200;

/**
 * ### purgeExpired
 *
 * Removes expired token pairs in batches until none are left. Runs off the request path, so
 * requests never pay for the cleanup; challenges, tickets and share ciphertext are cleared a
 * page at a time as new ones are written.
 *
 * @param store Where data is kept
 * @param now Current time
 * @returns How many token pairs were removed
 */
export async function purgeExpired(store: Store, now: Date): Promise<number> {
  let removed = 0;

  for (;;) {
    const batch = await store
      .repositories()
      .sessions.purgeExpired(now, PURGE_PAGE);

    removed += batch;

    if (batch < PURGE_PAGE) {
      return removed;
    }
  }
}

/**
 * ### startMaintenance
 *
 * Runs {@link purgeExpired} now and every hour while the server is up. The timer does not keep
 * the process alive.
 *
 * @param store Where data is kept
 * @param onError Reports a failed run; the next run tries again
 * @returns Stops the timer
 */
export function startMaintenance(
  store: Store,
  onError: (error: unknown) => void,
): () => void {
  const run = (): void => {
    purgeExpired(store, new Date()).catch(onError);
  };
  const timer = setInterval(run, MAINTENANCE_INTERVAL_MS);

  timer.unref();
  run();

  return () => {
    clearInterval(timer);
  };
}
