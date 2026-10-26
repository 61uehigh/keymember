/**
 * ### RateLimiter
 *
 * In-memory fixed-window counter for failed attempts, keyed by an arbitrary string
 * such as `login:<email>`. State is per process and lost on restart, which is acceptable
 * for a single-instance deployment; a multi-instance deployment needs a shared store.
 *
 * Memory stays bounded: expired windows are dropped as new ones start, and when the table is
 * full the oldest window goes, so a flood of distinct keys (random emails, spoofed addresses)
 * cannot grow it without limit.
 */
export class RateLimiter {
  readonly #windows = new Map<string, { count: number; resetAt: number }>();
  readonly #limit: number;
  readonly #windowMs: number;
  readonly #maxKeys: number;

  /**
   * ### constructor
   *
   * @param limit Failures allowed per window before {@link RateLimiter.isBlocked} returns true
   * @param windowMs Window length in milliseconds
   * @param maxKeys Most keys tracked at once
   */
  constructor(limit: number, windowMs: number, maxKeys = 100_000) {
    this.#limit = limit;
    this.#windowMs = windowMs;
    this.#maxKeys = maxKeys;
  }

  /**
   * ### size
   *
   * Number of keys tracked right now.
   */
  get size(): number {
    return this.#windows.size;
  }

  /**
   * ### isBlocked
   *
   * Whether the key has used up its failures for the current window.
   *
   * @param key Rate-limit key
   * @param now Current time in milliseconds
   * @returns Whether further attempts must be refused
   */
  isBlocked(key: string, now: number): boolean {
    const window = this.#windows.get(key);

    return (
      window !== undefined &&
      window.resetAt > now &&
      window.count >= this.#limit
    );
  }

  /**
   * ### recordFailure
   *
   * Counts one failure against the key, starting a new window when the previous one expired.
   *
   * @param key Rate-limit key
   * @param now Current time in milliseconds
   */
  recordFailure(key: string, now: number): void {
    const window = this.#windows.get(key);

    if (window !== undefined && window.resetAt > now) {
      window.count += 1;

      return;
    }

    // A new window goes to the end of the insertion order, which keeps the oldest first
    this.#windows.delete(key);
    this.#makeRoom(now);
    this.#windows.set(key, { count: 1, resetAt: now + this.#windowMs });
  }

  /**
   * ### #makeRoom
   *
   * Drops expired windows, then the oldest ones while the table is full. Every window lasts
   * equally long and new ones are appended, so the insertion order is also the expiry order
   * and only the front of the table needs looking at.
   *
   * @param now Current time in milliseconds
   */
  #makeRoom(now: number): void {
    for (const [key, window] of this.#windows) {
      if (window.resetAt > now && this.#windows.size < this.#maxKeys) {
        break;
      }

      this.#windows.delete(key);
    }
  }

  /**
   * ### reset
   *
   * Clears the key's failures, called after a successful attempt.
   *
   * @param key Rate-limit key
   */
  reset(key: string): void {
    this.#windows.delete(key);
  }
}
