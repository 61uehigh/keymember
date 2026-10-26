const CLEAR_AFTER_MS = 30_000;

/**
 * ### pending
 *
 * The secret waiting to be cleared, and its timer.
 */
let pending: { value: string; timer: number } | undefined;

/**
 * ### copySecret
 *
 * Copies a value and clears the clipboard after 30 seconds if it still holds that value.
 * When the browser does not let the page read the clipboard, it is cleared regardless,
 * because leaving a password there is the worse outcome than losing something copied later.
 *
 * @param value Secret to copy
 */
export async function copySecret(value: string): Promise<void> {
  await navigator.clipboard.writeText(value);

  if (pending !== undefined) {
    window.clearTimeout(pending.timer);
  }

  pending = {
    value,
    timer: window.setTimeout(() => {
      clearCopiedSecret();
    }, CLEAR_AFTER_MS),
  };
}

/**
 * ### clearCopiedSecret
 *
 * Clears a secret copied with {@link copySecret} now rather than when its timer runs out, as
 * locking does. Does nothing when no copied secret is waiting.
 */
export function clearCopiedSecret(): void {
  if (pending === undefined) {
    return;
  }

  const { value, timer } = pending;

  window.clearTimeout(timer);
  pending = undefined;
  void clearIfStill(value);
}

/**
 * ### clearIfStill
 *
 * Empties the clipboard if it still holds `value`, or if the page may not read it.
 *
 * @param value Secret that was copied
 */
async function clearIfStill(value: string): Promise<void> {
  try {
    if ((await navigator.clipboard.readText()) !== value) {
      return;
    }
  } catch {
    // Reading needs permission; without it we cannot tell, so clear anyway
  }

  try {
    await navigator.clipboard.writeText("");
  } catch {
    // The page lost focus; browsers refuse clipboard writes then, and nothing else can be done
  }
}
