import { createHash } from "node:crypto";

import type { Clipboard } from "./platform.js";

/**
 * ### CLIPBOARD_CLEAR_MS
 *
 * How long a copied secret stays on the clipboard: 30 seconds.
 */
export const CLIPBOARD_CLEAR_MS = 30_000;

/**
 * ### sha256
 *
 * Hex SHA-256 of a string; the guard remembers this, never the secret itself.
 *
 * @param text Text to hash
 * @returns The digest
 */
function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

/**
 * ### ClipboardGuard
 *
 * Puts secrets on the clipboard and takes them off again: after a delay, or when asked (on
 * lock and quit), but only while the clipboard still holds that secret, so something the user
 * copied in between is left alone.
 */
export class ClipboardGuard {
  readonly #clipboard: Clipboard;
  readonly #delayMs: number;
  // Clears now if the clipboard still holds the last copied secret; set while one is pending
  #pending: (() => Promise<void>) | undefined;

  /**
   * ### constructor
   *
   * @param clipboard The system clipboard
   * @param delayMs How long a secret may stay
   */
  constructor(clipboard: Clipboard, delayMs: number = CLIPBOARD_CLEAR_MS) {
    this.#clipboard = clipboard;
    this.#delayMs = delayMs;
  }

  /**
   * ### copy
   *
   * Copies a secret and schedules its removal, replacing any removal still pending.
   *
   * @param value Secret to copy
   */
  copy(value: string): void {
    const expected = sha256(value);
    const clear = async (): Promise<void> => {
      clearTimeout(timer);
      this.#pending = undefined;

      if (sha256(await this.#clipboard.read()) === expected) {
        this.#clipboard.write("");
      }
    };
    const timer = setTimeout(() => {
      // Nothing waits on the timer; a clipboard that cannot be read is left as it is
      clear().catch(() => undefined);
    }, this.#delayMs);

    this.#clipboard.write(value);
    // The previous secret is replaced by this one, so its pending removal is moot
    this.#pending?.().catch(() => undefined);
    this.#pending = clear;
  }

  /**
   * ### clearIfUnchanged
   *
   * Empties the clipboard now if it still holds the last copied secret.
   *
   * @returns When the clipboard has been checked and, if needed, emptied
   */
  async clearIfUnchanged(): Promise<void> {
    await this.#pending?.();
  }
}
