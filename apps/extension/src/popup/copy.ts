import { call } from "./background.js";

/**
 * ### copy
 *
 * Copies a value. The popup closes soon after, so the background clears the clipboard 30
 * seconds later, if it still holds this value.
 *
 * @param value Value to copy
 */
export async function copy(value: string): Promise<void> {
  await navigator.clipboard.writeText(value);
  await call({ type: "copied", value });
}
