import type { ContentCommand } from "../shared/messages.js";
import { findLoginFields, isVisible } from "./detect.js";

/**
 * ### setValue
 *
 * Writes a value the way typing would: through the native setter, so frameworks that
 * patch `value` (React, Vue) see the change, followed by input and change events.
 *
 * @param input Field to fill
 * @param value Value to write
 */
export function setValue(input: HTMLInputElement, value: string): void {
  // The prototype's own setter, called with the input as `this`, bypasses framework value patches
  // eslint-disable-next-line @typescript-eslint/unbound-method
  const setter = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(input) as object,
    "value",
  )?.set;

  input.focus();

  if (setter === undefined) {
    input.value = value;
  } else {
    setter.call(input, value);
  }

  input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

/**
 * ### applyFill
 *
 * Fills the login fields around the focused input, after re-checking that the frame is still
 * on the URL the background matched against and that every target is visible. Signup forms
 * are never filled. A one-time code goes only into a detected code field.
 *
 * @param command Fill command from the background
 * @param focused Input the user last focused, if any
 * @param currentUrl This frame's current URL
 * @returns Number of fields filled
 */
export function applyFill(
  command: Extract<ContentCommand, { type: "fill" }>,
  focused: HTMLInputElement | undefined,
  currentUrl: string,
): number {
  if (currentUrl !== command.expectedUrl) {
    return 0;
  }

  const anchor = focused ?? firstLoginInput();

  if (anchor === undefined) {
    return 0;
  }

  const fields = findLoginFields(anchor);
  let filled = 0;

  if (fields.isSignup) {
    return 0;
  }

  const write = (
    input: HTMLInputElement | undefined,
    value: string | undefined,
  ): void => {
    if (input !== undefined && value !== undefined && isVisible(input)) {
      setValue(input, value);
      filled += 1;
    }
  };

  if (command.kind === "otp") {
    write(fields.otp, command.totp);

    return filled;
  }

  write(fields.username, command.username);
  write(fields.password, command.password);

  return filled;
}

/**
 * ### firstLoginInput
 *
 * The first visible password or user-name-looking input on the page, used when a fill comes
 * from the popup or the keyboard shortcut rather than from a focused field.
 *
 * @returns An input to anchor detection on, if any
 */
function firstLoginInput(): HTMLInputElement | undefined {
  const candidates = [
    ...document.querySelectorAll<HTMLInputElement>('input[type="password"]'),
    ...document.querySelectorAll<HTMLInputElement>(
      'input[autocomplete~="username"], input[type="email"]',
    ),
  ];

  return candidates.find((input) => isVisible(input));
}
