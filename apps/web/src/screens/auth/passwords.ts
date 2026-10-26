import { MIN_PASSWORD_LENGTH } from "./AuthCard.js";

/**
 * ### checkNewPassword
 *
 * Validates a new password and its confirmation.
 *
 * @param password New password
 * @param confirm Repeated password
 */
export function checkNewPassword(password: string, confirm: string): void {
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(
      `Password must be at least ${String(MIN_PASSWORD_LENGTH)} characters.`,
    );
  }

  if (password !== confirm) {
    throw new Error("Passwords don't match.");
  }
}

/**
 * ### deviceName
 *
 * Human-readable name for this browser, shown in audit logs.
 *
 * @returns A short browser description
 */
export function deviceName(): string {
  return `Web (${navigator.platform || "browser"})`;
}
