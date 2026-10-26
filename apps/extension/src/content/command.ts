import type { ContentCommand, FieldKind } from "../shared/messages.js";
import { isRecord } from "../shared/records.js";

const KINDS: ReadonlySet<string> = new Set<FieldKind>([
  "username",
  "password",
  "otp",
]);

/**
 * ### optionalString
 *
 * Reads an optional string property, rejecting any other type.
 *
 * @param record Message object
 * @param key Property name
 * @returns `[ok, value]`: `ok` is false when the property exists but is not a string
 */
function optionalString(
  record: Record<string, unknown>,
  key: string,
): [boolean, string | undefined] {
  const value = record[key];

  return value === undefined
    ? [true, undefined]
    : typeof value === "string"
      ? [true, value]
      : [false, undefined];
}

/**
 * ### parseContentCommand
 *
 * Validates a command from the background without a schema library, because the content
 * script is injected into every page and must stay small.
 *
 * @param message Message received by the content script
 * @returns The command, or `undefined` when the message is not a valid command
 */
export function parseContentCommand(
  message: unknown,
): ContentCommand | undefined {
  if (!isRecord(message)) {
    return undefined;
  }

  const record = message;

  if (record.type === "close-menu") {
    return { type: "close-menu" };
  }

  if (record.type !== "fill" || typeof record.expectedUrl !== "string") {
    return undefined;
  }

  const [kindOk, kind] = optionalString(record, "kind");
  const [userOk, username] = optionalString(record, "username");
  const [passOk, password] = optionalString(record, "password");
  const [totpOk, totp] = optionalString(record, "totp");

  if (
    !kindOk ||
    !userOk ||
    !passOk ||
    !totpOk ||
    (kind !== undefined && !KINDS.has(kind))
  ) {
    return undefined;
  }

  return {
    type: "fill",
    expectedUrl: record.expectedUrl,
    // KINDS.has narrowed kind to a field kind
    ...(kind === undefined ? {} : { kind: kind as FieldKind }),
    ...(username === undefined ? {} : { username }),
    ...(password === undefined ? {} : { password }),
    ...(totp === undefined ? {} : { totp }),
  };
}
