/**
 * ### isRecord
 *
 * Whether a value received from another context (a message, a page event, a response) is an
 * object whose fields can be checked one by one. Nothing about the fields is assumed.
 *
 * @param value Value as received
 * @returns Whether it is a non-null object
 */
export function isRecord(
  value: unknown,
): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null;
}
