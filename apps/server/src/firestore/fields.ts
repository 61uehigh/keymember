import type { DocumentData } from "./Documents.js";

/**
 * ### CorruptDocumentError
 *
 * A stored document lacks a field or holds the wrong type in it. Only the server writes these
 * documents, so this means a bug or a hand-edited database.
 */
export class CorruptDocumentError extends Error {
  /**
   * ### constructor
   *
   * @param field Field that was missing or of the wrong type
   * @param expected Type it should have held
   */
  constructor(field: string, expected: string) {
    super(`Stored field "${field}" is not ${expected}`);
    this.name = "CorruptDocumentError";
  }
}

/**
 * ### text
 *
 * Reads a string field.
 *
 * @param data Document fields
 * @param field Field name
 * @returns The string
 */
export function text(data: DocumentData, field: string): string {
  const value = data[field];

  if (typeof value !== "string") {
    throw new CorruptDocumentError(field, "a string");
  }

  return value;
}

/**
 * ### optionalText
 *
 * Reads a string field that may be `null`. A field missing from documents written before it
 * existed reads as `null` too.
 *
 * @param data Document fields
 * @param field Field name
 * @returns The string, or `undefined` for `null`
 */
export function optionalText(
  data: DocumentData,
  field: string,
): string | undefined {
  return (data[field] ?? null) === null ? undefined : text(data, field);
}

/**
 * ### flag
 *
 * Reads a boolean field.
 *
 * @param data Document fields
 * @param field Field name
 * @returns The boolean
 */
export function flag(data: DocumentData, field: string): boolean {
  const value = data[field];

  if (typeof value !== "boolean") {
    throw new CorruptDocumentError(field, "a boolean");
  }

  return value;
}

/**
 * ### date
 *
 * Reads a date field.
 *
 * @param data Document fields
 * @param field Field name
 * @returns The date
 */
export function date(data: DocumentData, field: string): Date {
  const value = data[field];

  if (!(value instanceof Date)) {
    throw new CorruptDocumentError(field, "a date");
  }

  return value;
}

/**
 * ### optionalDate
 *
 * Reads a date field that may be `null`.
 *
 * @param data Document fields
 * @param field Field name
 * @returns The date, or `undefined` for `null`
 */
export function optionalDate(
  data: DocumentData,
  field: string,
): Date | undefined {
  return (data[field] ?? null) === null ? undefined : date(data, field);
}

/**
 * ### bytes
 *
 * Reads a bytes field.
 *
 * @param data Document fields
 * @param field Field name
 * @returns The bytes
 */
export function bytes(data: DocumentData, field: string): Uint8Array {
  const value = data[field];

  if (!(value instanceof Uint8Array)) {
    throw new CorruptDocumentError(field, "bytes");
  }

  return value;
}

/**
 * ### optionalBytes
 *
 * Reads a bytes field that may be `null`.
 *
 * @param data Document fields
 * @param field Field name
 * @returns The bytes, or `undefined` for `null`
 */
export function optionalBytes(
  data: DocumentData,
  field: string,
): Uint8Array | undefined {
  return (data[field] ?? null) === null ? undefined : bytes(data, field);
}

/**
 * ### integer
 *
 * Reads a number field.
 *
 * @param data Document fields
 * @param field Field name
 * @returns The number
 */
export function integer(data: DocumentData, field: string): number {
  const value = data[field];

  if (typeof value !== "number") {
    throw new CorruptDocumentError(field, "a number");
  }

  return value;
}

/**
 * ### optionalInteger
 *
 * Reads a number field that may be `null`.
 *
 * @param data Document fields
 * @param field Field name
 * @returns The number, or `undefined` for `null`
 */
export function optionalInteger(
  data: DocumentData,
  field: string,
): number | undefined {
  return (data[field] ?? null) === null ? undefined : integer(data, field);
}

/**
 * ### compareText
 *
 * Orders strings by UTF-16 code unit, like PostgreSQL's `C` collation, for sorting in memory.
 *
 * @param left One string
 * @param right The other string
 * @returns Negative, zero or positive, as `Array.prototype.sort` expects
 */
export function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
