import { decode, encode, rfc8949EncodeOptions } from "cborg";

import { MalformedDataError } from "./errors.js";

/**
 * ### CborValue
 *
 * The subset of CBOR values the core serialises: no floats, no undefined, no tags.
 * Keeping the subset small keeps every encoding deterministic.
 */
export type CborValue =
  | string
  | number
  | boolean
  | null
  | Uint8Array
  | ReadonlyArray<CborValue>
  | { readonly [key: string]: CborValue };

/**
 * ### encodeCbor
 *
 * Encodes a value as deterministic CBOR (RFC 8949 §4.2.1 core deterministic encoding),
 * so the same value always produces the same bytes for signatures and AAD.
 *
 * @param value Value to encode
 * @returns The canonical CBOR bytes
 */
export function encodeCbor(value: CborValue): Uint8Array {
  return encode(value, rfc8949EncodeOptions);
}

/**
 * ### decodeCbor
 *
 * Decodes CBOR into an unvalidated value. The result is `unknown`; callers narrow it.
 * Throws {@link MalformedDataError} when the bytes are not well-formed CBOR.
 *
 * @param bytes CBOR bytes to decode
 * @returns The decoded value, not yet validated
 */
export function decodeCbor(bytes: Uint8Array): unknown {
  try {
    return decode(bytes, {
      useMaps: false,
      rejectDuplicateMapKeys: true,
      strict: true,
    });
  } catch (error) {
    throw new MalformedDataError("Malformed CBOR", { cause: error });
  }
}

/**
 * ### isRecord
 *
 * Narrows a decoded value to a plain string-keyed object.
 *
 * @param value Decoded value to inspect
 * @returns Whether the value is a non-array, non-null object
 */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof Uint8Array)
  );
}

/**
 * ### readBytes
 *
 * Reads a required byte-string field from a decoded record.
 * Throws {@link MalformedDataError} when the field is missing or not bytes.
 *
 * @param record Decoded record
 * @param field Name of the field to read
 * @param length Exact required length, when the field has a fixed size
 * @returns The field's bytes
 */
export function readBytes(
  record: Record<string, unknown>,
  field: string,
  length?: number,
): Uint8Array {
  const value = record[field];

  if (
    !(value instanceof Uint8Array) ||
    (length !== undefined && value.length !== length)
  ) {
    throw new MalformedDataError(
      `Field "${field}" is missing or has the wrong shape`,
    );
  }

  return value;
}

/**
 * ### readString
 *
 * Reads a required string field from a decoded record.
 * Throws {@link MalformedDataError} when the field is missing or not a string.
 *
 * @param record Decoded record
 * @param field Name of the field to read
 * @returns The field's string value
 */
export function readString(
  record: Record<string, unknown>,
  field: string,
): string {
  const value = record[field];

  if (typeof value !== "string") {
    throw new MalformedDataError(`Field "${field}" is missing or not a string`);
  }

  return value;
}

/**
 * ### readInteger
 *
 * Reads a required non-negative integer field from a decoded record.
 * Throws {@link MalformedDataError} when the field is missing or not a safe integer.
 *
 * @param record Decoded record
 * @param field Name of the field to read
 * @returns The field's integer value
 */
export function readInteger(
  record: Record<string, unknown>,
  field: string,
): number {
  const value = record[field];

  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new MalformedDataError(
      `Field "${field}" is missing or not a non-negative integer`,
    );
  }

  return value;
}
