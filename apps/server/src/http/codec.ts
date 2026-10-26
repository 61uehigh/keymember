import { fromBase64Url, toBase64Url } from "@keymember/core";
import { z } from "zod";

import { DomainError } from "../domain/DomainError.js";

/**
 * ### bytes
 *
 * Zod schema for a base64url field, decoded to bytes.
 * Every binary value in the API travels this way.
 *
 * @param length Exact required length in bytes; omit for variable-length values
 * @param maxLength Upper bound in bytes for variable-length values. Defaults to 1 MiB.
 * @returns A schema producing a `Uint8Array`
 */
export function bytes(
  length?: number,
  maxLength = 1024 * 1024,
): z.ZodType<Uint8Array, string> {
  return z.string().transform((text, context) => {
    const decoded = fromBase64Url(text);

    if (
      decoded === undefined ||
      (length !== undefined && decoded.length !== length) ||
      decoded.length > maxLength
    ) {
      context.addIssue({
        code: "custom",
        message:
          length === undefined
            ? "Invalid base64url value"
            : `Expected ${String(length)} base64url bytes`,
      });

      return z.NEVER;
    }

    return decoded;
  });
}

/**
 * ### b64
 *
 * Encodes bytes for a JSON response.
 *
 * @param value Bytes to encode
 * @returns Unpadded base64url text
 */
export function b64(value: Uint8Array): string {
  return toBase64Url(value);
}

/**
 * ### parseBody
 *
 * Validates request input against a schema and throws a `invalid` {@link DomainError} listing the
 * failing paths when it does not match.
 *
 * @param schema Schema the input must satisfy
 * @param input Raw request body, params or query
 * @returns The validated, transformed input
 */
export function parseBody<Output>(
  schema: z.ZodType<Output>,
  input: unknown,
): Output {
  const result = schema.safeParse(input);

  if (!result.success) {
    throw new DomainError(
      "invalid",
      "bad_request",
      "Request does not match the expected shape",
      {
        issues: result.error.issues.map((issue) => ({
          path: issue.path.join("."),
          message: issue.message,
        })),
      },
    );
  }

  return result.data;
}

/**
 * ### identifier
 *
 * Schema for client-generated identifiers: UUIDs for users, vaults and items.
 */
export const identifier = z.uuid();
