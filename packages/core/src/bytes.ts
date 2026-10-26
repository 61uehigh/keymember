import { equalBytes } from "@noble/ciphers/utils.js";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

/**
 * ### utf8Encode
 *
 * Encodes a string as UTF-8 bytes without any normalisation.
 * Callers that need canonical text (passwords) normalise before calling.
 *
 * @param text Text to encode
 * @returns The UTF-8 encoding of the text
 */
export function utf8Encode(text: string): Uint8Array {
  return textEncoder.encode(text);
}

/**
 * ### utf8Decode
 *
 * Decodes UTF-8 bytes into a string and throws a `TypeError` on malformed input,
 * so corrupted plaintext is never silently replaced with U+FFFD.
 *
 * @param bytes UTF-8 bytes to decode
 * @returns The decoded text
 */
export function utf8Decode(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

/**
 * ### concatBytes
 *
 * Concatenates byte arrays into a newly allocated array; inputs are not modified.
 *
 * @param parts Byte arrays in the order they appear in the output
 * @returns A new array holding every part back to back
 */
export function concatBytes(...parts: Array<Uint8Array>): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;

  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }

  return result;
}

/**
 * ### constantTimeEqual
 *
 * Compares two byte arrays in time that depends only on their length,
 * for comparing secrets such as authentication verifiers and tokens.
 * Arrays of different length compare unequal immediately; length is not treated as secret.
 *
 * @param a First byte array
 * @param b Second byte array
 * @returns Whether both arrays hold identical bytes
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  return equalBytes(a, b);
}

/**
 * ### randomBytes
 *
 * Draws bytes from the platform CSPRNG (`crypto.getRandomValues`).
 *
 * @param length Number of bytes to draw
 * @returns Fresh random bytes
 */
export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * ### toBase64Url
 *
 * Encodes bytes as unpadded base64url, the form used for every binary value in the HTTP API.
 *
 * @param bytes Bytes to encode
 * @returns Unpadded base64url text
 */
export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * ### fromBase64Url
 *
 * Decodes unpadded or padded base64url text.
 * Returns `undefined` for text outside the base64url alphabet instead of throwing,
 * because the input usually comes straight from an HTTP request.
 *
 * @param text Base64url text to decode
 * @returns The decoded bytes, or `undefined` when the text is not valid base64url
 */
export function fromBase64Url(text: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(text)) {
    return undefined;
  }

  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);

  try {
    const binary = atob(padded);

    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    // atob rejects a length that is 1 mod 4; that is malformed input, not an internal fault
    return undefined;
  }
}
