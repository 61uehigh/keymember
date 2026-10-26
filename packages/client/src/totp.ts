import { hmac } from "@noble/hashes/hmac.js";
import { sha1 } from "@noble/hashes/legacy.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * ### TotpParameters
 *
 * Settings of a TOTP generator, as found in an `otpauth://` URI.
 */
export interface TotpParameters {
  /**
   * ### secret
   *
   * Shared secret bytes.
   */
  readonly secret: Uint8Array;

  /**
   * ### algorithm
   *
   * HMAC hash.
   */
  readonly algorithm: "SHA1" | "SHA256" | "SHA512";

  /**
   * ### digits
   *
   * Code length.
   */
  readonly digits: number;

  /**
   * ### period
   *
   * Step length in seconds.
   */
  readonly period: number;
}

/**
 * ### decodeBase32
 *
 * Decodes RFC 4648 base32, ignoring case, spaces and padding.
 *
 * @param text Base32 text
 * @returns The bytes, or `undefined` when the text has characters outside the alphabet
 */
function decodeBase32(text: string): Uint8Array | undefined {
  const clean = text.toUpperCase().replace(/[\s=]/g, "");
  const output: Array<number> = [];
  let bits = 0;
  let value = 0;

  for (const char of clean) {
    const index = BASE32.indexOf(char);

    if (index === -1) {
      return undefined;
    }

    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Uint8Array.from(output);
}

/**
 * ### parseTotp
 *
 * Reads an item's TOTP field: either an `otpauth://totp/…` URI or a bare base32 secret
 * (then SHA-1, 6 digits, 30 seconds).
 *
 * @param value TOTP field value
 * @returns Generator settings, or `undefined` when the value is not usable
 */
export function parseTotp(value: string): TotpParameters | undefined {
  if (!value.startsWith("otpauth://")) {
    const secret = decodeBase32(value);

    return secret === undefined || secret.length === 0
      ? undefined
      : { secret, algorithm: "SHA1", digits: 6, period: 30 };
  }

  let url: URL;

  try {
    url = new URL(value);
  } catch {
    // A malformed URI is user data, not a fault: the item just has no usable TOTP
    return undefined;
  }

  const secret = decodeBase32(url.searchParams.get("secret") ?? "");
  const algorithm = (url.searchParams.get("algorithm") ?? "SHA1").toUpperCase();
  const digits = Number(url.searchParams.get("digits") ?? "6");
  const period = Number(url.searchParams.get("period") ?? "30");

  if (
    secret === undefined ||
    secret.length === 0 ||
    (algorithm !== "SHA1" &&
      algorithm !== "SHA256" &&
      algorithm !== "SHA512") ||
    !Number.isInteger(digits) ||
    digits < 6 ||
    digits > 8 ||
    !Number.isInteger(period) ||
    period < 1
  ) {
    return undefined;
  }

  return { secret, algorithm, digits, period };
}

/**
 * ### totpCode
 *
 * Computes the current TOTP code (RFC 6238).
 *
 * @param parameters Generator settings from {@link parseTotp}
 * @param now Current time
 * @returns The code and the seconds until it changes
 */
export function totpCode(
  parameters: TotpParameters,
  now: Date,
): { code: string; secondsLeft: number } {
  const seconds = Math.floor(now.getTime() / 1000);
  const step = Math.floor(seconds / parameters.period);
  const counter = new Uint8Array(8);

  new DataView(counter.buffer).setBigUint64(0, BigInt(step));

  const hash = { SHA1: sha1, SHA256: sha256, SHA512: sha512 }[
    parameters.algorithm
  ];
  const digest = hmac(hash, parameters.secret, counter);
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f;
  const binary =
    new DataView(digest.buffer, digest.byteOffset).getUint32(offset) &
    0x7fffffff;

  return {
    code: String(binary % 10 ** parameters.digits).padStart(
      parameters.digits,
      "0",
    ),
    secondsLeft: parameters.period - (seconds % parameters.period),
  };
}
