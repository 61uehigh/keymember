import { constantTimeEqual, randomBytes, utf8Encode } from "@keymember/core";
import { hmac } from "@noble/hashes/hmac.js";
import { sha1 } from "@noble/hashes/legacy.js";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEP_SECONDS = 30;
const DIGITS = 6;

/**
 * ### generateTotpSecret
 *
 * Generates a 160-bit TOTP secret, the size RFC 4226 recommends for HMAC-SHA1.
 *
 * @returns A fresh secret
 */
export function generateTotpSecret(): Uint8Array {
  return randomBytes(20);
}

/**
 * ### toBase32
 *
 * Encodes bytes as unpadded RFC 4648 base32, the format authenticator apps expect.
 *
 * @param bytes Bytes to encode
 * @returns Base32 text
 */
export function toBase32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET.charAt((value >>> (bits - 5)) & 31);
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET.charAt((value << (5 - bits)) & 31);
  }

  return output;
}

/**
 * ### totpUri
 *
 * Builds the `otpauth://` URI an authenticator app scans as a QR code.
 *
 * @param secret TOTP secret
 * @param accountName Label shown in the authenticator, usually the email
 * @returns The provisioning URI
 */
export function totpUri(secret: Uint8Array, accountName: string): string {
  const label = encodeURIComponent(`keymember:${accountName}`);

  return `otpauth://totp/${label}?secret=${toBase32(secret)}&issuer=keymember&algorithm=SHA1&digits=${String(DIGITS)}&period=${String(STEP_SECONDS)}`;
}

/**
 * ### codeForStep
 *
 * Computes the HOTP value (RFC 4226) for one time step.
 *
 * @param secret TOTP secret
 * @param step Time step counter
 * @returns The zero-padded code
 */
export function codeForStep(secret: Uint8Array, step: number): string {
  const counter = new Uint8Array(8);
  new DataView(counter.buffer).setBigUint64(0, BigInt(step));

  const digest = hmac(sha1, secret, counter);
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f;
  const binary =
    new DataView(digest.buffer, digest.byteOffset).getUint32(offset) &
    0x7fffffff;

  return String(binary % 10 ** DIGITS).padStart(DIGITS, "0");
}

/**
 * ### verifyTotp
 *
 * Checks a code against the current step and one step either side for clock drift.
 * Returns the matched step so the caller can store it and reject replays of the same code;
 * steps at or before `lastUsedStep` never match.
 *
 * @param secret TOTP secret
 * @param code Code entered by the user
 * @param now Current time
 * @param lastUsedStep Step of the last accepted code, if any
 * @returns The matched step, or `undefined` when the code is wrong or replayed
 */
export function verifyTotp(
  secret: Uint8Array,
  code: string,
  now: Date,
  lastUsedStep: number | undefined,
): number | undefined {
  const current = Math.floor(now.getTime() / 1000 / STEP_SECONDS);

  for (const step of [current - 1, current, current + 1]) {
    if (lastUsedStep !== undefined && step <= lastUsedStep) {
      continue;
    }

    if (
      constantTimeEqual(utf8Encode(codeForStep(secret, step)), utf8Encode(code))
    ) {
      return step;
    }
  }

  return undefined;
}
