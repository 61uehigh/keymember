import { randomBytes } from "./bytes.js";

/**
 * ### SECRET_KEY_ALPHABET
 *
 * The 31 characters a Secret Key may contain.
 * Omits 0, 1, I, O and U so that a key copied by hand from the Emergency Kit cannot be misread.
 */
export const SECRET_KEY_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTVWXYZ";

const VERSION = "K1";
const ACCOUNT_ID_LENGTH = 6;
const SECRET_LENGTH = 26;
const SECRET_GROUP_SIZES = [6, 5, 5, 5, 5] as const;

/**
 * ### SecretKey
 *
 * A parsed Secret Key: the device-held second secret mixed into key derivation (2SKD).
 * Only `accountId` is public; `secret` must never leave the client.
 */
export interface SecretKey {
  /**
   * ### version
   *
   * Derivation scheme the key belongs to; `K1` is the only scheme defined so far.
   */
  readonly version: "K1";

  /**
   * ### accountId
   *
   * Public six-character account identifier, also used as the HKDF salt for the secret part.
   */
  readonly accountId: string;

  /**
   * ### secret
   *
   * The 26 random characters, roughly 128.8 bits of entropy.
   */
  readonly secret: string;
}

/**
 * ### pickCharacters
 *
 * Picks characters uniformly from the alphabet by rejection sampling,
 * so no character is more likely than another.
 *
 * @param count Number of characters to pick
 * @returns A string of uniformly random alphabet characters
 */
function pickCharacters(count: number): string {
  const alphabetSize = SECRET_KEY_ALPHABET.length;

  // Largest multiple of the alphabet size below 256; bytes at or above it are redrawn to avoid modulo bias
  const limit = 256 - (256 % alphabetSize);
  let result = "";

  while (result.length < count) {
    for (const byte of randomBytes(count * 2)) {
      if (byte < limit && result.length < count) {
        result += SECRET_KEY_ALPHABET.charAt(byte % alphabetSize);
      }
    }
  }

  return result;
}

/**
 * ### generateSecretKey
 *
 * Generates a new Secret Key at sign-up. The caller is responsible for persisting it
 * in the device's secure storage and in the Emergency Kit before uploading any keyset.
 *
 * @returns A freshly generated Secret Key
 */
export function generateSecretKey(): SecretKey {
  return {
    version: VERSION,
    accountId: pickCharacters(ACCOUNT_ID_LENGTH),
    secret: pickCharacters(SECRET_LENGTH),
  };
}

/**
 * ### formatSecretKey
 *
 * Formats a Secret Key for display and the Emergency Kit, for example
 * `K1-ABCDEF-ABCDEF-ABCDE-ABCDE-ABCDE-ABCDE`. Hyphens are cosmetic.
 *
 * @param key Secret Key to format
 * @returns The hyphenated, human-readable form
 */
export function formatSecretKey(key: SecretKey): string {
  const groups: Array<string> = [];
  let offset = 0;

  for (const size of SECRET_GROUP_SIZES) {
    groups.push(key.secret.slice(offset, offset + size));
    offset += size;
  }

  return [key.version, key.accountId, ...groups].join("-");
}

/**
 * ### parseSecretKey
 *
 * Parses a Secret Key typed or pasted by a user. Ignores case, spaces and hyphens.
 * Returns `undefined` for anything that is not a well-formed K1 key, because bad input
 * here is an ordinary user mistake rather than a fault.
 *
 * @param text Secret Key text as entered by the user
 * @returns The parsed Secret Key, or `undefined` when the text is not a valid key
 */
export function parseSecretKey(text: string): SecretKey | undefined {
  const compact = text.toUpperCase().replace(/[\s-]/g, "");

  if (compact.length !== VERSION.length + ACCOUNT_ID_LENGTH + SECRET_LENGTH) {
    return undefined;
  }

  if (!compact.startsWith(VERSION)) {
    return undefined;
  }

  const body = compact.slice(VERSION.length);

  for (const char of body) {
    if (!SECRET_KEY_ALPHABET.includes(char)) {
      return undefined;
    }
  }

  return {
    version: VERSION,
    accountId: body.slice(0, ACCOUNT_ID_LENGTH),
    secret: body.slice(ACCOUNT_ID_LENGTH),
  };
}
