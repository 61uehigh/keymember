import { randomBytes } from "./bytes.js";

const LOWER = "abcdefghijkmnopqrstuvwxyz";
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS = "23456789";
const SYMBOLS = "!@#$%^&*-_=+";

/**
 * ### PasswordOptions
 *
 * Shape of a generated password.
 */
export interface PasswordOptions {
  /**
   * ### length
   *
   * Number of characters.
   *
   * @defaultValue `20` — about 115 bits of entropy with symbols on
   */
  readonly length?: number;

  /**
   * ### symbols
   *
   * Whether to include symbols, for sites that reject them.
   *
   * @defaultValue `true`
   */
  readonly symbols?: boolean;
}

/**
 * ### uniformIndex
 *
 * Draws an unbiased index below `bound` from the CSPRNG by rejection sampling.
 *
 * @param bound Exclusive upper bound, at most 256
 * @returns A uniformly random integer in `[0, bound)`
 */
function uniformIndex(bound: number): number {
  const limit = 256 - (256 % bound);

  for (;;) {
    const [byte = 0] = randomBytes(1);

    if (byte < limit) {
      return byte % bound;
    }
  }
}

/**
 * ### generatePassword
 *
 * Generates a random password with at least one character from every enabled class.
 * Visually ambiguous characters (0/O, 1/l/I) are left out so passwords can be read aloud.
 * Throws a `RangeError` for lengths outside 8–128.
 *
 * @param options Length and symbol choice
 * @returns The generated password
 */
export function generatePassword(options: PasswordOptions = {}): string {
  const length = options.length ?? 20;
  const classes =
    (options.symbols ?? true)
      ? [LOWER, UPPER, DIGITS, SYMBOLS]
      : [LOWER, UPPER, DIGITS];

  if (!Number.isInteger(length) || length < 8 || length > 128) {
    throw new RangeError("Password length must be between 8 and 128");
  }

  const pool = classes.join("");
  const chars = classes.map((set) => set.charAt(uniformIndex(set.length)));

  while (chars.length < length) {
    chars.push(pool.charAt(uniformIndex(pool.length)));
  }

  // Fisher–Yates, so the guaranteed characters do not always sit at the front
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = uniformIndex(i + 1);
    const swap = chars[i] ?? "";

    chars[i] = chars[j] ?? "";
    chars[j] = swap;
  }

  return chars.join("");
}
