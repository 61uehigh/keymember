import { argon2idAsync } from "@noble/hashes/argon2.js";
import { expand, extract, hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { concatBytes, randomBytes, utf8Encode } from "./bytes.js";
import { KdfParametersRejectedError } from "./errors.js";
import type { SecretKey } from "./SecretKey.js";

/**
 * ### KdfParams
 *
 * Argon2id cost parameters stored per account and returned by prelogin.
 * Always pass server-supplied values through {@link assertKdfParams} before use.
 */
export interface KdfParams {
  /**
   * ### algorithm
   *
   * Password hashing algorithm; Argon2id is the only supported value.
   */
  readonly algorithm: "argon2id";

  /**
   * ### memoryKiB
   *
   * Memory cost in KiB.
   */
  readonly memoryKiB: number;

  /**
   * ### iterations
   *
   * Time cost (number of passes over memory).
   */
  readonly iterations: number;

  /**
   * ### parallelism
   *
   * Number of lanes.
   */
  readonly parallelism: number;
}

/**
 * ### DEFAULT_KDF_PARAMS
 *
 * Parameters assigned to new accounts: 64 MiB, 3 passes, 1 lane.
 */
export const DEFAULT_KDF_PARAMS: KdfParams = {
  algorithm: "argon2id",
  memoryKiB: 64 * 1024,
  iterations: 3,
  parallelism: 1,
};

/**
 * ### KDF_PARAMS_FLOOR
 *
 * Hard-coded minimum. Unlike Bitwarden, whose client accepts 5,000 PBKDF2 rounds from a
 * server that would only ever set 600,000, the floor equals the default so a malicious
 * server cannot weaken derivation at all.
 */
export const KDF_PARAMS_FLOOR = {
  memoryKiB: DEFAULT_KDF_PARAMS.memoryKiB,
  iterations: DEFAULT_KDF_PARAMS.iterations,
  parallelism: 1,
} as const;

/**
 * ### KDF_PARAMS_CEILING
 *
 * Hard-coded maximum, so a malicious server cannot exhaust a client's memory or time.
 */
export const KDF_PARAMS_CEILING = {
  memoryKiB: 1024 * 1024,
  iterations: 10,
  parallelism: 16,
} as const;

/**
 * ### SALT_LENGTH
 *
 * Length in bytes of the random per-account salt.
 */
export const SALT_LENGTH = 16;

/**
 * ### AccountSecrets
 *
 * The two independent keys derived from the password and Secret Key.
 * Neither key can be derived from the other.
 */
export interface AccountSecrets {
  /**
   * ### accountUnlockKey
   *
   * Key that unwraps the Account Key (AUK). Never leaves the client.
   */
  readonly accountUnlockKey: Uint8Array;

  /**
   * ### authenticationKey
   *
   * Legacy login secret: sent to the server by accounts that predate signed-challenge login,
   * once, to switch them over. The server stores only {@link deriveAuthVerifier} of it.
   */
  readonly authenticationKey: Uint8Array;

  /**
   * ### loginSigningSeed
   *
   * Ed25519 seed of the login key. The server stores only its public key and checks a
   * signature over a fresh challenge at each login, so nothing the server or a TLS-terminating
   * proxy sees can be replayed to log in.
   */
  readonly loginSigningSeed: Uint8Array;
}

/**
 * ### assertKdfParams
 *
 * Rejects parameters outside the hard-coded floor and ceiling.
 * Call this on every server-supplied value before deriving; a rejection should abort login
 * and be reported as a possible downgrade attack.
 *
 * @param params Parameters to validate, typically from a prelogin response
 */
export function assertKdfParams(params: KdfParams): void {
  const checks: Array<[string, number, number, number]> = [
    [
      "memoryKiB",
      params.memoryKiB,
      KDF_PARAMS_FLOOR.memoryKiB,
      KDF_PARAMS_CEILING.memoryKiB,
    ],
    [
      "iterations",
      params.iterations,
      KDF_PARAMS_FLOOR.iterations,
      KDF_PARAMS_CEILING.iterations,
    ],
    [
      "parallelism",
      params.parallelism,
      KDF_PARAMS_FLOOR.parallelism,
      KDF_PARAMS_CEILING.parallelism,
    ],
  ];

  // The value arrives from an untrusted server, so the literal type is a claim to verify, not a guarantee
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  if (params.algorithm !== "argon2id") {
    throw new KdfParametersRejectedError(
      `Unsupported KDF algorithm: ${String(params.algorithm)}`,
    );
  }

  for (const [name, value, floor, ceiling] of checks) {
    if (!Number.isSafeInteger(value) || value < floor || value > ceiling) {
      throw new KdfParametersRejectedError(
        `KDF ${name}=${String(value)} is outside [${String(floor)}, ${String(ceiling)}]`,
      );
    }
  }
}

/**
 * ### generateSalt
 *
 * Generates the random per-account salt. The salt is deliberately not derived from the
 * email address, so changing the email never forces re-keying.
 *
 * @returns A fresh salt of {@link SALT_LENGTH} bytes
 */
export function generateSalt(): Uint8Array {
  return randomBytes(SALT_LENGTH);
}

/**
 * ### normalizePassword
 *
 * Trims surrounding whitespace and applies Unicode NFKD, so the same password typed on
 * different keyboards or platforms yields the same bytes.
 *
 * @param password Account password as entered
 * @returns The canonical UTF-8 bytes of the password
 */
export function normalizePassword(password: string): Uint8Array {
  return utf8Encode(password.trim().normalize("NFKD"));
}

/**
 * ### deriveAccountSecrets
 *
 * Runs Two-Secret Key Derivation: Argon2id over the password, HKDF over the Secret Key,
 * then HKDF-separates the unlock key and the authentication key.
 * Validates the parameters first and throws {@link KdfParametersRejectedError} when they are out of bounds.
 *
 * @param password Account password as entered
 * @param secretKey The account's Secret Key
 * @param salt Per-account salt from prelogin
 * @param params Argon2id parameters from prelogin
 * @returns The account unlock key and the authentication key
 */
export async function deriveAccountSecrets(
  password: string,
  secretKey: SecretKey,
  salt: Uint8Array,
  params: KdfParams,
): Promise<AccountSecrets> {
  assertKdfParams(params);

  const passwordKey = await argon2idAsync(normalizePassword(password), salt, {
    t: params.iterations,
    m: params.memoryKiB,
    p: params.parallelism,
    dkLen: 32,
  });
  const secretKeyMaterial = hkdf(
    sha256,
    utf8Encode(secretKey.secret),
    utf8Encode(secretKey.accountId),
    utf8Encode("keymember/secret-key/v1"),
    32,
  );
  const root = extract(
    sha256,
    concatBytes(passwordKey, secretKeyMaterial),
    utf8Encode("keymember/2skd/v1"),
  );

  return {
    accountUnlockKey: expand(sha256, root, utf8Encode("keymember/auk/v1"), 32),
    authenticationKey: expand(
      sha256,
      root,
      utf8Encode("keymember/auth/v1"),
      32,
    ),
    loginSigningSeed: expand(
      sha256,
      root,
      utf8Encode("keymember/login-signing/v1"),
      32,
    ),
  };
}

/**
 * ### deriveAuthVerifier
 *
 * Computes the value the server stores and compares at login.
 * A plain hash is sufficient because the authentication key carries the Secret Key's
 * 128 bits of entropy, so the verifier cannot be brute-forced (ADR-003).
 *
 * @param authenticationKey Authentication key presented by the client
 * @returns The SHA-256 verifier
 */
export function deriveAuthVerifier(authenticationKey: Uint8Array): Uint8Array {
  return sha256(authenticationKey);
}
