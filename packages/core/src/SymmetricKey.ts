import { randomBytes } from "./bytes.js";
import { MalformedDataError } from "./errors.js";

/**
 * ### KEY_ID_LENGTH
 *
 * Length in bytes of a key identifier.
 */
export const KEY_ID_LENGTH = 16;

/**
 * ### SYMMETRIC_KEY_LENGTH
 *
 * Length in bytes of every symmetric key (XChaCha20-Poly1305 key size).
 */
export const SYMMETRIC_KEY_LENGTH = 32;

/**
 * ### SymmetricKey
 *
 * A 256-bit symmetric key with a random identifier.
 * The identifier travels in every envelope sealed with the key, so a reader can tell which
 * key generation it needs without trial decryption. The identifier is not secret.
 */
export interface SymmetricKey {
  /**
   * ### id
   *
   * Random, non-secret identifier of this key.
   */
  readonly id: Uint8Array;

  /**
   * ### bytes
   *
   * The secret key material.
   */
  readonly bytes: Uint8Array;
}

/**
 * ### generateSymmetricKey
 *
 * Generates a new random key with a new random identifier.
 *
 * @returns A fresh symmetric key
 */
export function generateSymmetricKey(): SymmetricKey {
  return {
    id: randomBytes(KEY_ID_LENGTH),
    bytes: randomBytes(SYMMETRIC_KEY_LENGTH),
  };
}

/**
 * ### symmetricKeyFromBytes
 *
 * Wraps existing key material, such as a derived unlock key, as a {@link SymmetricKey}.
 * Throws {@link MalformedDataError} when the material or identifier has the wrong length.
 *
 * @param id Identifier to attach to the key
 * @param bytes Exactly {@link SYMMETRIC_KEY_LENGTH} bytes of key material
 * @returns The key with the given identifier
 */
export function symmetricKeyFromBytes(
  id: Uint8Array,
  bytes: Uint8Array,
): SymmetricKey {
  if (id.length !== KEY_ID_LENGTH || bytes.length !== SYMMETRIC_KEY_LENGTH) {
    throw new MalformedDataError(
      "Symmetric key or key id has the wrong length",
    );
  }

  return { id, bytes };
}
