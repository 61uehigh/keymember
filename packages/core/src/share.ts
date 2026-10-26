import { argon2idAsync } from "@noble/hashes/argon2.js";
import { expand, extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { concatBytes, randomBytes, utf8Encode } from "./bytes.js";
import { openBytes, sealBytes } from "./envelope.js";
import { DEFAULT_KDF_PARAMS, normalizePassword } from "./kdf.js";
import { symmetricKeyFromBytes } from "./SymmetricKey.js";
import type { SymmetricKey } from "./SymmetricKey.js";

/**
 * ### SHARE_SECRET_LENGTH
 *
 * Length of the random secret carried in a share link's URL fragment: 32 bytes.
 */
export const SHARE_SECRET_LENGTH = 32;

/**
 * ### ShareKeys
 *
 * Keys derived from a share link: one encrypts the shared snapshot, the other proves to the
 * server that the opener holds the link (and passphrase) before it releases the ciphertext.
 */
export interface ShareKeys {
  /**
   * ### encryptionKey
   *
   * Key the snapshot is sealed with. Never leaves the clients.
   */
  readonly encryptionKey: SymmetricKey;

  /**
   * ### accessProof
   *
   * Value the opener presents; the server stores only its SHA-256.
   */
  readonly accessProof: Uint8Array;
}

/**
 * ### generateShareSecret
 *
 * Draws the secret for a new share link.
 *
 * @returns {@link SHARE_SECRET_LENGTH} random bytes
 */
export function generateShareSecret(): Uint8Array {
  return randomBytes(SHARE_SECRET_LENGTH);
}

/**
 * ### deriveShareKeys
 *
 * Derives the keys of a share link from its secret and, when set, a passphrase the sender
 * passes on separately. The passphrase goes through Argon2id with the account defaults, so a
 * leaked link cannot be opened by guessing a short passphrase offline faster than that allows;
 * the server additionally limits failed attempts.
 *
 * @param secret Secret from the link
 * @param shareId Share id, binding the keys to this link
 * @param passphrase Optional passphrase
 * @returns The share keys
 */
export async function deriveShareKeys(
  secret: Uint8Array,
  shareId: string,
  passphrase?: string,
): Promise<ShareKeys> {
  const salt = utf8Encode(`keymember/share/v1/${shareId}`);
  const passphraseKey =
    passphrase === undefined
      ? new Uint8Array()
      : await argon2idAsync(normalizePassword(passphrase), sha256(salt), {
          t: DEFAULT_KDF_PARAMS.iterations,
          m: DEFAULT_KDF_PARAMS.memoryKiB,
          p: DEFAULT_KDF_PARAMS.parallelism,
          dkLen: 32,
        });
  const root = extract(sha256, concatBytes(secret, passphraseKey), salt);

  return {
    encryptionKey: symmetricKeyFromBytes(
      sha256(salt).slice(0, 16),
      expand(sha256, root, utf8Encode("keymember/share/v1/encryption"), 32),
    ),
    accessProof: expand(
      sha256,
      root,
      utf8Encode("keymember/share/v1/access"),
      32,
    ),
  };
}

/**
 * ### shareAccessHash
 *
 * What the server stores to check an access proof.
 *
 * @param accessProof Proof from {@link deriveShareKeys}
 * @returns Its SHA-256
 */
export function shareAccessHash(accessProof: Uint8Array): Uint8Array {
  return sha256(accessProof);
}

/**
 * ### sealShare
 *
 * Encrypts a share's snapshot, bound to the share id.
 *
 * @param keys Share keys
 * @param shareId Share id
 * @param snapshot Serialised snapshot
 * @returns The ciphertext for the server
 */
export function sealShare(
  keys: ShareKeys,
  shareId: string,
  snapshot: Uint8Array,
): Uint8Array {
  return sealBytes(keys.encryptionKey, snapshot, {
    kind: "share.snapshot",
    scope: [shareId],
  });
}

/**
 * ### openShare
 *
 * Decrypts a share's snapshot.
 *
 * @param keys Share keys
 * @param shareId Share id
 * @param ciphertext Ciphertext from the server
 * @returns The serialised snapshot
 */
export function openShare(
  keys: ShareKeys,
  shareId: string,
  ciphertext: Uint8Array,
): Uint8Array {
  return openBytes(keys.encryptionKey, ciphertext, {
    kind: "share.snapshot",
    scope: [shareId],
  });
}
