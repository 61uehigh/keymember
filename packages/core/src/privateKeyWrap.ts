import { x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { constantTimeEqual } from "./bytes.js";
import { MalformedDataError } from "./errors.js";
import { unwrapKey, wrapKey } from "./keyWrap.js";
import type { EncryptionKeyPair, WrapContext } from "./keyWrap.js";
import { KEY_ID_LENGTH, symmetricKeyFromBytes } from "./SymmetricKey.js";

/**
 * ### wrapPrivateKey
 *
 * Wraps a shared X25519 private key (a group's or the recovery key's) for one holder,
 * bound to a context naming what the key is and who it is for.
 *
 * @param keyPair Shared key pair
 * @param context Purpose and scope, including the holder's id
 * @param recipientPublicKey Holder's certified X25519 public key
 * @returns The wrapped private key
 */
export async function wrapPrivateKey(
  keyPair: EncryptionKeyPair,
  context: WrapContext,
  recipientPublicKey: Uint8Array,
): Promise<Uint8Array> {
  const id = sha256(keyPair.publicKey).slice(0, KEY_ID_LENGTH);

  return wrapKey(
    symmetricKeyFromBytes(id, keyPair.privateKey),
    recipientPublicKey,
    context,
  );
}

/**
 * ### unwrapPrivateKey
 *
 * Unwraps a holder's copy of a shared private key and checks it against the published public
 * key, so a server cannot slip in a different key pair. Throws `DecryptionError` for a copy
 * made for another holder or context and {@link MalformedDataError} for a mismatched key.
 *
 * @param wrapped Wrapped private key
 * @param context Context the copy must have been made for
 * @param holderKeyPair Holder's X25519 key pair
 * @param expectedPublicKey Published public key the private key must match
 * @returns The shared key pair
 */
export async function unwrapPrivateKey(
  wrapped: Uint8Array,
  context: WrapContext,
  holderKeyPair: EncryptionKeyPair,
  expectedPublicKey: Uint8Array,
): Promise<EncryptionKeyPair> {
  const key = await unwrapKey(wrapped, holderKeyPair, context);
  const publicKey = x25519.getPublicKey(key.bytes);

  if (!constantTimeEqual(publicKey, expectedPublicKey)) {
    throw new MalformedDataError(
      "Private key does not match the published public key",
    );
  }

  return { privateKey: key.bytes, publicKey };
}
