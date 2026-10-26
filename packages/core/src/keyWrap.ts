import { CipherSuite } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/dhkem-x25519";
import { x25519 } from "@noble/curves/ed25519.js";

import {
  decodeCbor,
  encodeCbor,
  isRecord,
  readBytes,
  readInteger,
} from "./cbor.js";
import type { CborValue } from "./cbor.js";
import { DecryptionError, MalformedDataError } from "./errors.js";
import { symmetricKeyFromBytes } from "./SymmetricKey.js";
import type { SymmetricKey } from "./SymmetricKey.js";

const SUITE_X25519_CHACHA20 = 1;

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

/**
 * ### EncryptionKeyPair
 *
 * An X25519 key pair that receives wrapped keys (vault keys, group keys) via HPKE.
 */
export interface EncryptionKeyPair {
  /**
   * ### publicKey
   *
   * 32-byte X25519 public key, published on the server.
   */
  readonly publicKey: Uint8Array;

  /**
   * ### privateKey
   *
   * 32-byte X25519 private key. Stored only inside an encrypted keyset.
   */
  readonly privateKey: Uint8Array;
}

/**
 * ### WrapContext
 *
 * What a wrapped key is for, bound into both the HPKE `info` and AAD.
 * Unwrapping with a different context fails, so a server cannot present a key wrapped for
 * one vault, generation or recipient as belonging to another.
 */
export interface WrapContext {
  /**
   * ### purpose
   *
   * What kind of key is wrapped, for example `vault-key` or `group-private-key`.
   */
  readonly purpose: string;

  /**
   * ### scope
   *
   * Identifiers that pin the wrapped key: owner id, key generation and recipient id.
   */
  readonly scope: ReadonlyArray<string | number>;
}

/**
 * ### generateEncryptionKeyPair
 *
 * Generates a new X25519 key pair from the platform CSPRNG.
 *
 * @returns A fresh encryption key pair
 */
export function generateEncryptionKeyPair(): EncryptionKeyPair {
  const privateKey = x25519.utils.randomSecretKey();

  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

/**
 * ### encodeContext
 *
 * Encodes a wrap context as deterministic CBOR for use as HPKE info and AAD.
 *
 * @param context Wrap context
 * @returns The encoded context bytes
 */
function encodeContext(context: WrapContext): Uint8Array {
  return encodeCbor(["keymember/wrap/v1", context.purpose, [...context.scope]]);
}

/**
 * ### wrapKey
 *
 * Wraps a symmetric key for one recipient with HPKE base mode
 * (DHKEM-X25519, HKDF-SHA256, ChaCha20-Poly1305). The sender is not authenticated;
 * recipients establish trust in public keys through member certificates instead.
 *
 * @param key Symmetric key to wrap, including its id
 * @param recipientPublicKey X25519 public key of the recipient
 * @param context What the key is for and who it is for
 * @returns The serialised wrapped key
 */
export async function wrapKey(
  key: SymmetricKey,
  recipientPublicKey: Uint8Array,
  context: WrapContext,
): Promise<Uint8Array> {
  const encodedContext = encodeContext(context);
  const recipientKey = await suite.kem.deserializePublicKey(recipientPublicKey);
  const sender = await suite.createSenderContext({
    recipientPublicKey: recipientKey,
    info: encodedContext,
  });
  const payload: CborValue = { id: key.id, key: key.bytes };
  const ciphertext = new Uint8Array(
    await sender.seal(encodeCbor(payload), encodedContext),
  );

  return encodeCbor({
    suite: SUITE_X25519_CHACHA20,
    enc: new Uint8Array(sender.enc),
    ct: ciphertext,
  });
}

/**
 * ### unwrapKey
 *
 * Unwraps a key produced by {@link wrapKey}.
 * Throws {@link DecryptionError} for a wrong private key, tampered bytes or a mismatched
 * context, and {@link MalformedDataError} when the structure is invalid.
 *
 * @param wrapped Serialised wrapped key
 * @param recipientKeyPair Recipient's X25519 key pair
 * @param context Context the key must have been wrapped for
 * @returns The unwrapped symmetric key
 */
export async function unwrapKey(
  wrapped: Uint8Array,
  recipientKeyPair: EncryptionKeyPair,
  context: WrapContext,
): Promise<SymmetricKey> {
  const decoded = decodeCbor(wrapped);

  if (
    !isRecord(decoded) ||
    readInteger(decoded, "suite") !== SUITE_X25519_CHACHA20
  ) {
    throw new MalformedDataError("Unsupported wrapped key suite");
  }

  const encodedContext = encodeContext(context);
  let plaintext: Uint8Array;

  try {
    // importKey accepts only an ArrayBuffer; slice copies the key into one of exactly its length
    const recipientKey = await suite.kem.importKey(
      "raw",
      recipientKeyPair.privateKey.slice().buffer,
      false,
    );
    const publicKey = await suite.kem.deserializePublicKey(
      recipientKeyPair.publicKey,
    );
    const recipient = await suite.createRecipientContext({
      recipientKey: { privateKey: recipientKey, publicKey },
      enc: readBytes(decoded, "enc"),
      info: encodedContext,
    });

    plaintext = new Uint8Array(
      await recipient.open(readBytes(decoded, "ct"), encodedContext),
    );
  } catch (error) {
    if (error instanceof MalformedDataError) {
      throw error;
    }

    throw new DecryptionError("Wrapped key failed authentication", {
      cause: error,
    });
  }

  const payload = decodeCbor(plaintext);

  if (!isRecord(payload)) {
    throw new MalformedDataError("Wrapped key payload is not a map");
  }

  return symmetricKeyFromBytes(
    readBytes(payload, "id"),
    readBytes(payload, "key"),
  );
}
