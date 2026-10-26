import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";

import { constantTimeEqual, randomBytes } from "./bytes.js";
import {
  decodeCbor,
  encodeCbor,
  isRecord,
  readBytes,
  readInteger,
} from "./cbor.js";
import type { CborValue } from "./cbor.js";
import { DecryptionError, MalformedDataError } from "./errors.js";
import { KEY_ID_LENGTH } from "./SymmetricKey.js";
import type { SymmetricKey } from "./SymmetricKey.js";

const ENVELOPE_VERSION = 1;
const ALG_XCHACHA20_POLY1305 = 1;
const NONCE_LENGTH = 24;
const PADDING_BLOCK = 32;

/**
 * ### EnvelopeContext
 *
 * What a ciphertext is bound to, authenticated as AAD.
 * Opening an envelope with a different context fails, so a server cannot move a
 * ciphertext to another item, field or owner. Every part must be identical at seal and open.
 */
export interface EnvelopeContext {
  /**
   * ### kind
   *
   * Kind of data sealed, for example `item.overview` or `account.private-keys`.
   */
  readonly kind: string;

  /**
   * ### scope
   *
   * Identifiers the data belongs to, outermost first (for example vault id, then item id).
   */
  readonly scope: ReadonlyArray<string | number>;
}

/**
 * ### encodeAad
 *
 * Encodes the context as deterministic CBOR so that no two distinct contexts share an encoding.
 *
 * @param context Context to encode
 * @returns The AAD bytes
 */
function encodeAad(context: EnvelopeContext): Uint8Array {
  return encodeCbor(["keymember/v1", context.kind, [...context.scope]]);
}

/**
 * ### pad
 *
 * Applies ISO/IEC 7816-4 padding up to a multiple of {@link PADDING_BLOCK} bytes,
 * hiding the exact plaintext length from the server.
 *
 * @param plaintext Bytes to pad
 * @returns The padded bytes
 */
function pad(plaintext: Uint8Array): Uint8Array {
  const paddedLength =
    (Math.floor(plaintext.length / PADDING_BLOCK) + 1) * PADDING_BLOCK;
  const padded = new Uint8Array(paddedLength);

  padded.set(plaintext);
  padded[plaintext.length] = 0x80;

  return padded;
}

/**
 * ### unpad
 *
 * Removes ISO/IEC 7816-4 padding. Throws {@link MalformedDataError} when the padding is invalid,
 * which can only happen after successful authentication if the sealing client was faulty.
 *
 * @param padded Padded bytes
 * @returns The original plaintext
 */
function unpad(padded: Uint8Array): Uint8Array {
  let index = padded.length - 1;

  while (index >= 0 && padded[index] === 0) {
    index -= 1;
  }

  if (index < 0 || padded[index] !== 0x80) {
    throw new MalformedDataError("Invalid padding");
  }

  return padded.slice(0, index);
}

/**
 * ### sealBytes
 *
 * Encrypts bytes with XChaCha20-Poly1305 under a random nonce, binding the context as AAD,
 * and packs the result as a versioned CBOR envelope carrying the key id.
 *
 * @param key Key to seal with
 * @param plaintext Bytes to encrypt
 * @param context What the ciphertext belongs to
 * @returns The serialised envelope
 */
export function sealBytes(
  key: SymmetricKey,
  plaintext: Uint8Array,
  context: EnvelopeContext,
): Uint8Array {
  const nonce = randomBytes(NONCE_LENGTH);
  const ciphertext = xchacha20poly1305(
    key.bytes,
    nonce,
    encodeAad(context),
  ).encrypt(pad(plaintext));

  return encodeCbor({
    v: ENVELOPE_VERSION,
    alg: ALG_XCHACHA20_POLY1305,
    kid: key.id,
    nonce,
    ct: ciphertext,
  });
}

/**
 * ### readEnvelopeKeyId
 *
 * Reads the id of the key an envelope was sealed with, without decrypting.
 * Used to pick the right key generation after a vault key rotation.
 *
 * @param envelope Serialised envelope
 * @returns The key id recorded in the envelope
 */
export function readEnvelopeKeyId(envelope: Uint8Array): Uint8Array {
  return parseEnvelope(envelope).kid;
}

/**
 * ### parseEnvelope
 *
 * Validates the envelope structure and version.
 *
 * @param envelope Serialised envelope
 * @returns The envelope fields
 */
function parseEnvelope(envelope: Uint8Array): {
  kid: Uint8Array;
  nonce: Uint8Array;
  ct: Uint8Array;
} {
  const decoded = decodeCbor(envelope);

  if (!isRecord(decoded)) {
    throw new MalformedDataError("Envelope is not a map");
  }

  if (
    readInteger(decoded, "v") !== ENVELOPE_VERSION ||
    readInteger(decoded, "alg") !== ALG_XCHACHA20_POLY1305
  ) {
    throw new MalformedDataError("Unsupported envelope version or algorithm");
  }

  return {
    kid: readBytes(decoded, "kid", KEY_ID_LENGTH),
    nonce: readBytes(decoded, "nonce", NONCE_LENGTH),
    ct: readBytes(decoded, "ct"),
  };
}

/**
 * ### openBytes
 *
 * Decrypts an envelope produced by {@link sealBytes}.
 * Throws {@link DecryptionError} for a wrong key, tampered bytes or a mismatched context,
 * and {@link MalformedDataError} when the envelope structure itself is invalid.
 *
 * @param key Key the envelope was sealed with
 * @param envelope Serialised envelope
 * @param context Context the envelope must have been sealed for
 * @returns The decrypted bytes
 */
export function openBytes(
  key: SymmetricKey,
  envelope: Uint8Array,
  context: EnvelopeContext,
): Uint8Array {
  const { kid, nonce, ct } = parseEnvelope(envelope);
  let padded: Uint8Array;

  // The key id is not covered by the AEAD tag, so a tampered one is caught here instead
  if (!constantTimeEqual(kid, key.id)) {
    throw new DecryptionError("Envelope was sealed under a different key");
  }

  try {
    padded = xchacha20poly1305(key.bytes, nonce, encodeAad(context)).decrypt(
      ct,
    );
  } catch (error) {
    throw new DecryptionError("Envelope failed authentication", {
      cause: error,
    });
  }

  return unpad(padded);
}

/**
 * ### sealValue
 *
 * Serialises a value as deterministic CBOR and seals it with {@link sealBytes}.
 *
 * @param key Key to seal with
 * @param value Value to encrypt
 * @param context What the ciphertext belongs to
 * @returns The serialised envelope
 */
export function sealValue(
  key: SymmetricKey,
  value: CborValue,
  context: EnvelopeContext,
): Uint8Array {
  return sealBytes(key, encodeCbor(value), context);
}

/**
 * ### openValue
 *
 * Opens an envelope with {@link openBytes} and decodes the CBOR payload.
 * The result is unvalidated; callers narrow it.
 *
 * @param key Key the envelope was sealed with
 * @param envelope Serialised envelope
 * @param context Context the envelope must have been sealed for
 * @returns The decoded, unvalidated value
 */
export function openValue(
  key: SymmetricKey,
  envelope: Uint8Array,
  context: EnvelopeContext,
): unknown {
  return decodeCbor(openBytes(key, envelope, context));
}
