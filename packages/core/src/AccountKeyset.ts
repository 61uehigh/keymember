import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { constantTimeEqual } from "./bytes.js";
import { encodeCbor, isRecord, readBytes } from "./cbor.js";
import type { CborValue } from "./cbor.js";
import { openValue, sealValue } from "./envelope.js";
import { MalformedDataError } from "./errors.js";
import { generateEncryptionKeyPair } from "./keyWrap.js";
import type { EncryptionKeyPair } from "./keyWrap.js";
import {
  generateSigningKeyPair,
  signStatement,
  verifyStatement,
} from "./signing.js";
import type { SigningKeyPair } from "./signing.js";
import {
  generateSymmetricKey,
  KEY_ID_LENGTH,
  symmetricKeyFromBytes,
} from "./SymmetricKey.js";
import type { SymmetricKey } from "./SymmetricKey.js";

/**
 * ### PublicKeyBundle
 *
 * A user's public keys as published on the server, self-signed by the user's signing key.
 * Self-signing proves key possession; trust in the bundle comes from a member certificate.
 */
export interface PublicKeyBundle {
  /**
   * ### userId
   *
   * Identifier of the user the keys belong to.
   */
  readonly userId: string;

  /**
   * ### encryptionPublicKey
   *
   * X25519 public key that vault and group keys are wrapped to.
   */
  readonly encryptionPublicKey: Uint8Array;

  /**
   * ### signingPublicKey
   *
   * Ed25519 public key that verifies the user's signatures.
   */
  readonly signingPublicKey: Uint8Array;

  /**
   * ### keysetVersion
   *
   * Monotonic counter incremented every time the keyset is regenerated.
   */
  readonly keysetVersion: number;
}

/**
 * ### AccountKeyset
 *
 * The unlocked keyset held in client memory while the vault is unlocked.
 * Must be dropped on lock; nothing in it may be persisted unencrypted.
 */
export interface AccountKeyset {
  /**
   * ### userId
   *
   * Identifier of the owning user.
   */
  readonly userId: string;

  /**
   * ### accountKey
   *
   * The Account Key (AK) that encrypts the private keys and personal vault key.
   */
  readonly accountKey: SymmetricKey;

  /**
   * ### encryption
   *
   * X25519 key pair receiving wrapped vault and group keys.
   */
  readonly encryption: EncryptionKeyPair;

  /**
   * ### signing
   *
   * Ed25519 key pair for self-signatures and member certificates.
   */
  readonly signing: SigningKeyPair;

  /**
   * ### keysetVersion
   *
   * Version of this keyset, matching {@link PublicKeyBundle.keysetVersion}.
   */
  readonly keysetVersion: number;
}

/**
 * ### StoredAccountKeyset
 *
 * The keyset as stored on the server: everything secret is encrypted,
 * the public bundle and its self-signature are in the clear.
 */
export interface StoredAccountKeyset {
  /**
   * ### encryptedAccountKey
   *
   * The Account Key sealed under the account unlock key (AUK).
   */
  readonly encryptedAccountKey: Uint8Array;

  /**
   * ### encryptedPrivateKeys
   *
   * Both private keys sealed under the Account Key.
   */
  readonly encryptedPrivateKeys: Uint8Array;

  /**
   * ### publicBundle
   *
   * Public keys of the keyset.
   */
  readonly publicBundle: PublicKeyBundle;

  /**
   * ### selfSignature
   *
   * Signature over the public bundle by the keyset's own signing key.
   */
  readonly selfSignature: Uint8Array;
}

// The AUK is derived, not generated, so it has no random id; a fixed id marks envelopes sealed with it
const ACCOUNT_UNLOCK_KEY_ID = new Uint8Array(KEY_ID_LENGTH);

/**
 * ### publicBundleStatement
 *
 * Converts a public bundle into the exact statement that is signed.
 *
 * @param bundle Public bundle to convert
 * @returns The statement covered by self-signatures and member certificates
 */
export function publicBundleStatement(bundle: PublicKeyBundle): CborValue {
  return {
    userId: bundle.userId,
    encryptionPublicKey: bundle.encryptionPublicKey,
    signingPublicKey: bundle.signingPublicKey,
    keysetVersion: bundle.keysetVersion,
  };
}

/**
 * ### verifyPublicBundle
 *
 * Checks the self-signature of a published bundle. This proves only that the bundle was
 * produced by the holder of its signing key; it does not prove the holder is the user.
 *
 * @param bundle Bundle as received from the server
 * @param selfSignature Self-signature as received from the server
 * @returns Whether the self-signature is valid
 */
export function verifyPublicBundle(
  bundle: PublicKeyBundle,
  selfSignature: Uint8Array,
): boolean {
  return verifyStatement(
    bundle.signingPublicKey,
    "keymember/public-bundle/v1",
    publicBundleStatement(bundle),
    selfSignature,
  );
}

/**
 * ### publicKeyFingerprint
 *
 * Short human-comparable fingerprint of a bundle's keys, shown when an admin confirms a member
 * so both sides can compare it out of band (in person or over Slack).
 *
 * @param bundle Bundle to fingerprint
 * @returns Twenty hex digits in groups of four, for example `1a2b-3c4d-5e6f-7a8b-9c0d`
 */
export function publicKeyFingerprint(bundle: PublicKeyBundle): string {
  const digest = sha256(
    encodeCbor([
      "keymember/fingerprint/v1",
      bundle.userId,
      bundle.encryptionPublicKey,
      bundle.signingPublicKey,
    ]),
  );
  const hex = Array.from(digest.slice(0, 10), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");

  return hex.match(/.{4}/g)?.join("-") ?? hex;
}

/**
 * ### createAccountKeyset
 *
 * Generates a complete keyset at sign-up or keyset regeneration, and seals it for storage.
 *
 * @param userId Identifier of the owning user
 * @param accountUnlockKey AUK from {@link deriveAccountSecrets}
 * @param keysetVersion Version for the new keyset; `1` at sign-up, previous plus one on regeneration
 * @returns The unlocked keyset for immediate use and its storable form
 */
export function createAccountKeyset(
  userId: string,
  accountUnlockKey: Uint8Array,
  keysetVersion = 1,
): { keyset: AccountKeyset; stored: StoredAccountKeyset } {
  const keyset: AccountKeyset = {
    userId,
    accountKey: generateSymmetricKey(),
    encryption: generateEncryptionKeyPair(),
    signing: generateSigningKeyPair(),
    keysetVersion,
  };

  return { keyset, stored: sealAccountKeyset(keyset, accountUnlockKey) };
}

/**
 * ### sealAccountKeyset
 *
 * Seals an unlocked keyset for storage under the given AUK. Used at sign-up and on
 * password change, where only the AUK wrapping changes and the keys stay the same.
 *
 * @param keyset Unlocked keyset
 * @param accountUnlockKey AUK to seal the Account Key under
 * @returns The storable keyset
 */
export function sealAccountKeyset(
  keyset: AccountKeyset,
  accountUnlockKey: Uint8Array,
): StoredAccountKeyset {
  const auk = symmetricKeyFromBytes(ACCOUNT_UNLOCK_KEY_ID, accountUnlockKey);
  const publicBundle: PublicKeyBundle = {
    userId: keyset.userId,
    encryptionPublicKey: keyset.encryption.publicKey,
    signingPublicKey: keyset.signing.publicKey,
    keysetVersion: keyset.keysetVersion,
  };

  return {
    encryptedAccountKey: sealValue(
      auk,
      { id: keyset.accountKey.id, key: keyset.accountKey.bytes },
      { kind: "account.key", scope: [keyset.userId] },
    ),
    encryptedPrivateKeys: sealValue(
      keyset.accountKey,
      {
        encryption: keyset.encryption.privateKey,
        signing: keyset.signing.privateKey,
      },
      {
        kind: "account.private-keys",
        scope: [keyset.userId, keyset.keysetVersion],
      },
    ),
    publicBundle,
    selfSignature: signStatement(
      keyset.signing.privateKey,
      "keymember/public-bundle/v1",
      publicBundleStatement(publicBundle),
    ),
  };
}

/**
 * ### unlockAccountKeyset
 *
 * Decrypts a stored keyset and checks that the private keys match the published public keys
 * and self-signature, so a server cannot pair a user's private keys with substituted public keys.
 * Throws {@link DecryptionError} for a wrong AUK and {@link MalformedDataError} for an inconsistent keyset.
 *
 * @param stored Keyset as stored on the server
 * @param accountUnlockKey AUK derived from the password and Secret Key
 * @returns The unlocked keyset
 */
export function unlockAccountKeyset(
  stored: StoredAccountKeyset,
  accountUnlockKey: Uint8Array,
): AccountKeyset {
  const { userId, keysetVersion } = stored.publicBundle;
  const auk = symmetricKeyFromBytes(ACCOUNT_UNLOCK_KEY_ID, accountUnlockKey);
  const accountKeyValue = openValue(auk, stored.encryptedAccountKey, {
    kind: "account.key",
    scope: [userId],
  });

  if (!isRecord(accountKeyValue)) {
    throw new MalformedDataError("Account key payload is not a map");
  }

  const accountKey = symmetricKeyFromBytes(
    readBytes(accountKeyValue, "id"),
    readBytes(accountKeyValue, "key"),
  );
  const privateKeys = openValue(accountKey, stored.encryptedPrivateKeys, {
    kind: "account.private-keys",
    scope: [userId, keysetVersion],
  });

  if (!isRecord(privateKeys)) {
    throw new MalformedDataError("Private keys payload is not a map");
  }

  const encryptionPrivateKey = readBytes(privateKeys, "encryption", 32);
  const signingPrivateKey = readBytes(privateKeys, "signing", 32);
  const keyset: AccountKeyset = {
    userId,
    accountKey,
    encryption: {
      privateKey: encryptionPrivateKey,
      publicKey: x25519.getPublicKey(encryptionPrivateKey),
    },
    signing: {
      privateKey: signingPrivateKey,
      publicKey: ed25519.getPublicKey(signingPrivateKey),
    },
    keysetVersion,
  };

  if (
    !constantTimeEqual(
      keyset.encryption.publicKey,
      stored.publicBundle.encryptionPublicKey,
    ) ||
    !constantTimeEqual(
      keyset.signing.publicKey,
      stored.publicBundle.signingPublicKey,
    ) ||
    !verifyPublicBundle(stored.publicBundle, stored.selfSignature)
  ) {
    throw new MalformedDataError(
      "Stored public keys do not match the decrypted private keys",
    );
  }

  return keyset;
}
