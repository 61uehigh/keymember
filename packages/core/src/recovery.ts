import type { EncryptionKeyPair } from "./keyWrap.js";
import { unwrapPrivateKey, wrapPrivateKey } from "./privateKeyWrap.js";
import { signStatement, verifyStatement } from "./signing.js";

/**
 * ### RECOVERY_PRINCIPAL_ID
 *
 * Principal id vault keys are wrapped to for the organisation's recovery key.
 */
export const RECOVERY_PRINCIPAL_ID = "recovery";

/**
 * ### RecoveryKeyStatement
 *
 * What an owner or admin vouches for when signing the recovery key. Taking it as one object,
 * rather than as loose byte arrays, keeps the key, the statement and the signature from being
 * passed in the wrong order.
 */
export interface RecoveryKeyStatement {
  readonly orgId: string;
  readonly publicKey: Uint8Array;
}

/**
 * ### signRecoveryKey
 *
 * Signs the organisation's recovery public key, so clients wrap vault keys only to a
 * recovery key an owner or admin vouched for, never to one the server substituted.
 *
 * @param signingPrivateKey Ed25519 seed of the signing owner or admin
 * @param statement Organisation and the recovery X25519 public key it uses
 * @returns The signature
 */
export function signRecoveryKey(
  signingPrivateKey: Uint8Array,
  statement: RecoveryKeyStatement,
): Uint8Array {
  return signStatement(signingPrivateKey, "keymember/recovery-key/v1", {
    orgId: statement.orgId,
    publicKey: statement.publicKey,
  });
}

/**
 * ### verifyRecoveryKey
 *
 * Verifies a recovery public key against the signer's verified signing key.
 *
 * @param signerPublicKey Signing key of the claimed signer, taken from a verified certificate
 * @param statement Organisation and the recovery public key as served
 * @param signature Signature as served
 * @returns Whether the signature is valid
 */
export function verifyRecoveryKey(
  signerPublicKey: Uint8Array,
  statement: RecoveryKeyStatement,
  signature: Uint8Array,
): boolean {
  return verifyStatement(
    signerPublicKey,
    "keymember/recovery-key/v1",
    { orgId: statement.orgId, publicKey: statement.publicKey },
    signature,
  );
}

/**
 * ### wrapRecoveryPrivateKey
 *
 * Wraps the recovery private key for one admin. Every admin holds such a copy; the
 * two-admin approval that gates its use is enforced by the server.
 *
 * @param recoveryKey The recovery key pair
 * @param orgId Organisation the key belongs to
 * @param adminId Admin receiving the copy
 * @param adminEncryptionPublicKey The admin's certified X25519 public key
 * @returns The wrapped private key
 */
export async function wrapRecoveryPrivateKey(
  recoveryKey: EncryptionKeyPair,
  orgId: string,
  adminId: string,
  adminEncryptionPublicKey: Uint8Array,
): Promise<Uint8Array> {
  return wrapPrivateKey(
    recoveryKey,
    { purpose: "recovery-private-key", scope: [orgId, adminId] },
    adminEncryptionPublicKey,
  );
}

/**
 * ### unwrapRecoveryPrivateKey
 *
 * Unwraps an admin's copy of the recovery private key and checks it matches the published
 * public key. Throws `DecryptionError` when the copy is not for this admin or org, and
 * `MalformedDataError` when it does not match the published public key.
 *
 * @param wrapped Wrapped private key
 * @param orgId Organisation the key belongs to
 * @param adminId Admin the copy is for
 * @param adminKeyPair The admin's X25519 key pair
 * @param expectedPublicKey Recovery public key the private key must match
 * @returns The recovery key pair
 */
export async function unwrapRecoveryPrivateKey(
  wrapped: Uint8Array,
  orgId: string,
  adminId: string,
  adminKeyPair: EncryptionKeyPair,
  expectedPublicKey: Uint8Array,
): Promise<EncryptionKeyPair> {
  return unwrapPrivateKey(
    wrapped,
    { purpose: "recovery-private-key", scope: [orgId, adminId] },
    adminKeyPair,
    expectedPublicKey,
  );
}
