import type { CborValue } from "./cbor.js";
import type { EncryptionKeyPair } from "./keyWrap.js";
import { unwrapPrivateKey, wrapPrivateKey } from "./privateKeyWrap.js";
import { signStatement, verifyStatement } from "./signing.js";

/**
 * ### GroupCertificate
 *
 * An admin's signed statement binding a group's public key to the group. Clients verify it
 * before wrapping a vault key to a group, exactly as they do for members.
 */
export interface GroupCertificate {
  /**
   * ### orgId
   *
   * Organisation the group belongs to.
   */
  readonly orgId: string;

  /**
   * ### groupId
   *
   * Group id.
   */
  readonly groupId: string;

  /**
   * ### name
   *
   * Group name as certified, so a server cannot relabel a group to mislead whoever shares with it.
   */
  readonly name: string;

  /**
   * ### encryptionPublicKey
   *
   * Group's X25519 public key.
   */
  readonly encryptionPublicKey: Uint8Array;

  /**
   * ### keysetVersion
   *
   * Version of the group key; a rotation needs a new certificate.
   */
  readonly keysetVersion: number;

  /**
   * ### issuerId
   *
   * Admin who signed.
   */
  readonly issuerId: string;

  /**
   * ### issuedAt
   *
   * Signing time in Unix seconds.
   */
  readonly issuedAt: number;
}

/**
 * ### groupCertificateStatement
 *
 * The exact statement a group certificate signs.
 *
 * @param certificate Certificate
 * @returns The signed statement
 */
function groupCertificateStatement(certificate: GroupCertificate): CborValue {
  return {
    orgId: certificate.orgId,
    groupId: certificate.groupId,
    name: certificate.name,
    encryptionPublicKey: certificate.encryptionPublicKey,
    keysetVersion: certificate.keysetVersion,
    issuerId: certificate.issuerId,
    issuedAt: certificate.issuedAt,
  };
}

/**
 * ### signGroupCertificate
 *
 * Signs a group certificate with an admin's signing key.
 *
 * @param issuerSigningPrivateKey Admin's Ed25519 seed
 * @param certificate Certificate to sign; `issuerId` must be the signing admin
 * @returns The signature
 */
export function signGroupCertificate(
  issuerSigningPrivateKey: Uint8Array,
  certificate: GroupCertificate,
): Uint8Array {
  return signStatement(
    issuerSigningPrivateKey,
    "keymember/group-certificate/v1",
    groupCertificateStatement(certificate),
  );
}

/**
 * ### verifyGroupCertificate
 *
 * Verifies a group certificate against trusted admin signing keys.
 *
 * @param certificate Certificate as served
 * @param signature Signature as served
 * @param trustedIssuers Trusted issuer keys by user id (see `trustedIssuers`)
 * @returns Whether a trusted admin signed this exact certificate
 */
export function verifyGroupCertificate(
  certificate: GroupCertificate,
  signature: Uint8Array,
  trustedIssuers: ReadonlyMap<string, Uint8Array>,
): boolean {
  const issuerKey = trustedIssuers.get(certificate.issuerId);

  return (
    issuerKey !== undefined &&
    verifyStatement(
      issuerKey,
      "keymember/group-certificate/v1",
      groupCertificateStatement(certificate),
      signature,
    )
  );
}

/**
 * ### groupWrapContext
 *
 * Context a group private key copy is bound to: group, key version and holder.
 *
 * @param groupId Group id
 * @param keysetVersion Group key version
 * @param holderId Member user id, or the recovery principal id
 * @returns The wrap context
 */
function groupWrapContext(
  groupId: string,
  keysetVersion: number,
  holderId: string,
): { purpose: string; scope: Array<string | number> } {
  return {
    purpose: "group-private-key",
    scope: [groupId, keysetVersion, holderId],
  };
}

/**
 * ### wrapGroupPrivateKey
 *
 * Gives one holder (a member, or the recovery key) a copy of the group private key.
 *
 * @param groupKey Group key pair
 * @param groupId Group id
 * @param keysetVersion Group key version
 * @param holderId Member user id, or the recovery principal id
 * @param holderPublicKey Holder's certified X25519 public key
 * @returns The wrapped private key
 */
export async function wrapGroupPrivateKey(
  groupKey: EncryptionKeyPair,
  groupId: string,
  keysetVersion: number,
  holderId: string,
  holderPublicKey: Uint8Array,
): Promise<Uint8Array> {
  return wrapPrivateKey(
    groupKey,
    groupWrapContext(groupId, keysetVersion, holderId),
    holderPublicKey,
  );
}

/**
 * ### unwrapGroupPrivateKey
 *
 * Opens a holder's copy of the group private key and checks it against the certified public key.
 *
 * @param wrapped Wrapped private key
 * @param groupId Group id
 * @param keysetVersion Group key version
 * @param holderId Holder the copy was made for
 * @param holderKeyPair Holder's X25519 key pair
 * @param expectedPublicKey Certified group public key
 * @returns The group key pair
 */
export async function unwrapGroupPrivateKey(
  wrapped: Uint8Array,
  groupId: string,
  keysetVersion: number,
  holderId: string,
  holderKeyPair: EncryptionKeyPair,
  expectedPublicKey: Uint8Array,
): Promise<EncryptionKeyPair> {
  return unwrapPrivateKey(
    wrapped,
    groupWrapContext(groupId, keysetVersion, holderId),
    holderKeyPair,
    expectedPublicKey,
  );
}
