import type { CborValue } from "./cbor.js";
import { signStatement, verifyStatement } from "./signing.js";

/**
 * ### MemberRole
 *
 * Role of a member in the organisation. Owners and admins may certify other members.
 */
export type MemberRole = "owner" | "admin" | "member";

/**
 * ### ISSUER_ROLES
 *
 * Roles whose certificate authorises its holder to sign member certificates.
 */
export const ISSUER_ROLES: ReadonlySet<MemberRole> = new Set([
  "owner",
  "admin",
]);

/**
 * ### MemberCertificate
 *
 * An admin's signed statement that a user's public keys belong to a member of the organisation.
 * Clients verify it before wrapping any key to a member, so a malicious server cannot
 * substitute its own public key (the weakness 1Password lists as Appendix C).
 */
export interface MemberCertificate {
  /**
   * ### orgId
   *
   * Organisation the membership belongs to.
   */
  readonly orgId: string;

  /**
   * ### userId
   *
   * Certified user.
   */
  readonly userId: string;

  /**
   * ### email
   *
   * Email the admin confirmed, lowercased.
   */
  readonly email: string;

  /**
   * ### encryptionPublicKey
   *
   * Certified X25519 public key.
   */
  readonly encryptionPublicKey: Uint8Array;

  /**
   * ### signingPublicKey
   *
   * Certified Ed25519 public key.
   */
  readonly signingPublicKey: Uint8Array;

  /**
   * ### keysetVersion
   *
   * Keyset version the certificate covers; a regenerated keyset needs a new certificate.
   */
  readonly keysetVersion: number;

  /**
   * ### role
   *
   * Role the admin granted. Signed so that a server cannot promote a member to an issuer:
   * only certificates with `owner` or `admin` may sign further certificates.
   */
  readonly role: MemberRole;

  /**
   * ### issuerId
   *
   * User id of the admin who signed.
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
 * ### memberCertificateStatement
 *
 * Converts a certificate into the exact statement that is signed.
 *
 * @param certificate Certificate to convert
 * @returns The signed statement
 */
function memberCertificateStatement(certificate: MemberCertificate): CborValue {
  return {
    orgId: certificate.orgId,
    userId: certificate.userId,
    email: certificate.email,
    encryptionPublicKey: certificate.encryptionPublicKey,
    signingPublicKey: certificate.signingPublicKey,
    keysetVersion: certificate.keysetVersion,
    role: certificate.role,
    issuerId: certificate.issuerId,
    issuedAt: certificate.issuedAt,
  };
}

/**
 * ### signMemberCertificate
 *
 * Signs a member certificate with the issuing admin's signing key. The admin should
 * compare the member's fingerprint out of band before calling this.
 *
 * @param issuerSigningPrivateKey Ed25519 seed of the issuing admin
 * @param certificate Certificate to sign; `issuerId` must be the signing admin
 * @returns The certificate signature
 */
export function signMemberCertificate(
  issuerSigningPrivateKey: Uint8Array,
  certificate: MemberCertificate,
): Uint8Array {
  return signStatement(
    issuerSigningPrivateKey,
    "keymember/member-certificate/v1",
    memberCertificateStatement(certificate),
  );
}

/**
 * ### verifyMemberCertificate
 *
 * Verifies a certificate against the set of admin signing keys the client already trusts.
 * Returns `false` when the issuer is unknown or the signature is invalid.
 *
 * @param certificate Certificate as received from the server
 * @param signature Signature as received from the server
 * @param trustedIssuers Signing public keys of trusted admins, keyed by user id
 * @returns Whether a trusted admin signed this exact certificate
 */
export function verifyMemberCertificate(
  certificate: MemberCertificate,
  signature: Uint8Array,
  trustedIssuers: ReadonlyMap<string, Uint8Array>,
): boolean {
  const issuerKey = trustedIssuers.get(certificate.issuerId);

  if (issuerKey === undefined) {
    return false;
  }

  return verifyStatement(
    issuerKey,
    "keymember/member-certificate/v1",
    memberCertificateStatement(certificate),
    signature,
  );
}
