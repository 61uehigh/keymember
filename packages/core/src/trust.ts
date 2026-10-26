import { constantTimeEqual } from "./bytes.js";
import { ISSUER_ROLES, verifyMemberCertificate } from "./MemberCertificate.js";
import type { MemberCertificate } from "./MemberCertificate.js";

/**
 * ### DirectoryEntry
 *
 * One member's certificate as served by the organisation directory. Either field is
 * `undefined` for a member nobody has confirmed yet.
 */
export interface DirectoryEntry {
  /**
   * ### certificate
   *
   * Certificate claimed for the member.
   */
  readonly certificate: MemberCertificate | undefined;

  /**
   * ### signature
   *
   * Signature claimed for the certificate.
   */
  readonly signature: Uint8Array | undefined;

  /**
   * ### keysetVersion
   *
   * Version of the keys the member currently publishes. When set, a certificate for any other
   * version is ignored, so a server cannot keep vouching for keys the member has replaced.
   */
  readonly keysetVersion?: number | undefined;

  /**
   * ### userId
   *
   * Member the directory row is for. When set, a certificate for anyone else is ignored, so a
   * server cannot move one member's certificate onto another member's row.
   */
  readonly userId?: string | undefined;
}

/**
 * ### verifyDirectory
 *
 * Determines which members' keys are vouched for by a chain of certificates that starts at the
 * pinned root keys. A certificate counts only if its issuer is a root or holds a verified
 * certificate with an issuer role; repeated passes resolve chains of any order.
 * Anything the server adds, alters or reorders without a valid chain is simply left out, and a
 * member listed on more than one row is left out entirely: the server could otherwise list an
 * old certificate first to have it win.
 *
 * @param entries Directory entries as served by the server
 * @param roots Signing keys pinned on first use (normally the owner's), keyed by user id
 * @param orgId Organisation of the directory; certificates for any other are ignored
 * @returns Verified certificates keyed by user id
 */
export function verifyDirectory(
  entries: ReadonlyArray<DirectoryEntry>,
  roots: ReadonlyMap<string, Uint8Array>,
  orgId: string,
): Map<string, MemberCertificate> {
  const issuers = new Map(roots);
  const verified = new Map<string, MemberCertificate>();
  const rows = new Map<string, number>();

  for (const entry of entries) {
    const member = entry.userId ?? entry.certificate?.userId;

    if (member !== undefined) {
      rows.set(member, (rows.get(member) ?? 0) + 1);
    }
  }

  let changed = true;

  while (changed) {
    changed = false;

    for (const { certificate, signature, keysetVersion, userId } of entries) {
      if (
        certificate === undefined ||
        signature === undefined ||
        verified.has(certificate.userId) ||
        (userId !== undefined && certificate.userId !== userId) ||
        (rows.get(certificate.userId) ?? 0) > 1 ||
        certificate.orgId !== orgId ||
        (keysetVersion !== undefined &&
          certificate.keysetVersion !== keysetVersion)
      ) {
        continue;
      }

      const pinnedKey = roots.get(certificate.userId);

      // A root's own certificate must carry the pinned key, or the server has swapped the root's keys
      if (
        pinnedKey !== undefined &&
        !constantTimeEqual(pinnedKey, certificate.signingPublicKey)
      ) {
        continue;
      }

      if (!verifyMemberCertificate(certificate, signature, issuers)) {
        continue;
      }

      verified.set(certificate.userId, certificate);
      changed = true;

      if (
        ISSUER_ROLES.has(certificate.role) &&
        !issuers.has(certificate.userId)
      ) {
        issuers.set(certificate.userId, certificate.signingPublicKey);
      }
    }
  }

  return verified;
}

/**
 * ### trustedIssuers
 *
 * Signing keys allowed to vouch for organisation-level statements such as the recovery key:
 * the pinned roots plus every verified certificate holder with an issuer role.
 *
 * @param verified Result of {@link verifyDirectory}
 * @param roots Pinned root keys
 * @returns Issuer signing keys keyed by user id
 */
export function trustedIssuers(
  verified: ReadonlyMap<string, MemberCertificate>,
  roots: ReadonlyMap<string, Uint8Array>,
): Map<string, Uint8Array> {
  const issuers = new Map(roots);

  for (const certificate of verified.values()) {
    if (ISSUER_ROLES.has(certificate.role)) {
      issuers.set(certificate.userId, certificate.signingPublicKey);
    }
  }

  return issuers;
}
