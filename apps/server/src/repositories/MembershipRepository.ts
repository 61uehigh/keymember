import type { MembershipRole, MembershipStatus } from "../domain/membership.js";

/**
 * ### StoredCertificate
 *
 * A member certificate as kept in the `certificate` jsonb column, with keys in base64url.
 */
export interface StoredCertificate {
  readonly orgId: string;
  readonly userId: string;
  readonly email: string;
  readonly encryptionPublicKey: string;
  readonly signingPublicKey: string;
  readonly keysetVersion: number;
  readonly role: MembershipRole;
  readonly issuerId: string;
  readonly issuedAt: number;
}

/**
 * ### DirectoryEntry
 *
 * A member as the directory lists them: membership, published keys, the certificate an admin
 * signed, and the signed invite they joined with.
 */
export interface DirectoryEntry {
  readonly userId: string;
  readonly email: string;
  readonly name: string;
  readonly role: MembershipRole;
  readonly status: MembershipStatus;
  readonly encryptionPublicKey: Uint8Array;
  readonly signingPublicKey: Uint8Array;
  readonly keysetVersion: number;
  readonly selfSignature: Uint8Array;
  readonly certificate: StoredCertificate | undefined;
  readonly certificateSignature: Uint8Array | undefined;
  readonly invite:
    | {
        statement: Record<string, unknown>;
        signature: Uint8Array;
        proof: Uint8Array | undefined;
      }
    | undefined;
}

/**
 * ### MembershipRepository
 *
 * Storage of who belongs to which organisation, in what role and state.
 */
export interface MembershipRepository {
  /**
   * ### isConfirmed
   *
   * Whether a user is a confirmed member of an organisation: their keys are certified and they
   * may receive vault keys.
   *
   * @param orgId Organisation
   * @param userId User
   * @returns Whether they are
   */
  isConfirmed(orgId: string, userId: string): Promise<boolean>;

  /**
   * ### insert
   *
   * Adds a member who just signed up, `accepted` until an admin certifies their keys.
   *
   * @param orgId Organisation
   * @param userId User
   * @param role Role from the invite or bootstrap
   */
  insert(orgId: string, userId: string, role: MembershipRole): Promise<void>;

  /**
   * ### unfreeze
   *
   * Returns a member frozen by an approved recovery to `confirmed`.
   *
   * @param userId Member
   */
  unfreeze(userId: string): Promise<void>;

  /**
   * ### directory
   *
   * Every member of an organisation with their published keys, certificate, and the invite
   * they last used, ordered by email.
   *
   * @param orgId Organisation
   * @returns The members
   */
  directory(orgId: string): Promise<Array<DirectoryEntry>>;

  /**
   * ### lockForCertification
   *
   * Locks a member's membership and returns what certifying them must match.
   *
   * @param userId Member
   * @returns Their membership and published keys, or `undefined`
   */
  lockForCertification(userId: string): Promise<
    | {
        email: string;
        orgId: string;
        role: MembershipRole;
        status: MembershipStatus;
        encryptionPublicKey: Uint8Array;
        signingPublicKey: Uint8Array;
        keysetVersion: number;
      }
    | undefined
  >;

  /**
   * ### certify
   *
   * Confirms a member with the certificate an admin signed for their keys.
   *
   * @param userId Member
   * @param certificate Stored certificate
   * @param signature The admin's signature
   * @param by Admin
   * @param at Time of confirmation
   */
  certify(
    userId: string,
    certificate: StoredCertificate,
    signature: Uint8Array,
    by: string,
    at: Date,
  ): Promise<void>;

  /**
   * ### lockRole
   *
   * Locks a membership and returns its role.
   *
   * @param orgId Organisation
   * @param userId Member
   * @returns The role, or `undefined` when they are not a member
   */
  lockRole(orgId: string, userId: string): Promise<MembershipRole | undefined>;

  /**
   * ### suspend
   *
   * Suspends a member.
   *
   * @param orgId Organisation
   * @param userId Member
   */
  suspend(orgId: string, userId: string): Promise<void>;

  /**
   * ### lockState
   *
   * Locks a membership and returns its role and status.
   *
   * @param orgId Organisation
   * @param userId Member
   * @returns Role and status, or `undefined` when they are not a member
   */
  lockState(
    orgId: string,
    userId: string,
  ): Promise<{ role: MembershipRole; status: MembershipStatus } | undefined>;

  /**
   * ### status
   *
   * A member's status.
   *
   * @param userId Member
   * @returns The status, or `undefined`
   */
  status(userId: string): Promise<MembershipStatus | undefined>;

  /**
   * ### confirmation
   *
   * Who confirmed a member and when.
   *
   * @param userId Member
   * @returns The confirming admin and time, either unset for an unconfirmed member
   */
  confirmation(userId: string): Promise<{
    confirmedBy: string | undefined;
    confirmedAt: Date | undefined;
  }>;

  /**
   * ### freeze
   *
   * Puts a confirmed member into `recovering` while their recovery waits for them.
   *
   * @param userId Member
   * @returns Whether they were confirmed
   */
  freeze(userId: string): Promise<boolean>;

  /**
   * ### resetForRekey
   *
   * Drops a member's certificate after they re-enrolled with new keys; an admin must certify
   * them again.
   *
   * @param userId Member
   */
  resetForRekey(userId: string): Promise<void>;
}
