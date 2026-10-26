import type { MembershipRole } from "../domain/membership.js";

/**
 * ### InviteRepository
 *
 * One-time invites, stored by the hash of their token.
 */
export interface InviteRepository {
  /**
   * ### lockValid
   *
   * Locks an unused, unexpired invite.
   *
   * @param tokenHash Hash of the presented token
   * @param now Current time
   * @returns The organisation, email and role it grants, or `undefined`
   */
  lockValid(
    tokenHash: Uint8Array,
    now: Date,
  ): Promise<
    { orgId: string; email: string; role: MembershipRole } | undefined
  >;

  /**
   * ### markUsed
   *
   * Uses up an invite, keeping the invitee's proof that the keys they published are theirs.
   *
   * @param tokenHash Hash of its token
   * @param at Time of use
   * @param proof Proof made with the invite link's secret, when the invitee came by link
   */
  markUsed(tokenHash: Uint8Array, at: Date, proof?: Uint8Array): Promise<void>;

  /**
   * ### insert
   *
   * Stores an invite with the admin's signed statement of email and role.
   *
   * @param invite Token hash, organisation, email, role, creator, expiry, statement and signature
   */
  insert(invite: {
    tokenHash: Uint8Array;
    orgId: string;
    email: string;
    role: MembershipRole;
    createdBy: string;
    expiresAt: Date;
    statement: Record<string, unknown>;
    signature: Uint8Array;
  }): Promise<void>;

  /**
   * ### expireAllBy
   *
   * Ends every unused invite a member made, when they leave.
   *
   * @param userId Member who made them
   * @param at Time they stop working
   */
  expireAllBy(userId: string, at: Date): Promise<void>;
}
