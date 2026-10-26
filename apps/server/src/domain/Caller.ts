import type { MembershipRole } from "./membership.js";

/**
 * ### Caller
 *
 * The member a service acts for, as the HTTP edge authenticated them.
 */
export interface Caller {
  /**
   * ### userId
   *
   * The member's user id.
   */
  readonly userId: string;

  /**
   * ### orgId
   *
   * Organisation the member belongs to.
   */
  readonly orgId: string;

  /**
   * ### role
   *
   * The member's role.
   */
  readonly role: MembershipRole;

  /**
   * ### ip
   *
   * Where the request came from, for the audit log.
   */
  readonly ip: string;
}
