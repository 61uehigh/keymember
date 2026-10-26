/**
 * ### MembershipRole
 *
 * Role of a member in the organisation.
 */
export type MembershipRole = "owner" | "admin" | "member";

/**
 * ### MembershipStatus
 *
 * Lifecycle of a membership: `accepted` after sign-up, `confirmed` once an admin has
 * certified the member's keys, `suspended` after removal, `recovering` while an approved
 * account recovery waits for the user to re-enrol.
 */
export type MembershipStatus =
  "accepted" | "confirmed" | "suspended" | "recovering";
