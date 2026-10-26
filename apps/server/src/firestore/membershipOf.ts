import type { MembershipRole, MembershipStatus } from "../domain/membership.js";
import { COLLECTIONS } from "./collections.js";
import type { DocumentData, Documents } from "./Documents.js";
import { text } from "./fields.js";

/**
 * ### MemberOrganization
 *
 * A user's membership joined with their organisation, as SQL's
 * `JOIN memberships … JOIN organizations` gives it.
 */
export interface MemberOrganization {
  /**
   * ### orgId
   *
   * Organisation the user belongs to.
   */
  readonly orgId: string;

  /**
   * ### role
   *
   * Role in that organisation.
   */
  readonly role: MembershipRole;

  /**
   * ### status
   *
   * Membership status.
   */
  readonly status: MembershipStatus;

  /**
   * ### organization
   *
   * The organisation document's fields.
   */
  readonly organization: DocumentData;
}

/**
 * ### membershipOf
 *
 * Finds a user's membership and organisation. A user belongs to one organisation; a user with
 * no membership, or one whose organisation is gone, has none, as an inner join would drop them.
 *
 * @param docs Documents to read
 * @param userId User
 * @returns The membership with its organisation, or `undefined`
 */
export async function membershipOf(
  docs: Documents,
  userId: string,
): Promise<MemberOrganization | undefined> {
  const [membership] = await docs.find(COLLECTIONS.memberships, [
    ["userId", userId],
  ]);

  if (membership === undefined) {
    return undefined;
  }

  const orgId = text(membership.data, "orgId");
  const organization = await docs.get(COLLECTIONS.organizations, orgId);

  return organization === undefined
    ? undefined
    : {
        orgId,
        // Only membership writes store these fields, always with valid values
        role: text(membership.data, "role") as MembershipRole,
        status: text(membership.data, "status") as MembershipStatus,
        organization,
      };
}
