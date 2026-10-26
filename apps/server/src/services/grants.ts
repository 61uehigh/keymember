import { verifyGroupMembership, verifyKeyGrant } from "@keymember/core";
import type { GroupMembership, KeyGrant } from "@keymember/core";

import type { UserRepository } from "../repositories/UserRepository.js";
import { DomainError } from "../domain/DomainError.js";

/**
 * ### requireGrantSignature
 *
 * Checks that the caller signed the vault key they are handing out. Recipients verify the same
 * signature against the caller's certificate; checking here only catches faulty clients early.
 *
 * @param users User storage, for the caller's signing key
 * @param granterId Caller, who must have signed
 * @param grant What is granted
 * @param signature Caller's signature
 */
export async function requireGrantSignature(
  users: Pick<UserRepository, "signingPublicKey">,
  granterId: string,
  grant: KeyGrant,
  signature: Uint8Array,
): Promise<void> {
  const signingKey = await users.signingPublicKey(granterId);

  if (
    signingKey === undefined ||
    !verifyKeyGrant(signingKey, grant, signature)
  ) {
    throw new DomainError(
      "invalid",
      "bad_request",
      `Grant of vault ${grant.vaultId} to ${grant.principalId} is not signed by the caller`,
    );
  }
}

/**
 * ### requireMembershipSignature
 *
 * Checks that the caller signed the group key copy they are handing to a member. Admins verify
 * the same signature before re-wrapping a rotated group key; checking here only catches faulty
 * clients early.
 *
 * @param users User storage, for the caller's signing key
 * @param granterId Caller, who must have signed
 * @param membership What is handed out
 * @param signature Caller's signature
 */
export async function requireMembershipSignature(
  users: Pick<UserRepository, "signingPublicKey">,
  granterId: string,
  membership: GroupMembership,
  signature: Uint8Array,
): Promise<void> {
  const signingKey = await users.signingPublicKey(granterId);

  if (
    signingKey === undefined ||
    !verifyGroupMembership(signingKey, membership, signature)
  ) {
    throw new DomainError(
      "invalid",
      "bad_request",
      `Group key copy for ${membership.userId} is not signed by the caller`,
    );
  }
}
