import { sha256 } from "@noble/hashes/sha2.js";

import { signStatement, verifyStatement } from "./signing.js";

/**
 * ### GroupMembership
 *
 * A group's private key handed to a member, as the admin who handed it signs it. Group rotation
 * re-wraps the new key only to members whose membership an admin signed, so a server that slips
 * someone into a group's member list does not get them the next group key.
 */
export interface GroupMembership {
  /**
   * ### groupId
   *
   * Group the key belongs to.
   */
  readonly groupId: string;

  /**
   * ### keysetVersion
   *
   * Group key version the wrap belongs to.
   */
  readonly keysetVersion: number;

  /**
   * ### userId
   *
   * Member receiving the key.
   */
  readonly userId: string;

  /**
   * ### wrappedPrivateKey
   *
   * The group private key wrapped to the member; only its SHA-256 is signed.
   */
  readonly wrappedPrivateKey: Uint8Array;
}

/**
 * ### membershipStatement
 *
 * The signed form of a membership.
 *
 * @param membership Membership
 * @returns CBOR-ready map
 */
function membershipStatement(membership: GroupMembership) {
  return {
    groupId: membership.groupId,
    keysetVersion: membership.keysetVersion,
    userId: membership.userId,
    wrappedKeyHash: sha256(membership.wrappedPrivateKey),
  };
}

/**
 * ### signGroupMembership
 *
 * Signs a membership with the admin's signing key.
 *
 * @param signingPrivateKey Admin's Ed25519 seed
 * @param membership What is handed out
 * @returns The signature
 */
export function signGroupMembership(
  signingPrivateKey: Uint8Array,
  membership: GroupMembership,
): Uint8Array {
  return signStatement(
    signingPrivateKey,
    "keymember/group-membership/v1",
    membershipStatement(membership),
  );
}

/**
 * ### verifyGroupMembership
 *
 * Checks a membership signature.
 *
 * @param signingPublicKey Signer's verified signing key
 * @param membership The membership as served
 * @param signature Signature as served
 * @returns Whether the signer signed exactly this membership
 */
export function verifyGroupMembership(
  signingPublicKey: Uint8Array,
  membership: GroupMembership,
  signature: Uint8Array,
): boolean {
  return verifyStatement(
    signingPublicKey,
    "keymember/group-membership/v1",
    membershipStatement(membership),
    signature,
  );
}
