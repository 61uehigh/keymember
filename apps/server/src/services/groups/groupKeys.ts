import { verifyGroupCertificate } from "@keymember/core";
import type { GroupCertificate } from "@keymember/core";

import { b64 } from "../../http/codec.js";
import { DomainError } from "../../domain/DomainError.js";
import type {
  GroupKeyChange,
  GroupRecord,
  GroupRepository,
} from "../../repositories/GroupRepository.js";
import type { OrganizationRepository } from "../../repositories/OrganizationRepository.js";
import type { Repositories } from "../../repositories/Repositories.js";
import type { UserRepository } from "../../repositories/UserRepository.js";
import { requireMembershipSignature } from "../grants.js";

/**
 * ### MemberCopy
 *
 * A group's private key wrapped to one member, with the handing admin's signature over it.
 */
export interface MemberCopy {
  readonly userId: string;
  readonly wrappedPrivateKey: Uint8Array;
  readonly membershipSignature: Uint8Array;
}

/**
 * ### SignedGroupKey
 *
 * A group key as an admin issues it: the certificate, the admin's signature, and the private key
 * wrapped to the recovery key when the organisation has one.
 */
export interface SignedGroupKey {
  readonly certificate: GroupCertificate;
  readonly signature: Uint8Array;
  readonly recoveryWrappedKey: Uint8Array | undefined;
}

/**
 * ### storedKey
 *
 * What the group storage keeps for a signed group key.
 *
 * @param key Verified certificate, signature and recovery copy
 * @returns The stored form
 */
export function storedKey(key: SignedGroupKey): GroupKeyChange {
  return {
    name: key.certificate.name,
    encryptionPublicKey: key.certificate.encryptionPublicKey,
    keysetVersion: key.certificate.keysetVersion,
    certificate: {
      ...key.certificate,
      encryptionPublicKey: b64(key.certificate.encryptionPublicKey),
    },
    certificateSignature: key.signature,
    recoveryWrappedKey: key.recoveryWrappedKey,
  };
}

/**
 * ### findGroup
 *
 * Loads a live group of the organisation, locking it for the rest of the transaction.
 *
 * @param groups Group storage
 * @param orgId Caller's organisation
 * @param groupId Group to load
 * @returns The group
 */
export async function findGroup(
  groups: Pick<GroupRepository, "lockLive">,
  orgId: string,
  groupId: string,
): Promise<GroupRecord> {
  const group = await groups.lockLive(orgId, groupId);

  if (group === undefined) {
    throw new DomainError("not_found", "not_found", "No such group");
  }

  return group;
}

/**
 * ### checkCertificate
 *
 * Checks that a group certificate was issued by the caller for this organisation and group, at
 * the expected keyset version, that its signature verifies, and that the recovery key gets a
 * copy when the organisation has one. Clients verify certificates against their pinned roots
 * themselves; this only stops faulty clients early.
 *
 * @param repositories User and organisation storage
 * @param key Submitted certificate, signature and recovery copy
 * @param expected Values the certificate must carry
 */
export async function checkCertificate(
  repositories: {
    users: Pick<UserRepository, "signingPublicKey">;
    organizations: Pick<OrganizationRepository, "hasRecoveryKey">;
  },
  key: SignedGroupKey,
  expected: {
    orgId: string;
    groupId: string;
    issuerId: string;
    keysetVersion: number;
  },
): Promise<void> {
  const { certificate } = key;
  const issuerKey = await repositories.users.signingPublicKey(
    expected.issuerId,
  );

  if (
    issuerKey === undefined ||
    certificate.orgId !== expected.orgId ||
    certificate.groupId !== expected.groupId ||
    certificate.issuerId !== expected.issuerId ||
    certificate.keysetVersion !== expected.keysetVersion ||
    !verifyGroupCertificate(
      certificate,
      key.signature,
      new Map([[expected.issuerId, issuerKey]]),
    )
  ) {
    throw new DomainError(
      "invalid",
      "bad_request",
      "Group certificate is not valid for this group",
    );
  }

  // Recovered members could not get their groups back without a recovery copy
  if (
    key.recoveryWrappedKey === undefined &&
    (await repositories.organizations.hasRecoveryKey(expected.orgId))
  ) {
    throw new DomainError(
      "invalid",
      "bad_request",
      "This organisation has a recovery key; wrap the group key to it",
    );
  }
}

/**
 * ### insertMembers
 *
 * Stores the group's private key wrapped to each member, after checking every member is
 * confirmed in the organisation and the caller signed every copy.
 *
 * @param repositories Membership, group and user storage
 * @param caller Admin handing out the copies
 * @param groupId Group
 * @param keysetVersion Group keyset version the copies belong to
 * @param members Member copies
 */
export async function insertMembers(
  repositories: Pick<Repositories, "groups" | "memberships" | "users">,
  caller: { userId: string; orgId: string },
  groupId: string,
  keysetVersion: number,
  members: ReadonlyArray<MemberCopy>,
): Promise<void> {
  if (new Set(members.map((member) => member.userId)).size !== members.length) {
    throw new DomainError("invalid", "bad_request", "Duplicate group member");
  }

  for (const member of members) {
    if (
      !(await repositories.memberships.isConfirmed(caller.orgId, member.userId))
    ) {
      throw new DomainError(
        "invalid",
        "bad_request",
        "Groups can only contain confirmed members",
      );
    }

    await requireMembershipSignature(
      repositories.users,
      caller.userId,
      {
        groupId,
        keysetVersion,
        userId: member.userId,
        wrappedPrivateKey: member.wrappedPrivateKey,
      },
      member.membershipSignature,
    );
    await repositories.groups.putMember(
      groupId,
      member.userId,
      member.wrappedPrivateKey,
      keysetVersion,
      { grantedBy: caller.userId, signature: member.membershipSignature },
    );
  }
}
