import type { GroupCertificate } from "@keymember/core";

/**
 * ### StoredGroupCertificate
 *
 * A group certificate as kept in the `certificate` jsonb column, with the key in base64url.
 */
export type StoredGroupCertificate = Omit<
  GroupCertificate,
  "encryptionPublicKey"
> & { readonly encryptionPublicKey: string };

/**
 * ### GroupRecord
 *
 * A live group: its current key, the certificate an admin signed for it, and the copy of its
 * private key wrapped to the organisation's recovery key.
 */
export interface GroupRecord {
  readonly id: string;
  readonly name: string;
  readonly encryptionPublicKey: Uint8Array;
  readonly keysetVersion: number;
  readonly certificate: StoredGroupCertificate;
  readonly certificateSignature: Uint8Array;
  readonly recoveryWrappedKey: Uint8Array | undefined;
}

/**
 * ### GroupKeyChange
 *
 * A group's key and certificate as a create or rotation sets them.
 */
export interface GroupKeyChange {
  readonly name: string;
  readonly encryptionPublicKey: Uint8Array;
  readonly keysetVersion: number;
  readonly certificate: StoredGroupCertificate;
  readonly certificateSignature: Uint8Array;
  readonly recoveryWrappedKey: Uint8Array | undefined;
}

/**
 * ### HeldGroupKey
 *
 * A live group a user belongs to, with their copy of its private key and the certificate
 * clients check before trusting the group's public key.
 */
export interface HeldGroupKey {
  readonly id: string;
  readonly name: string;
  readonly encryptionPublicKey: Uint8Array;
  /** The group's current key version */
  readonly keysetVersion: number;
  readonly certificate: Record<string, unknown>;
  readonly certificateSignature: Uint8Array;
  readonly wrappedPrivateKey: Uint8Array;
  /** Key version the user's copy is for; older than `keysetVersion` after a rotation */
  readonly memberKeysetVersion: number;
}

/**
 * ### MembershipSignature
 *
 * Who handed a member their copy of a group key, and their signature over it
 * (`keymember/group-membership/v1`).
 */
export interface MembershipSignature {
  readonly grantedBy: string;
  readonly signature: Uint8Array;
}

/**
 * ### StoredGroupMembership
 *
 * A member's copy of a group key as stored. Copies from before membership signatures have no
 * signer or signature, and clients treat them as unverified.
 */
export interface StoredGroupMembership {
  readonly userId: string;
  readonly wrappedPrivateKey: Uint8Array;
  readonly keysetVersion: number;
  readonly grantedBy: string | undefined;
  readonly signature: Uint8Array | undefined;
}

/**
 * ### GroupRepository
 *
 * Storage of groups, their keys and their members.
 */
export interface GroupRepository {
  /**
   * ### liveKeysetVersion
   *
   * The current key version of a live group of an organisation.
   *
   * @param orgId Organisation
   * @param groupId Group
   * @returns The version, or `undefined` when there is no such live group
   */
  liveKeysetVersion(
    orgId: string,
    groupId: string,
  ): Promise<number | undefined>;

  /**
   * ### keysHeldBy
   *
   * The live groups a user belongs to, with their copies of the group keys.
   *
   * @param userId User
   * @returns Groups ordered by id
   */
  keysHeldBy(userId: string): Promise<Array<HeldGroupKey>>;

  /**
   * ### exists
   *
   * Whether a group id is taken, by a live or a deleted group.
   *
   * @param groupId Group
   * @returns Whether it exists
   */
  exists(groupId: string): Promise<boolean>;

  /**
   * ### listLive
   *
   * An organisation's live groups with their members, ordered by name.
   *
   * @param orgId Organisation
   * @returns Groups and the key version each member holds
   */
  listLive(orgId: string): Promise<
    Array<
      GroupRecord & {
        members: Array<{ userId: string; keysetVersion: number }>;
      }
    >
  >;

  /**
   * ### lockLive
   *
   * Locks a live group of an organisation for the rest of the transaction.
   *
   * @param orgId Organisation
   * @param groupId Group
   * @returns The group, or `undefined` when there is no such live group
   */
  lockLive(orgId: string, groupId: string): Promise<GroupRecord | undefined>;

  /**
   * ### findLive
   *
   * Reads a live group of an organisation without locking it, for read-only snapshots.
   *
   * @param orgId Organisation
   * @param groupId Group
   * @returns The group, or `undefined` when there is no such live group
   */
  findLive(orgId: string, groupId: string): Promise<GroupRecord | undefined>;

  /**
   * ### insert
   *
   * Creates a group at key version 1.
   *
   * @param group Ids and key
   */
  insert(
    group: GroupKeyChange & { id: string; orgId: string; createdBy: string },
  ): Promise<void>;

  /**
   * ### changeKey
   *
   * Replaces a group's key and certificate, as a rotation does.
   *
   * @param groupId Group
   * @param key New key, version and certificate
   */
  changeKey(groupId: string, key: GroupKeyChange): Promise<void>;

  /**
   * ### putMember
   *
   * Adds a member, or replaces their copy of the group key.
   *
   * @param groupId Group
   * @param userId Member
   * @param wrappedPrivateKey Group private key wrapped to the member
   * @param keysetVersion Key version the copy is for
   * @param signed The admin who handed out the copy and their membership signature
   */
  putMember(
    groupId: string,
    userId: string,
    wrappedPrivateKey: Uint8Array,
    keysetVersion: number,
    signed: MembershipSignature,
  ): Promise<void>;

  /**
   * ### memberships
   *
   * Every member's copy of a group key, with who handed it out and their signature, so an
   * admin's client can tell members an admin added from members the server may have added.
   *
   * @param groupId Group
   * @returns The copies, ordered by user id
   */
  memberships(groupId: string): Promise<Array<StoredGroupMembership>>;

  /**
   * ### memberKey
   *
   * A member's copy of a group key.
   *
   * @param groupId Group
   * @param userId Member
   * @returns The copy and its version, or `undefined` when they are not a member
   */
  memberKey(
    groupId: string,
    userId: string,
  ): Promise<
    { wrappedPrivateKey: Uint8Array; keysetVersion: number } | undefined
  >;

  /**
   * ### removeAllMembers
   *
   * Empties a group, before a rotation lists its members again or when it is deleted.
   *
   * @param groupId Group
   */
  removeAllMembers(groupId: string): Promise<void>;

  /**
   * ### markDeleted
   *
   * Deletes a group; sync stops reporting it.
   *
   * @param groupId Group
   * @param at Time of deletion
   */
  markDeleted(groupId: string, at: Date): Promise<void>;

  /**
   * ### liveGroupsOf
   *
   * The live groups a user belongs to.
   *
   * @param userId User
   * @returns Group ids, ordered
   */
  liveGroupsOf(userId: string): Promise<Array<string>>;

  /**
   * ### removeFromAll
   *
   * Takes a user out of every group, when they are suspended.
   *
   * @param userId User
   */
  removeFromAll(userId: string): Promise<void>;

  /**
   * ### recoveryCopies
   *
   * The recovery-key copies of the current keys of the given live groups.
   *
   * @param groupIds Groups
   * @returns Group, version, public key and wrapped private key; groups without a copy are left out
   */
  recoveryCopies(groupIds: ReadonlyArray<string>): Promise<
    Array<{
      groupId: string;
      keysetVersion: number;
      encryptionPublicKey: Uint8Array;
      recoveryWrappedKey: Uint8Array;
    }>
  >;
}
