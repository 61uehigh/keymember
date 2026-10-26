/**
 * ### VaultPermission
 *
 * Access level on a vault. `view` is enforced cryptographically (holding the key);
 * `edit` and `manage` are enforced by the server, because any key holder can produce ciphertext.
 */
export type VaultPermission = "view" | "edit" | "manage";

/**
 * ### PrincipalType
 *
 * Who a vault key is wrapped to: a member or a group.
 */
export type PrincipalType = "user" | "group";

/**
 * ### VaultKind
 *
 * A personal vault has only its owner; a shared one can be shared.
 */
export type VaultKind = "personal" | "shared";

/**
 * ### VaultGrant
 *
 * A vault key wrapped to one principal, with the granter's signature over that wrap.
 */
export interface VaultGrant {
  readonly principalType: PrincipalType;
  readonly principalId: string;
  readonly wrappedKey: Uint8Array;
  readonly permission: VaultPermission;
  readonly grantSignature: Uint8Array;
}

/**
 * ### AccessPath
 *
 * One way a user reaches a vault: their own grant, or a grant to a live group they are in.
 */
export interface AccessPath {
  readonly vaultId: string;
  readonly kind: VaultKind;
  readonly encryptedName: Uint8Array;
  /** The vault's current key generation */
  readonly keyGeneration: number;
  /** Whether a member with access left and the key should be rotated */
  readonly rotationDue: boolean;
  readonly principalType: PrincipalType;
  readonly principalId: string;
  readonly wrappedKey: Uint8Array;
  /** Generation the wrapped key belongs to */
  readonly accessGeneration: number;
  readonly permission: VaultPermission;
  /** Latest change to the grant or to the user's group membership behind it */
  readonly accessRevision: number;
  readonly grantedBy: string | undefined;
  readonly grantSignature: Uint8Array | undefined;
}

/**
 * ### StoredGrant
 *
 * A grant as stored: who can open the vault, the key generation the wrap belongs to, and the
 * member who signed it. Grants from before signatures have none.
 */
export interface StoredGrant {
  readonly principalType: PrincipalType;
  readonly principalId: string;
  readonly permission: VaultPermission;
  readonly wrappedKey: Uint8Array;
  readonly keyGeneration: number;
  readonly grantedBy: string | undefined;
  readonly grantSignature: Uint8Array | undefined;
}

/**
 * ### VaultRepository
 *
 * Storage of vaults, of who holds each vault's key (`vault_access`), and of the copy wrapped to
 * the organisation's recovery key.
 */
export interface VaultRepository {
  /**
   * ### exists
   *
   * Whether a vault id is taken.
   *
   * @param vaultId Vault id
   * @returns Whether it exists
   */
  exists(vaultId: string): Promise<boolean>;

  /**
   * ### insert
   *
   * Creates a vault at key generation 1.
   *
   * @param vault Ids, kind and encrypted name
   */
  insert(vault: {
    id: string;
    orgId: string;
    kind: VaultKind;
    encryptedName: Uint8Array;
    createdBy: string;
  }): Promise<void>;

  /**
   * ### accessOf
   *
   * Every permission a user holds on a live vault, directly and through live groups.
   *
   * @param vaultId Vault
   * @param userId User
   * @returns The vault's kind and key generation with each permission; empty without access
   */
  accessOf(
    vaultId: string,
    userId: string,
  ): Promise<
    Array<{
      permission: VaultPermission;
      kind: VaultKind;
      keyGeneration: number;
    }>
  >;

  /**
   * ### grants
   *
   * Who can open a vault, with each grant as stored, ordered by principal id.
   *
   * @param vaultId Vault
   * @returns The grants
   */
  grants(vaultId: string): Promise<Array<StoredGrant>>;

  /**
   * ### putGrant
   *
   * Adds or replaces one principal's grant.
   *
   * @param vaultId Vault
   * @param grant The wrap, permission and signature
   * @param keyGeneration Generation the wrap belongs to
   * @param grantedBy Member who signed the grant
   */
  putGrant(
    vaultId: string,
    grant: VaultGrant,
    keyGeneration: number,
    grantedBy: string,
  ): Promise<void>;

  /**
   * ### replaceGrants
   *
   * Replaces every grant of a vault, as a key rotation does.
   *
   * @param vaultId Vault
   * @param grants The new grants
   * @param keyGeneration Generation they belong to
   * @param grantedBy Member who signed them
   */
  replaceGrants(
    vaultId: string,
    grants: ReadonlyArray<VaultGrant>,
    keyGeneration: number,
    grantedBy: string,
  ): Promise<void>;

  /**
   * ### removeGrant
   *
   * Removes one principal's grant.
   *
   * @param vaultId Vault
   * @param principalId Member or group
   */
  removeGrant(vaultId: string, principalId: string): Promise<void>;

  /**
   * ### hasManager
   *
   * Whether anyone holds `manage` on a vault.
   *
   * @param vaultId Vault
   * @returns Whether a manager is left
   */
  hasManager(vaultId: string): Promise<boolean>;

  /**
   * ### leftWithoutManager
   *
   * Finds the vaults that would have no `manage` access left once a principal loses theirs.
   *
   * @param principalId Member or group about to lose access
   * @param vaultIds Vaults to check; omit for every live vault the principal can access
   * @returns Ids of the vaults that would be left without a manager
   */
  leftWithoutManager(
    principalId: string,
    vaultIds?: ReadonlyArray<string>,
  ): Promise<Array<string>>;

  /**
   * ### advanceKey
   *
   * Moves a vault to a new key generation with its re-encrypted name, and clears any pending
   * rotation flag.
   *
   * @param vaultId Vault
   * @param keyGeneration New generation
   * @param encryptedName Name under the new key
   */
  advanceKey(
    vaultId: string,
    keyGeneration: number,
    encryptedName: Uint8Array,
  ): Promise<void>;

  /**
   * ### storeRecoveryWrap
   *
   * Stores the vault key's copy for the recovery key, replacing the previous generation's.
   *
   * @param vaultId Vault
   * @param wrappedKey Vault key wrapped to the recovery public key
   * @param keyGeneration Generation of that key
   */
  storeRecoveryWrap(
    vaultId: string,
    wrappedKey: Uint8Array,
    keyGeneration: number,
  ): Promise<void>;

  /**
   * ### accessPaths
   *
   * Every way a user reaches each live vault, for sync: one row per grant to them or to a live
   * group they belong to, ordered by vault with the user's own grant first.
   *
   * @param userId User
   * @returns Access paths
   */
  accessPaths(userId: string): Promise<Array<AccessPath>>;

  /**
   * ### grantsToGroup
   *
   * The grants a group holds on live vaults, with each vault's current key generation.
   *
   * @param groupId Group
   * @returns Grants ordered by vault id
   */
  grantsToGroup(groupId: string): Promise<
    Array<{
      vaultId: string;
      wrappedKey: Uint8Array;
      keyGeneration: number;
      vaultKeyGeneration: number;
      permission: VaultPermission;
    }>
  >;

  /**
   * ### rewrapForGroup
   *
   * Replaces a group's wrapped key on one vault, keeping its permission, as a group key
   * rotation does.
   *
   * @param vaultId Vault
   * @param groupId Group
   * @param wrap New wrap, its generation and the granter's signature
   * @param grantedBy Member who signed it
   */
  rewrapForGroup(
    vaultId: string,
    groupId: string,
    wrap: {
      wrappedKey: Uint8Array;
      keyGeneration: number;
      grantSignature: Uint8Array;
    },
    grantedBy: string,
  ): Promise<void>;

  /**
   * ### removeGroupGrants
   *
   * Removes every grant a group holds, when it is deleted.
   *
   * @param groupId Group
   */
  removeGroupGrants(groupId: string): Promise<void>;

  /**
   * ### flagForRotation
   *
   * Marks every live shared vault a user could open, directly or through the given groups, as
   * due for a key rotation. Personal vaults are left out: nobody else can open them.
   *
   * @param userId User who left
   * @param groupIds Groups they were in
   * @param at Time of the flag
   * @returns The flagged vault ids
   */
  flagForRotation(
    userId: string,
    groupIds: ReadonlyArray<string>,
    at: Date,
  ): Promise<Array<string>>;

  /**
   * ### managers
   *
   * Who can manage each vault, directly or through a live group, other than one user.
   *
   * @param vaultIds Vaults
   * @param exceptUserId User to leave out
   * @returns Vault and manager pairs
   */
  managers(
    vaultIds: ReadonlyArray<string>,
    exceptUserId: string,
  ): Promise<Array<{ vaultId: string; userId: string }>>;

  /**
   * ### removeUserGrants
   *
   * Removes every grant made to a user, when they are suspended.
   *
   * @param userId User
   */
  removeUserGrants(userId: string): Promise<void>;

  /**
   * ### userGrants
   *
   * The vaults granted to a user directly, with their permissions.
   *
   * @param userId User
   * @returns Vault and permission pairs
   */
  userGrants(
    userId: string,
  ): Promise<Array<{ vaultId: string; permission: VaultPermission }>>;

  /**
   * ### liveKeyGeneration
   *
   * A live vault's current key generation.
   *
   * @param vaultId Vault
   * @returns The generation, or `undefined` for a missing or deleted vault
   */
  liveKeyGeneration(vaultId: string): Promise<number | undefined>;

  /**
   * ### recoveryCopies
   *
   * The recovery-key copies of the current keys of the given live vaults.
   *
   * @param vaultIds Vaults
   * @returns Vault, generation and wrapped key
   */
  recoveryCopies(
    vaultIds: ReadonlyArray<string>,
  ): Promise<
    Array<{ vaultId: string; keyGeneration: number; wrappedKey: Uint8Array }>
  >;
}
