import type {
  AccessPath,
  PrincipalType,
  VaultGrant,
  VaultKind,
  VaultPermission,
  VaultRepository,
  StoredGrant,
} from "../repositories/VaultRepository.js";
import { COLLECTIONS, documentId, REVISION_SEQUENCE } from "./collections.js";
import type { DocumentData, Documents } from "./Documents.js";
import {
  bytes,
  compareText,
  CorruptDocumentError,
  integer,
  optionalBytes,
  optionalDate,
  optionalText,
  text,
} from "./fields.js";
import { insertNew } from "./insertNew.js";

const VAULTS = COLLECTIONS.vaults;
const VAULT_ACCESS = COLLECTIONS.vaultAccess;
const VAULT_RECOVERY = COLLECTIONS.vaultRecovery;
const GROUPS = COLLECTIONS.groups;
const GROUP_MEMBERS = COLLECTIONS.groupMembers;

/**
 * ### FirestoreVaultRepository
 *
 * {@link VaultRepository} on Firestore. Vaults and their recovery copies are keyed by vault id,
 * grants by `vaultId:principalId`. Joins with groups and group members are done in memory.
 */
export class FirestoreVaultRepository implements VaultRepository {
  readonly #docs: Documents;

  /**
   * ### constructor
   *
   * @param docs Documents to work in, inside a transaction or not
   */
  constructor(docs: Documents) {
    this.#docs = docs;
  }

  /**
   * ### exists
   *
   * @see {@link VaultRepository.exists}
   */
  async exists(vaultId: string): Promise<boolean> {
    return (await this.#docs.get(VAULTS, vaultId)) !== undefined;
  }

  /**
   * ### insert
   *
   * @see {@link VaultRepository.insert}
   */
  async insert(vault: {
    id: string;
    orgId: string;
    kind: VaultKind;
    encryptedName: Uint8Array;
    createdBy: string;
  }): Promise<void> {
    await insertNew(this.#docs, VAULTS, vault.id, {
      id: vault.id,
      orgId: vault.orgId,
      kind: vault.kind,
      encName: vault.encryptedName,
      keyGeneration: 1,
      createdBy: vault.createdBy,
      revision: await this.#docs.nextSequence(REVISION_SEQUENCE),
      deletedAt: null,
      rotationDueAt: null,
    });
  }

  /**
   * ### accessOf
   *
   * @see {@link VaultRepository.accessOf}
   */
  async accessOf(
    vaultId: string,
    userId: string,
  ): Promise<
    Array<{
      permission: VaultPermission;
      kind: VaultKind;
      keyGeneration: number;
    }>
  > {
    const vault = await this.#liveVault(vaultId);

    if (vault === undefined) {
      return [];
    }

    const result = [];

    for (const grant of await this.#docs.find(VAULT_ACCESS, [
      ["vaultId", vaultId],
    ])) {
      const type = principalTypeOf(grant.data);
      const principalId = text(grant.data, "principalId");
      const reaches =
        type === "user"
          ? principalId === userId
          : await this.#inLiveGroup(principalId, userId);

      if (reaches) {
        result.push({
          permission: permissionOf(grant.data),
          kind: kindOf(vault),
          keyGeneration: integer(vault, "keyGeneration"),
        });
      }
    }

    return result;
  }

  /**
   * ### grants
   *
   * @see {@link VaultRepository.grants}
   */
  async grants(vaultId: string): Promise<Array<StoredGrant>> {
    return (await this.#docs.find(VAULT_ACCESS, [["vaultId", vaultId]]))
      .map((grant) => ({
        principalType: principalTypeOf(grant.data),
        principalId: text(grant.data, "principalId"),
        permission: permissionOf(grant.data),
        wrappedKey: bytes(grant.data, "wrappedKey"),
        keyGeneration: integer(grant.data, "keyGeneration"),
        grantedBy: optionalText(grant.data, "grantedBy"),
        grantSignature: optionalBytes(grant.data, "grantSignature"),
      }))
      .sort((left, right) => compareText(left.principalId, right.principalId));
  }

  /**
   * ### putGrant
   *
   * Like the SQL upsert, replacing a grant keeps the principal type it was stored with.
   *
   * @see {@link VaultRepository.putGrant}
   */
  async putGrant(
    vaultId: string,
    grant: VaultGrant,
    keyGeneration: number,
    grantedBy: string,
  ): Promise<void> {
    const id = documentId.vaultAccess(vaultId, grant.principalId);
    const existing = await this.#docs.get(VAULT_ACCESS, id);

    await this.#docs.set(VAULT_ACCESS, id, {
      vaultId,
      principalType:
        existing === undefined
          ? grant.principalType
          : principalTypeOf(existing),
      principalId: grant.principalId,
      wrappedKey: grant.wrappedKey,
      keyGeneration,
      permission: grant.permission,
      revision: await this.#docs.nextSequence(REVISION_SEQUENCE),
      grantedBy,
      grantSignature: grant.grantSignature,
    });
  }

  /**
   * ### replaceGrants
   *
   * @see {@link VaultRepository.replaceGrants}
   */
  async replaceGrants(
    vaultId: string,
    grants: ReadonlyArray<VaultGrant>,
    keyGeneration: number,
    grantedBy: string,
  ): Promise<void> {
    for (const grant of await this.#docs.find(VAULT_ACCESS, [
      ["vaultId", vaultId],
    ])) {
      await this.#docs.delete(VAULT_ACCESS, grant.id);
    }

    for (const grant of grants) {
      await this.putGrant(vaultId, grant, keyGeneration, grantedBy);
    }
  }

  /**
   * ### removeGrant
   *
   * @see {@link VaultRepository.removeGrant}
   */
  async removeGrant(vaultId: string, principalId: string): Promise<void> {
    await this.#docs.delete(
      VAULT_ACCESS,
      documentId.vaultAccess(vaultId, principalId),
    );
  }

  /**
   * ### hasManager
   *
   * @see {@link VaultRepository.hasManager}
   */
  async hasManager(vaultId: string): Promise<boolean> {
    return (
      (
        await this.#docs.find(VAULT_ACCESS, [
          ["vaultId", vaultId],
          ["permission", "manage"],
        ])
      ).length > 0
    );
  }

  /**
   * ### leftWithoutManager
   *
   * @see {@link VaultRepository.leftWithoutManager}
   */
  async leftWithoutManager(
    principalId: string,
    vaultIds?: ReadonlyArray<string>,
  ): Promise<Array<string>> {
    const wanted = vaultIds === undefined ? undefined : new Set(vaultIds);
    const result = [];

    for (const grant of await this.#docs.find(VAULT_ACCESS, [
      ["principalId", principalId],
    ])) {
      const vaultId = text(grant.data, "vaultId");

      if (
        (wanted !== undefined && !wanted.has(vaultId)) ||
        (await this.#liveVault(vaultId)) === undefined
      ) {
        continue;
      }

      const otherManagers = (
        await this.#docs.find(VAULT_ACCESS, [
          ["vaultId", vaultId],
          ["permission", "manage"],
        ])
      ).filter((other) => text(other.data, "principalId") !== principalId);

      if (otherManagers.length === 0) {
        result.push(vaultId);
      }
    }

    return result;
  }

  /**
   * ### advanceKey
   *
   * @see {@link VaultRepository.advanceKey}
   */
  async advanceKey(
    vaultId: string,
    keyGeneration: number,
    encryptedName: Uint8Array,
  ): Promise<void> {
    if ((await this.#docs.get(VAULTS, vaultId)) === undefined) {
      return;
    }

    await this.#docs.update(VAULTS, vaultId, {
      keyGeneration,
      encName: encryptedName,
      rotationDueAt: null,
      revision: await this.#docs.nextSequence(REVISION_SEQUENCE),
    });
  }

  /**
   * ### storeRecoveryWrap
   *
   * @see {@link VaultRepository.storeRecoveryWrap}
   */
  async storeRecoveryWrap(
    vaultId: string,
    wrappedKey: Uint8Array,
    keyGeneration: number,
  ): Promise<void> {
    await this.#docs.set(VAULT_RECOVERY, vaultId, {
      vaultId,
      wrappedKey,
      keyGeneration,
    });
  }

  /**
   * ### accessPaths
   *
   * @see {@link VaultRepository.accessPaths}
   */
  async accessPaths(userId: string): Promise<Array<AccessPath>> {
    // Every sync runs this: independent reads go out together, and each vault is read once
    const [own, memberships] = await Promise.all([
      this.#docs.find(VAULT_ACCESS, [
        ["principalType", "user"],
        ["principalId", userId],
      ]),
      this.#docs.find(GROUP_MEMBERS, [["userId", userId]]),
    ]);
    const throughGroups = await Promise.all(
      memberships.map(async (membership) => {
        const groupId = text(membership.data, "groupId");
        const [live, grants] = await Promise.all([
          this.#isLiveGroup(groupId),
          this.#docs.find(VAULT_ACCESS, [
            ["principalType", "group"],
            ["principalId", groupId],
          ]),
        ]);

        return live
          ? grants.map((grant) => ({
              grant: grant.data,
              memberRevision: integer(membership.data, "revision"),
            }))
          : [];
      }),
    );
    const reached: Array<{ grant: DocumentData; memberRevision: number }> = [
      ...own.map((grant) => ({ grant: grant.data, memberRevision: 0 })),
      ...throughGroups.flat(),
    ];
    const vaultIds = [
      ...new Set(reached.map(({ grant }) => text(grant, "vaultId"))),
    ];
    const vaults = new Map(
      await Promise.all(
        vaultIds.map(
          async (vaultId) => [vaultId, await this.#liveVault(vaultId)] as const,
        ),
      ),
    );
    const paths: Array<AccessPath> = [];

    for (const { grant, memberRevision } of reached) {
      const vaultId = text(grant, "vaultId");
      const vault = vaults.get(vaultId);

      if (vault === undefined) {
        continue;
      }

      paths.push({
        vaultId,
        kind: kindOf(vault),
        encryptedName: bytes(vault, "encName"),
        keyGeneration: integer(vault, "keyGeneration"),
        rotationDue: optionalDate(vault, "rotationDueAt") !== undefined,
        principalType: principalTypeOf(grant),
        principalId: text(grant, "principalId"),
        wrappedKey: bytes(grant, "wrappedKey"),
        accessGeneration: integer(grant, "keyGeneration"),
        permission: permissionOf(grant),
        accessRevision: Math.max(integer(grant, "revision"), memberRevision),
        grantedBy: optionalText(grant, "grantedBy"),
        grantSignature: optionalBytes(grant, "grantSignature"),
      });
    }

    // Vault id, then the user's own grant ("user" sorts after "group", so descending), then principal
    return paths.sort(
      (left, right) =>
        compareText(left.vaultId, right.vaultId) ||
        compareText(right.principalType, left.principalType) ||
        compareText(left.principalId, right.principalId),
    );
  }

  /**
   * ### grantsToGroup
   *
   * @see {@link VaultRepository.grantsToGroup}
   */
  async grantsToGroup(groupId: string): Promise<
    Array<{
      vaultId: string;
      wrappedKey: Uint8Array;
      keyGeneration: number;
      vaultKeyGeneration: number;
      permission: VaultPermission;
    }>
  > {
    const result = [];

    for (const grant of await this.#docs.find(VAULT_ACCESS, [
      ["principalType", "group"],
      ["principalId", groupId],
    ])) {
      const vaultId = text(grant.data, "vaultId");
      const vault = await this.#liveVault(vaultId);

      if (vault !== undefined) {
        result.push({
          vaultId,
          wrappedKey: bytes(grant.data, "wrappedKey"),
          keyGeneration: integer(grant.data, "keyGeneration"),
          vaultKeyGeneration: integer(vault, "keyGeneration"),
          permission: permissionOf(grant.data),
        });
      }
    }

    return result.sort((left, right) =>
      compareText(left.vaultId, right.vaultId),
    );
  }

  /**
   * ### rewrapForGroup
   *
   * @see {@link VaultRepository.rewrapForGroup}
   */
  async rewrapForGroup(
    vaultId: string,
    groupId: string,
    wrap: {
      wrappedKey: Uint8Array;
      keyGeneration: number;
      grantSignature: Uint8Array;
    },
    grantedBy: string,
  ): Promise<void> {
    const id = documentId.vaultAccess(vaultId, groupId);
    const grant = await this.#docs.get(VAULT_ACCESS, id);

    if (grant === undefined || principalTypeOf(grant) !== "group") {
      return;
    }

    await this.#docs.update(VAULT_ACCESS, id, {
      wrappedKey: wrap.wrappedKey,
      keyGeneration: wrap.keyGeneration,
      grantedBy,
      grantSignature: wrap.grantSignature,
      revision: await this.#docs.nextSequence(REVISION_SEQUENCE),
    });
  }

  /**
   * ### removeGroupGrants
   *
   * @see {@link VaultRepository.removeGroupGrants}
   */
  async removeGroupGrants(groupId: string): Promise<void> {
    await this.#removeGrantsTo("group", groupId);
  }

  /**
   * ### flagForRotation
   *
   * @see {@link VaultRepository.flagForRotation}
   */
  async flagForRotation(
    userId: string,
    groupIds: ReadonlyArray<string>,
    at: Date,
  ): Promise<Array<string>> {
    const vaultIds = new Set<string>();
    const principals: Array<[PrincipalType, string]> = [
      ["user", userId],
      ...groupIds.map((groupId): [PrincipalType, string] => ["group", groupId]),
    ];

    for (const [type, principalId] of principals) {
      for (const grant of await this.#docs.find(VAULT_ACCESS, [
        ["principalType", type],
        ["principalId", principalId],
      ])) {
        vaultIds.add(text(grant.data, "vaultId"));
      }
    }

    const flagged = [];

    for (const vaultId of [...vaultIds].sort(compareText)) {
      const vault = await this.#liveVault(vaultId);

      if (vault !== undefined && kindOf(vault) === "shared") {
        await this.#docs.update(VAULTS, vaultId, { rotationDueAt: at });
        flagged.push(vaultId);
      }
    }

    return flagged;
  }

  /**
   * ### managers
   *
   * @see {@link VaultRepository.managers}
   */
  async managers(
    vaultIds: ReadonlyArray<string>,
    exceptUserId: string,
  ): Promise<Array<{ vaultId: string; userId: string }>> {
    const pairs = new Map<string, { vaultId: string; userId: string }>();
    const add = (vaultId: string, userId: string): void => {
      if (userId !== exceptUserId) {
        pairs.set(`${vaultId}:${userId}`, { vaultId, userId });
      }
    };

    for (const vaultId of new Set(vaultIds)) {
      for (const grant of await this.#docs.find(VAULT_ACCESS, [
        ["vaultId", vaultId],
        ["permission", "manage"],
      ])) {
        const principalId = text(grant.data, "principalId");

        if (principalTypeOf(grant.data) === "user") {
          add(vaultId, principalId);
        } else if (await this.#isLiveGroup(principalId)) {
          for (const member of await this.#docs.find(GROUP_MEMBERS, [
            ["groupId", principalId],
          ])) {
            add(vaultId, text(member.data, "userId"));
          }
        }
      }
    }

    return [...pairs.values()];
  }

  /**
   * ### removeUserGrants
   *
   * @see {@link VaultRepository.removeUserGrants}
   */
  async removeUserGrants(userId: string): Promise<void> {
    await this.#removeGrantsTo("user", userId);
  }

  /**
   * ### userGrants
   *
   * @see {@link VaultRepository.userGrants}
   */
  async userGrants(
    userId: string,
  ): Promise<Array<{ vaultId: string; permission: VaultPermission }>> {
    return (
      await this.#docs.find(VAULT_ACCESS, [
        ["principalType", "user"],
        ["principalId", userId],
      ])
    ).map((grant) => ({
      vaultId: text(grant.data, "vaultId"),
      permission: permissionOf(grant.data),
    }));
  }

  /**
   * ### liveKeyGeneration
   *
   * @see {@link VaultRepository.liveKeyGeneration}
   */
  async liveKeyGeneration(vaultId: string): Promise<number | undefined> {
    const vault = await this.#liveVault(vaultId);

    return vault === undefined ? undefined : integer(vault, "keyGeneration");
  }

  /**
   * ### recoveryCopies
   *
   * @see {@link VaultRepository.recoveryCopies}
   */
  async recoveryCopies(
    vaultIds: ReadonlyArray<string>,
  ): Promise<
    Array<{ vaultId: string; keyGeneration: number; wrappedKey: Uint8Array }>
  > {
    const copies = [];

    for (const vaultId of new Set(vaultIds)) {
      const vault = await this.#liveVault(vaultId);
      const copy = await this.#docs.get(VAULT_RECOVERY, vaultId);

      if (
        vault !== undefined &&
        copy !== undefined &&
        integer(copy, "keyGeneration") === integer(vault, "keyGeneration")
      ) {
        copies.push({
          vaultId,
          keyGeneration: integer(copy, "keyGeneration"),
          wrappedKey: bytes(copy, "wrappedKey"),
        });
      }
    }

    return copies;
  }

  /**
   * ### #liveVault
   *
   * Reads a vault that exists and is not deleted.
   *
   * @param vaultId Vault
   * @returns Its fields, or `undefined`
   */
  async #liveVault(vaultId: string): Promise<DocumentData | undefined> {
    const vault = await this.#docs.get(VAULTS, vaultId);

    return vault === undefined || optionalDate(vault, "deletedAt") !== undefined
      ? undefined
      : vault;
  }

  /**
   * ### #isLiveGroup
   *
   * Whether a group exists and is not deleted.
   *
   * @param groupId Group
   * @returns Whether it is live
   */
  async #isLiveGroup(groupId: string): Promise<boolean> {
    const group = await this.#docs.get(GROUPS, groupId);

    return (
      group !== undefined && optionalDate(group, "deletedAt") === undefined
    );
  }

  /**
   * ### #inLiveGroup
   *
   * Whether a user belongs to a group that is not deleted.
   *
   * @param groupId Group
   * @param userId User
   * @returns Whether they are a member
   */
  async #inLiveGroup(groupId: string, userId: string): Promise<boolean> {
    return (
      (await this.#docs.get(
        GROUP_MEMBERS,
        documentId.groupMember(groupId, userId),
      )) !== undefined && (await this.#isLiveGroup(groupId))
    );
  }

  /**
   * ### #removeGrantsTo
   *
   * Removes every grant to one principal.
   *
   * @param type Whether the principal is a user or a group
   * @param principalId User or group
   */
  async #removeGrantsTo(
    type: PrincipalType,
    principalId: string,
  ): Promise<void> {
    for (const grant of await this.#docs.find(VAULT_ACCESS, [
      ["principalType", type],
      ["principalId", principalId],
    ])) {
      await this.#docs.delete(VAULT_ACCESS, grant.id);
    }
  }
}

/**
 * ### principalTypeOf
 *
 * Reads a grant's principal type.
 *
 * @param grant Grant fields
 * @returns `user` or `group`
 */
function principalTypeOf(grant: DocumentData): PrincipalType {
  const type = text(grant, "principalType");

  if (type !== "user" && type !== "group") {
    throw new CorruptDocumentError("principalType", "user or group");
  }

  return type;
}

/**
 * ### permissionOf
 *
 * Reads a grant's permission.
 *
 * @param grant Grant fields
 * @returns The permission
 */
function permissionOf(grant: DocumentData): VaultPermission {
  const permission = text(grant, "permission");

  if (
    permission !== "view" &&
    permission !== "edit" &&
    permission !== "manage"
  ) {
    throw new CorruptDocumentError("permission", "a vault permission");
  }

  return permission;
}

/**
 * ### kindOf
 *
 * Reads a vault's kind.
 *
 * @param vault Vault fields
 * @returns `personal` or `shared`
 */
function kindOf(vault: DocumentData): VaultKind {
  const kind = text(vault, "kind");

  if (kind !== "personal" && kind !== "shared") {
    throw new CorruptDocumentError("kind", "personal or shared");
  }

  return kind;
}
