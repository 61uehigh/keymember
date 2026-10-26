import type { Queryable } from "../../db/Database.js";
import { lockChangeFeed } from "./changeFeedLock.js";
import type {
  VaultPermission,
  PrincipalType,
  VaultKind,
  VaultGrant,
  AccessPath,
  VaultRepository,
  StoredGrant,
} from "../VaultRepository.js";

/**
 * ### PgVaultRepository
 *
 * {@link VaultRepository} on PostgreSQL.
 */
export class PgVaultRepository implements VaultRepository {
  readonly #db: Queryable;

  /**
   * ### constructor
   *
   * @param db Connection or transaction to work in
   */
  constructor(db: Queryable) {
    this.#db = db;
  }

  /**
   * ### exists
   *
   * @see {@link VaultRepository.exists}
   */
  async exists(vaultId: string): Promise<boolean> {
    return (
      (await this.#db.query("SELECT 1 FROM vaults WHERE id = $1", [vaultId]))
        .length > 0
    );
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
    await lockChangeFeed(this.#db);

    await this.#db.query(
      "INSERT INTO vaults (id, org_id, kind, enc_name, key_generation, created_by) VALUES ($1, $2, $3, $4, 1, $5)",
      [vault.id, vault.orgId, vault.kind, vault.encryptedName, vault.createdBy],
    );
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
    const rows = await this.#db.query<{
      permission: VaultPermission;
      kind: VaultKind;
      key_generation: number;
    }>(
      `SELECT a.permission, v.kind, v.key_generation
         FROM vault_access a JOIN vaults v ON v.id = a.vault_id
        WHERE a.vault_id = $1 AND v.deleted_at IS NULL
          AND ((a.principal_type = 'user' AND a.principal_id = $2)
            OR (a.principal_type = 'group' AND a.principal_id IN (
                  SELECT gm.group_id FROM group_members gm JOIN groups g ON g.id = gm.group_id
                   WHERE gm.user_id = $2 AND g.deleted_at IS NULL)))`,
      [vaultId, userId],
    );

    return rows.map((row) => ({
      permission: row.permission,
      kind: row.kind,
      keyGeneration: row.key_generation,
    }));
  }

  /**
   * ### grants
   *
   * @see {@link VaultRepository.grants}
   */
  async grants(vaultId: string): Promise<Array<StoredGrant>> {
    const rows = await this.#db.query<{
      principal_type: PrincipalType;
      principal_id: string;
      permission: VaultPermission;
      wrapped_key: Uint8Array;
      key_generation: number;
      granted_by: string | null;
      grant_signature: Uint8Array | null;
    }>(
      `SELECT principal_type, principal_id, permission, wrapped_key, key_generation, granted_by, grant_signature
         FROM vault_access WHERE vault_id = $1 ORDER BY principal_id`,
      [vaultId],
    );

    return rows.map((row) => ({
      principalType: row.principal_type,
      principalId: row.principal_id,
      permission: row.permission,
      wrappedKey: row.wrapped_key,
      keyGeneration: row.key_generation,
      grantedBy: row.granted_by ?? undefined,
      grantSignature: row.grant_signature ?? undefined,
    }));
  }

  /**
   * ### putGrant
   *
   * @see {@link VaultRepository.putGrant}
   */
  async putGrant(
    vaultId: string,
    grant: VaultGrant,
    keyGeneration: number,
    grantedBy: string,
  ): Promise<void> {
    await lockChangeFeed(this.#db);

    await this.#db.query(
      `INSERT INTO vault_access (vault_id, principal_type, principal_id, wrapped_key, key_generation, permission,
                                 granted_by, grant_signature)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (vault_id, principal_id) DO UPDATE
         SET wrapped_key = EXCLUDED.wrapped_key, key_generation = EXCLUDED.key_generation,
             permission = EXCLUDED.permission, granted_by = EXCLUDED.granted_by,
             grant_signature = EXCLUDED.grant_signature, revision = nextval('change_seq')`,
      [
        vaultId,
        grant.principalType,
        grant.principalId,
        grant.wrappedKey,
        keyGeneration,
        grant.permission,
        grantedBy,
        grant.grantSignature,
      ],
    );
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
    await lockChangeFeed(this.#db);

    await this.#db.query("DELETE FROM vault_access WHERE vault_id = $1", [
      vaultId,
    ]);

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
    await lockChangeFeed(this.#db);

    await this.#db.query(
      "DELETE FROM vault_access WHERE vault_id = $1 AND principal_id = $2",
      [vaultId, principalId],
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
        await this.#db.query(
          "SELECT 1 FROM vault_access WHERE vault_id = $1 AND permission = 'manage'",
          [vaultId],
        )
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
    const rows = await this.#db.query<{ vault_id: string }>(
      `SELECT a.vault_id FROM vault_access a JOIN vaults v ON v.id = a.vault_id
        WHERE a.principal_id = $1 AND v.deleted_at IS NULL
          AND ($2::text[] IS NULL OR a.vault_id = ANY($2::text[]))
          AND NOT EXISTS (
            SELECT 1 FROM vault_access o
             WHERE o.vault_id = a.vault_id AND o.principal_id <> $1 AND o.permission = 'manage')`,
      [principalId, vaultIds === undefined ? null : [...vaultIds]],
    );

    return rows.map((row) => row.vault_id);
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
    await lockChangeFeed(this.#db);

    await this.#db.query(
      "UPDATE vaults SET key_generation = $2, enc_name = $3, rotation_due_at = NULL, revision = nextval('change_seq') WHERE id = $1",
      [vaultId, keyGeneration, encryptedName],
    );
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
    await this.#db.query(
      `INSERT INTO vault_recovery (vault_id, wrapped_key, key_generation) VALUES ($1, $2, $3)
       ON CONFLICT (vault_id) DO UPDATE SET wrapped_key = EXCLUDED.wrapped_key, key_generation = EXCLUDED.key_generation`,
      [vaultId, wrappedKey, keyGeneration],
    );
  }

  /**
   * ### accessPaths
   *
   * @see {@link VaultRepository.accessPaths}
   */
  async accessPaths(userId: string): Promise<Array<AccessPath>> {
    const rows = await this.#db.query<{
      id: string;
      kind: VaultKind;
      enc_name: Uint8Array;
      key_generation: number;
      rotation_due: boolean;
      principal_type: PrincipalType;
      principal_id: string;
      wrapped_key: Uint8Array;
      access_generation: number;
      permission: VaultPermission;
      access_revision: string;
      granted_by: string | null;
      grant_signature: Uint8Array | null;
    }>(
      `SELECT v.id, v.kind, v.enc_name, v.key_generation, v.rotation_due_at IS NOT NULL AS rotation_due, a.principal_type, a.principal_id, a.wrapped_key,
              a.key_generation AS access_generation, a.permission, a.granted_by, a.grant_signature,
              GREATEST(a.revision, COALESCE(gm.revision, 0)) AS access_revision
         FROM vault_access a
         JOIN vaults v ON v.id = a.vault_id
         LEFT JOIN group_members gm
           ON a.principal_type = 'group' AND gm.group_id = a.principal_id AND gm.user_id = $1
         LEFT JOIN groups g ON g.id = gm.group_id
        WHERE v.deleted_at IS NULL
          AND ((a.principal_type = 'user' AND a.principal_id = $1)
            OR (a.principal_type = 'group' AND gm.user_id IS NOT NULL AND g.deleted_at IS NULL))
        ORDER BY v.id, a.principal_type DESC, a.principal_id`,
      [userId],
    );

    return rows.map((row) => ({
      vaultId: row.id,
      kind: row.kind,
      encryptedName: row.enc_name,
      keyGeneration: row.key_generation,
      rotationDue: row.rotation_due,
      principalType: row.principal_type,
      principalId: row.principal_id,
      wrappedKey: row.wrapped_key,
      accessGeneration: row.access_generation,
      permission: row.permission,
      accessRevision: Number(row.access_revision),
      grantedBy: row.granted_by ?? undefined,
      grantSignature: row.grant_signature ?? undefined,
    }));
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
    const rows = await this.#db.query<{
      vault_id: string;
      wrapped_key: Uint8Array;
      key_generation: number;
      vault_key_generation: number;
      permission: VaultPermission;
    }>(
      `SELECT a.vault_id, a.wrapped_key, a.key_generation, v.key_generation AS vault_key_generation, a.permission
         FROM vault_access a JOIN vaults v ON v.id = a.vault_id
        WHERE a.principal_type = 'group' AND a.principal_id = $1 AND v.deleted_at IS NULL
        ORDER BY a.vault_id`,
      [groupId],
    );

    return rows.map((row) => ({
      vaultId: row.vault_id,
      wrappedKey: row.wrapped_key,
      keyGeneration: row.key_generation,
      vaultKeyGeneration: row.vault_key_generation,
      permission: row.permission,
    }));
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
    await lockChangeFeed(this.#db);

    await this.#db.query(
      `UPDATE vault_access SET wrapped_key = $3, key_generation = $4, granted_by = $5, grant_signature = $6,
              revision = nextval('change_seq')
        WHERE vault_id = $1 AND principal_id = $2 AND principal_type = 'group'`,
      [
        vaultId,
        groupId,
        wrap.wrappedKey,
        wrap.keyGeneration,
        grantedBy,
        wrap.grantSignature,
      ],
    );
  }

  /**
   * ### removeGroupGrants
   *
   * @see {@link VaultRepository.removeGroupGrants}
   */
  async removeGroupGrants(groupId: string): Promise<void> {
    await lockChangeFeed(this.#db);

    await this.#db.query(
      "DELETE FROM vault_access WHERE principal_type = 'group' AND principal_id = $1",
      [groupId],
    );
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
    await lockChangeFeed(this.#db);

    const rows = await this.#db.query<{ vault_id: string }>(
      `UPDATE vaults SET rotation_due_at = $3
        WHERE deleted_at IS NULL AND kind = 'shared' AND id IN (
          SELECT a.vault_id FROM vault_access a
           WHERE (a.principal_type = 'user' AND a.principal_id = $1)
              OR (a.principal_type = 'group' AND a.principal_id = ANY($2::text[])))
        RETURNING id AS vault_id`,
      [userId, [...groupIds], at],
    );

    return rows.map((row) => row.vault_id);
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
    const rows = await this.#db.query<{ vault_id: string; user_id: string }>(
      `SELECT DISTINCT a.vault_id, COALESCE(gm.user_id, a.principal_id) AS user_id
         FROM vault_access a
         LEFT JOIN group_members gm ON a.principal_type = 'group' AND gm.group_id = a.principal_id
         LEFT JOIN groups g ON g.id = gm.group_id
        WHERE a.vault_id = ANY($1::text[]) AND a.permission = 'manage'
          AND (a.principal_type = 'user' OR (gm.user_id IS NOT NULL AND g.deleted_at IS NULL))
          AND COALESCE(gm.user_id, a.principal_id) <> $2`,
      [[...vaultIds], exceptUserId],
    );

    return rows.map((row) => ({ vaultId: row.vault_id, userId: row.user_id }));
  }

  /**
   * ### removeUserGrants
   *
   * @see {@link VaultRepository.removeUserGrants}
   */
  async removeUserGrants(userId: string): Promise<void> {
    await lockChangeFeed(this.#db);

    await this.#db.query(
      "DELETE FROM vault_access WHERE principal_type = 'user' AND principal_id = $1",
      [userId],
    );
  }

  /**
   * ### userGrants
   *
   * @see {@link VaultRepository.userGrants}
   */
  async userGrants(
    userId: string,
  ): Promise<Array<{ vaultId: string; permission: VaultPermission }>> {
    const rows = await this.#db.query<{
      vault_id: string;
      permission: VaultPermission;
    }>(
      "SELECT vault_id, permission FROM vault_access WHERE principal_type = 'user' AND principal_id = $1",
      [userId],
    );

    return rows.map((row) => ({
      vaultId: row.vault_id,
      permission: row.permission,
    }));
  }

  /**
   * ### liveKeyGeneration
   *
   * @see {@link VaultRepository.liveKeyGeneration}
   */
  async liveKeyGeneration(vaultId: string): Promise<number | undefined> {
    const [row] = await this.#db.query<{ key_generation: number }>(
      "SELECT key_generation FROM vaults WHERE id = $1 AND deleted_at IS NULL",
      [vaultId],
    );

    return row?.key_generation;
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
    const rows = await this.#db.query<{
      vault_id: string;
      wrapped_key: Uint8Array;
      key_generation: number;
    }>(
      `SELECT r.vault_id, r.wrapped_key, r.key_generation
         FROM vault_recovery r JOIN vaults v ON v.id = r.vault_id
        WHERE r.vault_id = ANY($1::text[]) AND v.deleted_at IS NULL AND r.key_generation = v.key_generation`,
      [[...vaultIds]],
    );

    return rows.map((row) => ({
      vaultId: row.vault_id,
      keyGeneration: row.key_generation,
      wrappedKey: row.wrapped_key,
    }));
  }
}
