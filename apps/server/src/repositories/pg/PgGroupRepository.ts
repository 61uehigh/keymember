import type { Queryable } from "../../db/Database.js";
import { lockChangeFeed } from "./changeFeedLock.js";
import type {
  StoredGroupCertificate,
  GroupRecord,
  GroupKeyChange,
  HeldGroupKey,
  GroupRepository,
  MembershipSignature,
  StoredGroupMembership,
} from "../GroupRepository.js";

/**
 * ### PgGroupRepository
 *
 * {@link GroupRepository} on PostgreSQL.
 */
export class PgGroupRepository implements GroupRepository {
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
   * ### liveKeysetVersion
   *
   * @see {@link GroupRepository.liveKeysetVersion}
   */
  async liveKeysetVersion(
    orgId: string,
    groupId: string,
  ): Promise<number | undefined> {
    const [group] = await this.#db.query<{ keyset_version: number }>(
      "SELECT keyset_version FROM groups WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL",
      [orgId, groupId],
    );

    return group?.keyset_version;
  }

  /**
   * ### keysHeldBy
   *
   * @see {@link GroupRepository.keysHeldBy}
   */
  async keysHeldBy(userId: string): Promise<Array<HeldGroupKey>> {
    const rows = await this.#db.query<{
      id: string;
      name: string;
      encryption_public_key: Uint8Array;
      keyset_version: number;
      certificate: Record<string, unknown>;
      certificate_signature: Uint8Array;
      wrapped_private_key: Uint8Array;
      member_version: number;
    }>(
      `SELECT g.id, g.name, g.encryption_public_key, g.keyset_version, g.certificate, g.certificate_signature,
              gm.wrapped_private_key, gm.keyset_version AS member_version
         FROM group_members gm JOIN groups g ON g.id = gm.group_id
        WHERE gm.user_id = $1 AND g.deleted_at IS NULL
        ORDER BY g.id`,
      [userId],
    );

    return rows.map((row) => ({
      id: row.id,
      name: row.name,
      encryptionPublicKey: row.encryption_public_key,
      keysetVersion: row.keyset_version,
      certificate: row.certificate,
      certificateSignature: row.certificate_signature,
      wrappedPrivateKey: row.wrapped_private_key,
      memberKeysetVersion: row.member_version,
    }));
  }

  /**
   * ### exists
   *
   * @see {@link GroupRepository.exists}
   */
  async exists(groupId: string): Promise<boolean> {
    return (
      (await this.#db.query("SELECT 1 FROM groups WHERE id = $1", [groupId]))
        .length > 0
    );
  }

  /**
   * ### listLive
   *
   * @see {@link GroupRepository.listLive}
   */
  async listLive(orgId: string): Promise<
    Array<
      GroupRecord & {
        members: Array<{ userId: string; keysetVersion: number }>;
      }
    >
  > {
    const groups = await this.#db.query<GroupRow>(
      `SELECT ${GROUP_COLUMNS} FROM groups WHERE org_id = $1 AND deleted_at IS NULL ORDER BY name, id`,
      [orgId],
    );
    const members = await this.#db.query<{
      group_id: string;
      user_id: string;
      keyset_version: number;
    }>(
      `SELECT gm.group_id, gm.user_id, gm.keyset_version
         FROM group_members gm JOIN groups g ON g.id = gm.group_id
        WHERE g.org_id = $1 AND g.deleted_at IS NULL
        ORDER BY gm.user_id`,
      [orgId],
    );

    return groups.map((row) => ({
      ...toGroupRecord(row),
      members: members
        .filter((member) => member.group_id === row.id)
        .map((member) => ({
          userId: member.user_id,
          keysetVersion: member.keyset_version,
        })),
    }));
  }

  /**
   * ### lockLive
   *
   * @see {@link GroupRepository.lockLive}
   */
  async lockLive(
    orgId: string,
    groupId: string,
  ): Promise<GroupRecord | undefined> {
    const [row] = await this.#db.query<GroupRow>(
      `SELECT ${GROUP_COLUMNS} FROM groups WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL FOR UPDATE`,
      [groupId, orgId],
    );

    return row === undefined ? undefined : toGroupRecord(row);
  }

  /**
   * ### findLive
   *
   * @see {@link GroupRepository.findLive}
   */
  async findLive(
    orgId: string,
    groupId: string,
  ): Promise<GroupRecord | undefined> {
    const [row] = await this.#db.query<GroupRow>(
      `SELECT ${GROUP_COLUMNS} FROM groups WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`,
      [groupId, orgId],
    );

    return row === undefined ? undefined : toGroupRecord(row);
  }

  /**
   * ### insert
   *
   * @see {@link GroupRepository.insert}
   */
  async insert(
    group: GroupKeyChange & { id: string; orgId: string; createdBy: string },
  ): Promise<void> {
    await lockChangeFeed(this.#db);

    await this.#db.query(
      `INSERT INTO groups (id, org_id, name, encryption_public_key, keyset_version, certificate,
                           certificate_signature, recovery_wrapped_key, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        group.id,
        group.orgId,
        group.name,
        group.encryptionPublicKey,
        group.keysetVersion,
        JSON.stringify(group.certificate),
        group.certificateSignature,
        group.recoveryWrappedKey ?? null,
        group.createdBy,
      ],
    );
  }

  /**
   * ### changeKey
   *
   * @see {@link GroupRepository.changeKey}
   */
  async changeKey(groupId: string, key: GroupKeyChange): Promise<void> {
    await lockChangeFeed(this.#db);

    await this.#db.query(
      `UPDATE groups
          SET name = $2, encryption_public_key = $3, keyset_version = $4, certificate = $5,
              certificate_signature = $6, recovery_wrapped_key = $7, revision = nextval('change_seq')
        WHERE id = $1`,
      [
        groupId,
        key.name,
        key.encryptionPublicKey,
        key.keysetVersion,
        JSON.stringify(key.certificate),
        key.certificateSignature,
        key.recoveryWrappedKey ?? null,
      ],
    );
  }

  /**
   * ### putMember
   *
   * @see {@link GroupRepository.putMember}
   */
  async putMember(
    groupId: string,
    userId: string,
    wrappedPrivateKey: Uint8Array,
    keysetVersion: number,
    signed: MembershipSignature,
  ): Promise<void> {
    await lockChangeFeed(this.#db);

    await this.#db.query(
      `INSERT INTO group_members (group_id, user_id, wrapped_private_key, keyset_version, granted_by,
                                  membership_signature)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (group_id, user_id) DO UPDATE
         SET wrapped_private_key = EXCLUDED.wrapped_private_key, keyset_version = EXCLUDED.keyset_version,
             granted_by = EXCLUDED.granted_by, membership_signature = EXCLUDED.membership_signature,
             revision = nextval('change_seq')`,
      [
        groupId,
        userId,
        wrappedPrivateKey,
        keysetVersion,
        signed.grantedBy,
        signed.signature,
      ],
    );
  }

  /**
   * ### memberships
   *
   * @see {@link GroupRepository.memberships}
   */
  async memberships(groupId: string): Promise<Array<StoredGroupMembership>> {
    const rows = await this.#db.query<{
      user_id: string;
      wrapped_private_key: Uint8Array;
      keyset_version: number;
      granted_by: string | null;
      membership_signature: Uint8Array | null;
    }>(
      `SELECT user_id, wrapped_private_key, keyset_version, granted_by, membership_signature
         FROM group_members WHERE group_id = $1 ORDER BY user_id`,
      [groupId],
    );

    return rows.map((row) => ({
      userId: row.user_id,
      wrappedPrivateKey: row.wrapped_private_key,
      keysetVersion: row.keyset_version,
      grantedBy: row.granted_by ?? undefined,
      signature: row.membership_signature ?? undefined,
    }));
  }

  /**
   * ### memberKey
   *
   * @see {@link GroupRepository.memberKey}
   */
  async memberKey(
    groupId: string,
    userId: string,
  ): Promise<
    { wrappedPrivateKey: Uint8Array; keysetVersion: number } | undefined
  > {
    const [row] = await this.#db.query<{
      wrapped_private_key: Uint8Array;
      keyset_version: number;
    }>(
      "SELECT wrapped_private_key, keyset_version FROM group_members WHERE group_id = $1 AND user_id = $2",
      [groupId, userId],
    );

    return row === undefined
      ? undefined
      : {
          wrappedPrivateKey: row.wrapped_private_key,
          keysetVersion: row.keyset_version,
        };
  }

  /**
   * ### removeAllMembers
   *
   * @see {@link GroupRepository.removeAllMembers}
   */
  async removeAllMembers(groupId: string): Promise<void> {
    await lockChangeFeed(this.#db);

    await this.#db.query("DELETE FROM group_members WHERE group_id = $1", [
      groupId,
    ]);
  }

  /**
   * ### markDeleted
   *
   * @see {@link GroupRepository.markDeleted}
   */
  async markDeleted(groupId: string, at: Date): Promise<void> {
    await lockChangeFeed(this.#db);

    await this.#db.query(
      "UPDATE groups SET deleted_at = $2, revision = nextval('change_seq') WHERE id = $1",
      [groupId, at],
    );
  }

  /**
   * ### liveGroupsOf
   *
   * @see {@link GroupRepository.liveGroupsOf}
   */
  async liveGroupsOf(userId: string): Promise<Array<string>> {
    const rows = await this.#db.query<{ group_id: string }>(
      `SELECT gm.group_id FROM group_members gm JOIN groups g ON g.id = gm.group_id
        WHERE gm.user_id = $1 AND g.deleted_at IS NULL ORDER BY gm.group_id`,
      [userId],
    );

    return rows.map((row) => row.group_id);
  }

  /**
   * ### removeFromAll
   *
   * @see {@link GroupRepository.removeFromAll}
   */
  async removeFromAll(userId: string): Promise<void> {
    await lockChangeFeed(this.#db);

    await this.#db.query("DELETE FROM group_members WHERE user_id = $1", [
      userId,
    ]);
  }

  /**
   * ### recoveryCopies
   *
   * @see {@link GroupRepository.recoveryCopies}
   */
  async recoveryCopies(groupIds: ReadonlyArray<string>): Promise<
    Array<{
      groupId: string;
      keysetVersion: number;
      encryptionPublicKey: Uint8Array;
      recoveryWrappedKey: Uint8Array;
    }>
  > {
    const rows = await this.#db.query<{
      id: string;
      keyset_version: number;
      encryption_public_key: Uint8Array;
      recovery_wrapped_key: Uint8Array;
    }>(
      `SELECT id, keyset_version, encryption_public_key, recovery_wrapped_key FROM groups
        WHERE id = ANY($1::text[]) AND deleted_at IS NULL AND recovery_wrapped_key IS NOT NULL`,
      [[...groupIds]],
    );

    return rows.map((row) => ({
      groupId: row.id,
      keysetVersion: row.keyset_version,
      encryptionPublicKey: row.encryption_public_key,
      recoveryWrappedKey: row.recovery_wrapped_key,
    }));
  }
}

const GROUP_COLUMNS =
  "id, name, encryption_public_key, keyset_version, certificate, certificate_signature, recovery_wrapped_key";

interface GroupRow {
  id: string;
  name: string;
  encryption_public_key: Uint8Array;
  keyset_version: number;
  certificate: StoredGroupCertificate;
  certificate_signature: Uint8Array;
  recovery_wrapped_key: Uint8Array | null;
}

/**
 * ### toGroupRecord
 *
 * Maps a `groups` row to a {@link GroupRecord}.
 *
 * @param row Database row
 * @returns The record
 */
function toGroupRecord(row: GroupRow): GroupRecord {
  return {
    id: row.id,
    name: row.name,
    encryptionPublicKey: row.encryption_public_key,
    keysetVersion: row.keyset_version,
    certificate: row.certificate,
    certificateSignature: row.certificate_signature,
    recoveryWrappedKey: row.recovery_wrapped_key ?? undefined,
  };
}
