import type { Queryable } from "../../db/Database.js";
import type { VaultPermission } from "../VaultRepository.js";
import type {
  RecoveryStatus,
  AccessSnapshot,
  RecoveryRecord,
  RecoveryRepository,
} from "../RecoveryRepository.js";

interface RecoveryRow {
  id: string;
  org_id: string;
  user_id: string;
  email: string;
  requested_by: string;
  approved_by: string | null;
  status: RecoveryStatus;
  vault_snapshot: Array<{ vaultId: string; permission: VaultPermission }>;
  group_snapshot: Array<string>;
  request_signature: Uint8Array | null;
  created_at: Date;
}

const RECOVERY_SELECT = `SELECT r.id, r.org_id, r.user_id, u.email, r.requested_by, r.approved_by, r.status,
                                r.vault_snapshot, r.group_snapshot, r.request_signature, r.created_at
                           FROM recoveries r JOIN users u ON u.id = r.user_id`;

/**
 * ### toRecord
 *
 * Maps a `recoveries` row to a {@link RecoveryRecord}.
 *
 * @param row Database row
 * @returns The record
 */
function toRecord(row: RecoveryRow): RecoveryRecord {
  return {
    id: row.id,
    orgId: row.org_id,
    userId: row.user_id,
    email: row.email,
    requestedBy: row.requested_by,
    approvedBy: row.approved_by ?? undefined,
    status: row.status,
    snapshot: { vaults: row.vault_snapshot, groups: row.group_snapshot },
    requestSignature: row.request_signature ?? undefined,
    createdAt: row.created_at,
  };
}

/**
 * ### PgRecoveryRepository
 *
 * {@link RecoveryRepository} on PostgreSQL.
 */
export class PgRecoveryRepository implements RecoveryRepository {
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
   * ### cancelOpen
   *
   * @see {@link RecoveryRepository.cancelOpen}
   */
  async cancelOpen(userId: string, at: Date): Promise<Array<string>> {
    const rows = await this.#db.query<{ id: string }>(
      `UPDATE recoveries SET status = 'cancelled', token_hash = NULL, updated_at = $2
        WHERE user_id = $1 AND status IN ('pending', 'approved')
        RETURNING id`,
      [userId, at],
    );

    return rows.map((row) => row.id);
  }

  /**
   * ### cancelInvolving
   *
   * @see {@link RecoveryRepository.cancelInvolving}
   */
  async cancelInvolving(userId: string, at: Date): Promise<void> {
    await this.#db.query(
      `UPDATE recoveries SET status = 'cancelled', token_hash = NULL, updated_at = $2
        WHERE (user_id = $1 OR requested_by = $1) AND status IN ('pending', 'approved', 'rekeyed')`,
      [userId, at],
    );
  }

  /**
   * ### find
   *
   * @see {@link RecoveryRepository.find}
   */
  async find(
    orgId: string,
    recoveryId: string,
  ): Promise<RecoveryRecord | undefined> {
    const [row] = await this.#db.query<RecoveryRow>(
      `${RECOVERY_SELECT} WHERE r.id = $1 AND r.org_id = $2`,
      [recoveryId, orgId],
    );

    return row === undefined ? undefined : toRecord(row);
  }

  /**
   * ### list
   *
   * @see {@link RecoveryRepository.list}
   */
  async list(orgId: string): Promise<Array<RecoveryRecord>> {
    const rows = await this.#db.query<RecoveryRow>(
      `${RECOVERY_SELECT} WHERE r.org_id = $1 ORDER BY r.created_at DESC LIMIT 100`,
      [orgId],
    );

    return rows.map(toRecord);
  }

  /**
   * ### hasOpen
   *
   * @see {@link RecoveryRepository.hasOpen}
   */
  async hasOpen(userId: string): Promise<boolean> {
    return (
      (
        await this.#db.query(
          "SELECT 1 FROM recoveries WHERE user_id = $1 AND status IN ('pending', 'approved', 'rekeyed')",
          [userId],
        )
      ).length > 0
    );
  }

  /**
   * ### insert
   *
   * @see {@link RecoveryRepository.insert}
   */
  async insert(
    recovery: {
      id: string;
      orgId: string;
      userId: string;
      requestedBy: string;
      requestSignature: Uint8Array;
      snapshot: AccessSnapshot;
    },
    at: Date,
  ): Promise<void> {
    await this.#db.query(
      `INSERT INTO recoveries (id, org_id, user_id, requested_by, status, vault_snapshot, group_snapshot,
                               request_signature, created_at, updated_at)
       VALUES ($1, $2, $3, $4, 'pending', $5, $6, $8, $7, $7)`,
      [
        recovery.id,
        recovery.orgId,
        recovery.userId,
        recovery.requestedBy,
        JSON.stringify(recovery.snapshot.vaults),
        JSON.stringify(recovery.snapshot.groups),
        at,
        recovery.requestSignature,
      ],
    );
  }

  /**
   * ### approve
   *
   * @see {@link RecoveryRepository.approve}
   */
  async approve(
    recoveryId: string,
    approvedBy: string,
    token: { hash: Uint8Array; expiresAt: Date },
    at: Date,
  ): Promise<boolean> {
    const rows = await this.#db.query(
      `UPDATE recoveries SET status = 'approved', approved_by = $2, token_hash = $3, token_expires_at = $4, updated_at = $5
        WHERE id = $1 AND status = 'pending'
        RETURNING id`,
      [recoveryId, approvedBy, token.hash, token.expiresAt, at],
    );

    return rows.length > 0;
  }

  /**
   * ### replaceSnapshot
   *
   * @see {@link RecoveryRepository.replaceSnapshot}
   */
  async replaceSnapshot(
    recoveryId: string,
    snapshot: AccessSnapshot,
  ): Promise<void> {
    await this.#db.query(
      "UPDATE recoveries SET vault_snapshot = $2, group_snapshot = $3 WHERE id = $1",
      [
        recoveryId,
        JSON.stringify(snapshot.vaults),
        JSON.stringify(snapshot.groups),
      ],
    );
  }

  /**
   * ### cancel
   *
   * @see {@link RecoveryRepository.cancel}
   */
  async cancel(recoveryId: string, at: Date): Promise<boolean> {
    const rows = await this.#db.query(
      `UPDATE recoveries SET status = 'cancelled', token_hash = NULL, updated_at = $2
        WHERE id = $1 AND status IN ('pending', 'approved', 'rekeyed')
        RETURNING id`,
      [recoveryId, at],
    );

    return rows.length > 0;
  }

  /**
   * ### approvedByToken
   *
   * @see {@link RecoveryRepository.approvedByToken}
   */
  async approvedByToken(
    tokenHash: Uint8Array,
    now: Date,
  ): Promise<
    (RecoveryRecord & { keysetVersion: number; orgName: string }) | undefined
  > {
    const [row] = await this.#db.query<
      RecoveryRow & { keyset_version: number; org_name: string }
    >(
      `SELECT r.id, r.org_id, r.user_id, u.email, r.requested_by, r.approved_by, r.status, r.vault_snapshot,
              r.group_snapshot, r.request_signature, r.created_at, u.keyset_version, o.name AS org_name
         FROM recoveries r JOIN users u ON u.id = r.user_id JOIN organizations o ON o.id = r.org_id
        WHERE r.token_hash = $1 AND r.status = 'approved' AND r.token_expires_at > $2`,
      [tokenHash, now],
    );

    return row === undefined
      ? undefined
      : {
          ...toRecord(row),
          keysetVersion: row.keyset_version,
          orgName: row.org_name,
        };
  }

  /**
   * ### markRekeyed
   *
   * @see {@link RecoveryRepository.markRekeyed}
   */
  async markRekeyed(recoveryId: string, at: Date): Promise<boolean> {
    const rows = await this.#db.query(
      "UPDATE recoveries SET status = 'rekeyed', token_hash = NULL, updated_at = $2 WHERE id = $1 AND status = 'approved' RETURNING id",
      [recoveryId, at],
    );

    return rows.length > 0;
  }

  /**
   * ### complete
   *
   * @see {@link RecoveryRepository.complete}
   */
  async complete(recoveryId: string, at: Date): Promise<boolean> {
    const rows = await this.#db.query(
      "UPDATE recoveries SET status = 'completed', updated_at = $2 WHERE id = $1 AND status = 'rekeyed' RETURNING id",
      [recoveryId, at],
    );

    return rows.length > 0;
  }
}
