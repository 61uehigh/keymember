import type { Queryable } from "../../db/Database.js";
import type {
  ShareLinkRecord,
  NewShareLink,
  ShareRepository,
} from "../ShareRepository.js";

interface ShareRow {
  id: string;
  org_id: string;
  vault_id: string;
  item_id: string;
  created_by: string;
  ciphertext: Uint8Array | null;
  access_hash: Uint8Array;
  passphrase: boolean;
  expires_at: Date;
  max_views: number;
  views: number;
  failed_attempts: number;
  revoked_at: Date | null;
  last_opened_at: Date | null;
  created_at: Date;
}

/**
 * ### toRecord
 *
 * Maps a `shares` row to a {@link ShareLinkRecord}.
 *
 * @param row Database row
 * @returns The record
 */
function toRecord(row: ShareRow): ShareLinkRecord {
  return {
    id: row.id,
    orgId: row.org_id,
    vaultId: row.vault_id,
    itemId: row.item_id,
    createdBy: row.created_by,
    ciphertext: row.ciphertext ?? undefined,
    accessHash: row.access_hash,
    passphrase: row.passphrase,
    expiresAt: row.expires_at,
    maxViews: row.max_views,
    views: row.views,
    failedAttempts: row.failed_attempts,
    revokedAt: row.revoked_at ?? undefined,
    lastOpenedAt: row.last_opened_at ?? undefined,
    createdAt: row.created_at,
  };
}

/**
 * ### PgShareRepository
 *
 * {@link ShareRepository} on PostgreSQL.
 */
export class PgShareRepository implements ShareRepository {
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
   * @see {@link ShareRepository.exists}
   */
  async exists(shareId: string): Promise<boolean> {
    return (
      (await this.#db.query("SELECT 1 FROM shares WHERE id = $1", [shareId]))
        .length > 0
    );
  }

  /**
   * ### insert
   *
   * @see {@link ShareRepository.insert}
   */
  async insert(share: NewShareLink, now: Date): Promise<void> {
    // Links that can no longer open keep no ciphertext
    await this.#db.query(
      "UPDATE shares SET ciphertext = NULL WHERE ciphertext IS NOT NULL AND expires_at <= $1",
      [now],
    );
    await this.#db.query(
      `INSERT INTO shares (id, org_id, vault_id, item_id, created_by, ciphertext, access_hash,
                           passphrase, expires_at, max_views)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        share.id,
        share.orgId,
        share.vaultId,
        share.itemId,
        share.createdBy,
        share.ciphertext,
        share.accessHash,
        share.passphrase,
        share.expiresAt,
        share.maxViews,
      ],
    );
  }

  /**
   * ### list
   *
   * @see {@link ShareRepository.list}
   */
  async list(filter: {
    orgId: string;
    createdBy?: string | undefined;
    itemId?: string | undefined;
  }): Promise<Array<ShareLinkRecord>> {
    const rows = await this.#db.query<ShareRow>(
      `SELECT * FROM shares
        WHERE org_id = $1 AND ($2::text IS NULL OR created_by = $2) AND ($3::text IS NULL OR item_id = $3)
        ORDER BY created_at DESC LIMIT 200`,
      [filter.orgId, filter.createdBy ?? null, filter.itemId ?? null],
    );

    return rows.map(toRecord);
  }

  /**
   * ### lock
   *
   * @see {@link ShareRepository.lock}
   */
  async lock(
    shareId: string,
    orgId?: string,
  ): Promise<ShareLinkRecord | undefined> {
    const [row] = await this.#db.query<ShareRow>(
      "SELECT * FROM shares WHERE id = $1 AND ($2::text IS NULL OR org_id = $2) FOR UPDATE",
      [shareId, orgId ?? null],
    );

    return row === undefined ? undefined : toRecord(row);
  }

  /**
   * ### revoke
   *
   * @see {@link ShareRepository.revoke}
   */
  async revoke(shareId: string, at: Date): Promise<void> {
    await this.#db.query(
      "UPDATE shares SET revoked_at = COALESCE(revoked_at, $2), ciphertext = NULL WHERE id = $1",
      [shareId, at],
    );
  }

  /**
   * ### revokeAllBy
   *
   * @see {@link ShareRepository.revokeAllBy}
   */
  async revokeAllBy(userId: string, at: Date): Promise<number> {
    const rows = await this.#db.query(
      `UPDATE shares SET revoked_at = $2, ciphertext = NULL
        WHERE created_by = $1 AND revoked_at IS NULL AND ciphertext IS NOT NULL
        RETURNING id`,
      [userId, at],
    );

    return rows.length;
  }

  /**
   * ### recordFailedAttempt
   *
   * @see {@link ShareRepository.recordFailedAttempt}
   */
  async recordFailedAttempt(
    shareId: string,
    failedAttempts: number,
    limit: number,
    at: Date,
  ): Promise<void> {
    await this.#db.query(
      `UPDATE shares SET failed_attempts = $2::int,
              revoked_at = CASE WHEN $2::int >= $3::int THEN $4::timestamptz ELSE revoked_at END,
              ciphertext = CASE WHEN $2::int >= $3::int THEN NULL ELSE ciphertext END
        WHERE id = $1`,
      [shareId, failedAttempts, limit, at],
    );
  }

  /**
   * ### recordView
   *
   * @see {@link ShareRepository.recordView}
   */
  async recordView(shareId: string, views: number, at: Date): Promise<void> {
    await this.#db.query(
      `UPDATE shares SET views = $2::int, last_opened_at = $3,
              ciphertext = CASE WHEN $2::int >= max_views THEN NULL ELSE ciphertext END
        WHERE id = $1`,
      [shareId, views, at],
    );
  }
}
