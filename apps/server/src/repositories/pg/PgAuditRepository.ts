import type { Queryable } from "../../db/Database.js";
import type {
  AuditEntry,
  AuditEvent,
  AuditRepository,
} from "../AuditRepository.js";

/**
 * ### PgAuditRepository
 *
 * {@link AuditRepository} on PostgreSQL.
 */
export class PgAuditRepository implements AuditRepository {
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
   * ### record
   *
   * @see {@link AuditRepository.record}
   */
  async record(entry: AuditEntry): Promise<void> {
    await this.#db.query(
      "INSERT INTO audit_events (org_id, actor_id, action, target_id, detail, ip) VALUES ($1, $2, $3, $4, $5, $6)",
      [
        entry.orgId,
        entry.actorId ?? null,
        entry.action,
        entry.targetId ?? null,
        JSON.stringify(entry.detail ?? {}),
        entry.ip,
      ],
    );
  }

  /**
   * ### latest
   *
   * @see {@link AuditRepository.latest}
   */
  async latest(orgId: string, limit: number): Promise<Array<AuditEvent>> {
    const rows = await this.#db.query<{
      id: string;
      actor_id: string | null;
      action: string;
      target_id: string | null;
      detail: Record<string, unknown>;
      ip: string | null;
      at: Date;
    }>(
      `SELECT id, actor_id, action, target_id, detail, ip, at
         FROM audit_events WHERE org_id = $1 ORDER BY id DESC LIMIT $2`,
      [orgId, limit],
    );

    return rows.map((row) => ({
      id: Number(row.id),
      actorId: row.actor_id ?? undefined,
      action: row.action,
      targetId: row.target_id ?? undefined,
      detail: row.detail,
      ip: row.ip ?? undefined,
      at: row.at,
    }));
  }
}
