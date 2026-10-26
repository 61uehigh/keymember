import type { Queryable } from "../../db/Database.js";
import type {
  SsoTicketRecord,
  SsoLink,
  SsoRepository,
} from "../SsoRepository.js";

interface TicketRow {
  id: string;
  secret_hash: Uint8Array;
  kind: "login" | "link";
  user_id: string;
  family_id: string | null;
  device_id: string | null;
  device_name: string | null;
  state: string;
  nonce: string;
  code_verifier: string;
  status: "pending" | "verified" | "failed" | "used";
  failure: string | null;
  subject: string | null;
  enc_refresh_token: Uint8Array | null;
  expires_at: Date;
  created_at: Date;
}

/**
 * ### toTicket
 *
 * Maps an `sso_tickets` row to an {@link SsoTicketRecord}.
 *
 * @param row Database row
 * @returns The record
 */
function toTicket(row: TicketRow): SsoTicketRecord {
  return {
    id: row.id,
    secretHash: row.secret_hash,
    kind: row.kind,
    userId: row.user_id,
    familyId: row.family_id ?? undefined,
    deviceId: row.device_id ?? undefined,
    deviceName: row.device_name ?? undefined,
    state: row.state,
    nonce: row.nonce,
    codeVerifier: row.code_verifier,
    status: row.status,
    failure: row.failure ?? undefined,
    subject: row.subject ?? undefined,
    encryptedRefreshToken: row.enc_refresh_token ?? undefined,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
  };
}

/**
 * ### PgSsoRepository
 *
 * {@link SsoRepository} on PostgreSQL.
 */
export class PgSsoRepository implements SsoRepository {
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
   * ### insertTicket
   *
   * @see {@link SsoRepository.insertTicket}
   */
  async insertTicket(
    ticket: Omit<
      SsoTicketRecord,
      "createdAt" | "encryptedRefreshToken" | "failure" | "status" | "subject"
    >,
    now: Date,
  ): Promise<void> {
    await this.#db.query("DELETE FROM sso_tickets WHERE expires_at < $1", [
      new Date(now.getTime() - 24 * 60 * 60 * 1000),
    ]);
    await this.#db.query(
      `INSERT INTO sso_tickets (id, secret_hash, kind, user_id, family_id, device_id, device_name,
                                state, nonce, code_verifier, status, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending', $11)`,
      [
        ticket.id,
        ticket.secretHash,
        ticket.kind,
        ticket.userId,
        ticket.familyId ?? null,
        ticket.deviceId ?? null,
        ticket.deviceName ?? null,
        ticket.state,
        ticket.nonce,
        ticket.codeVerifier,
        ticket.expiresAt,
      ],
    );
  }

  /**
   * ### ticket
   *
   * @see {@link SsoRepository.ticket}
   */
  async ticket(ticketId: string): Promise<SsoTicketRecord | undefined> {
    const [row] = await this.#db.query<TicketRow>(
      "SELECT * FROM sso_tickets WHERE id = $1",
      [ticketId],
    );

    return row === undefined ? undefined : toTicket(row);
  }

  /**
   * ### pendingTicket
   *
   * @see {@link SsoRepository.pendingTicket}
   */
  async pendingTicket(
    by: { id: string } | { state: string },
    now: Date,
  ): Promise<
    | (SsoTicketRecord & {
        email: string;
        boundSubject: string | undefined;
        orgId: string;
      })
    | undefined
  > {
    const [row] = await this.#db.query<
      TicketRow & { email: string; sso_subject: string | null; org_id: string }
    >(
      `SELECT t.*, u.email, u.sso_subject, m.org_id
         FROM sso_tickets t
         JOIN users u ON u.id = t.user_id
         JOIN memberships m ON m.user_id = t.user_id
        WHERE ${"id" in by ? "t.id" : "t.state"} = $1 AND t.status = 'pending' AND t.expires_at > $2`,
      ["id" in by ? by.id : by.state, now],
    );

    return row === undefined
      ? undefined
      : {
          ...toTicket(row),
          email: row.email,
          boundSubject: row.sso_subject ?? undefined,
          orgId: row.org_id,
        };
  }

  /**
   * ### failTicket
   *
   * @see {@link SsoRepository.failTicket}
   */
  async failTicket(ticketId: string, reason: string): Promise<void> {
    await this.#db.query(
      "UPDATE sso_tickets SET status = 'failed', failure = $2 WHERE id = $1 AND status = 'pending'",
      [ticketId, reason],
    );
  }

  /**
   * ### verifyTicket
   *
   * @see {@link SsoRepository.verifyTicket}
   */
  async verifyTicket(
    ticketId: string,
    subject: string,
    encryptedRefreshToken: Uint8Array,
  ): Promise<void> {
    await this.#db.query(
      `UPDATE sso_tickets SET status = 'verified', subject = $2, enc_refresh_token = $3
        WHERE id = $1 AND status = 'pending'`,
      [ticketId, subject, encryptedRefreshToken],
    );
  }

  /**
   * ### claimTicket
   *
   * @see {@link SsoRepository.claimTicket}
   */
  async claimTicket(ticketId: string): Promise<boolean> {
    const claimed = await this.#db.query(
      "UPDATE sso_tickets SET status = 'used' WHERE id = $1 AND status = 'verified' RETURNING id",
      [ticketId],
    );

    return claimed.length > 0;
  }

  /**
   * ### link
   *
   * @see {@link SsoRepository.link}
   */
  async link(familyId: string): Promise<SsoLink | undefined> {
    const [row] = await this.#db.query<{
      subject: string;
      enc_refresh_token: Uint8Array;
      checked_at: Date;
    }>(
      "SELECT subject, enc_refresh_token, checked_at FROM sso_sessions WHERE family_id = $1",
      [familyId],
    );

    return row === undefined
      ? undefined
      : {
          subject: row.subject,
          encryptedRefreshToken: row.enc_refresh_token,
          checkedAt: row.checked_at,
        };
  }

  /**
   * ### putLink
   *
   * @see {@link SsoRepository.putLink}
   */
  async putLink(
    familyId: string,
    userId: string,
    link: SsoLink,
  ): Promise<void> {
    await this.#db.query(
      `INSERT INTO sso_sessions (family_id, user_id, subject, enc_refresh_token, checked_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (family_id) DO UPDATE
         SET subject = EXCLUDED.subject, enc_refresh_token = EXCLUDED.enc_refresh_token,
             checked_at = EXCLUDED.checked_at`,
      [
        familyId,
        userId,
        link.subject,
        link.encryptedRefreshToken,
        link.checkedAt,
      ],
    );
  }

  /**
   * ### recordCheck
   *
   * @see {@link SsoRepository.recordCheck}
   */
  async recordCheck(
    familyId: string,
    at: Date,
    encryptedRefreshToken: Uint8Array | undefined,
  ): Promise<void> {
    await this.#db.query(
      "UPDATE sso_sessions SET checked_at = $2, enc_refresh_token = COALESCE($3, enc_refresh_token) WHERE family_id = $1",
      [familyId, at, encryptedRefreshToken ?? null],
    );
  }

  /**
   * ### removeLink
   *
   * @see {@link SsoRepository.removeLink}
   */
  async removeLink(familyId: string): Promise<SsoLink | undefined> {
    const [row] = await this.#db.query<{
      subject: string;
      enc_refresh_token: Uint8Array;
      checked_at: Date;
    }>(
      "DELETE FROM sso_sessions WHERE family_id = $1 RETURNING subject, enc_refresh_token, checked_at",
      [familyId],
    );

    return row === undefined
      ? undefined
      : {
          subject: row.subject,
          encryptedRefreshToken: row.enc_refresh_token,
          checkedAt: row.checked_at,
        };
  }

  /**
   * ### subjectTakenByOther
   *
   * @see {@link SsoRepository.subjectTakenByOther}
   */
  async subjectTakenByOther(subject: string, userId: string): Promise<boolean> {
    return (
      (
        await this.#db.query(
          "SELECT id FROM users WHERE sso_subject = $1 AND id <> $2",
          [subject, userId],
        )
      ).length > 0
    );
  }

  /**
   * ### bindSubject
   *
   * @see {@link SsoRepository.bindSubject}
   */
  async bindSubject(
    userId: string,
    subject: string,
  ): Promise<string | undefined> {
    const [row] = await this.#db.query<{ sso_subject: string | null }>(
      `UPDATE users SET sso_subject = COALESCE(sso_subject, $2) WHERE id = $1
        AND NOT EXISTS (SELECT 1 FROM users other WHERE other.sso_subject = $2 AND other.id <> $1)
        RETURNING sso_subject`,
      [userId, subject],
    );

    return row?.sso_subject ?? undefined;
  }
}
