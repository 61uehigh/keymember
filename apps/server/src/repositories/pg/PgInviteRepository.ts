import type { Queryable } from "../../db/Database.js";
import type { MembershipRole } from "../../domain/membership.js";
import type { InviteRepository } from "../InviteRepository.js";

/**
 * ### PgInviteRepository
 *
 * {@link InviteRepository} on PostgreSQL.
 */
export class PgInviteRepository implements InviteRepository {
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
   * ### lockValid
   *
   * @see {@link InviteRepository.lockValid}
   */
  async lockValid(
    tokenHash: Uint8Array,
    now: Date,
  ): Promise<
    { orgId: string; email: string; role: MembershipRole } | undefined
  > {
    const [row] = await this.#db.query<{
      org_id: string;
      email: string;
      role: MembershipRole;
    }>(
      `SELECT org_id, email, role FROM invites
        WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2
        FOR UPDATE`,
      [tokenHash, now],
    );

    return row === undefined
      ? undefined
      : { orgId: row.org_id, email: row.email, role: row.role };
  }

  /**
   * ### markUsed
   *
   * @see {@link InviteRepository.markUsed}
   */
  async markUsed(
    tokenHash: Uint8Array,
    at: Date,
    proof?: Uint8Array,
  ): Promise<void> {
    await this.#db.query(
      "UPDATE invites SET used_at = $1, proof = $3 WHERE token_hash = $2",
      [at, tokenHash, proof ?? null],
    );
  }

  /**
   * ### insert
   *
   * @see {@link InviteRepository.insert}
   */
  async insert(invite: {
    tokenHash: Uint8Array;
    orgId: string;
    email: string;
    role: MembershipRole;
    createdBy: string;
    expiresAt: Date;
    statement: Record<string, unknown>;
    signature: Uint8Array;
  }): Promise<void> {
    await this.#db.query(
      `INSERT INTO invites (token_hash, org_id, email, role, created_by, expires_at, statement, signature)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        invite.tokenHash,
        invite.orgId,
        invite.email,
        invite.role,
        invite.createdBy,
        invite.expiresAt,
        JSON.stringify(invite.statement),
        invite.signature,
      ],
    );
  }

  /**
   * ### expireAllBy
   *
   * @see {@link InviteRepository.expireAllBy}
   */
  async expireAllBy(userId: string, at: Date): Promise<void> {
    await this.#db.query(
      "UPDATE invites SET expires_at = $2 WHERE created_by = $1 AND used_at IS NULL AND expires_at > $2",
      [userId, at],
    );
  }
}
