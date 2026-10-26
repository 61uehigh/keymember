import type { Queryable } from "../../db/Database.js";
import { lockChangeFeed } from "./changeFeedLock.js";
import type {
  MembershipRole,
  MembershipStatus,
} from "../../domain/membership.js";
import type {
  StoredCertificate,
  DirectoryEntry,
  MembershipRepository,
} from "../MembershipRepository.js";

/**
 * ### PgMembershipRepository
 *
 * {@link MembershipRepository} on PostgreSQL.
 */
export class PgMembershipRepository implements MembershipRepository {
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
   * ### isConfirmed
   *
   * @see {@link MembershipRepository.isConfirmed}
   */
  async isConfirmed(orgId: string, userId: string): Promise<boolean> {
    return (
      (
        await this.#db.query(
          "SELECT 1 FROM memberships WHERE org_id = $1 AND user_id = $2 AND status = 'confirmed'",
          [orgId, userId],
        )
      ).length > 0
    );
  }

  /**
   * ### insert
   *
   * @see {@link MembershipRepository.insert}
   */
  async insert(
    orgId: string,
    userId: string,
    role: MembershipRole,
  ): Promise<void> {
    await this.#db.query(
      "INSERT INTO memberships (org_id, user_id, role, status) VALUES ($1, $2, $3, 'accepted')",
      [orgId, userId, role],
    );
  }

  /**
   * ### unfreeze
   *
   * @see {@link MembershipRepository.unfreeze}
   */
  async unfreeze(userId: string): Promise<void> {
    await this.#db.query(
      "UPDATE memberships SET status = 'confirmed' WHERE user_id = $1 AND status = 'recovering'",
      [userId],
    );
  }

  /**
   * ### directory
   *
   * @see {@link MembershipRepository.directory}
   */
  async directory(orgId: string): Promise<Array<DirectoryEntry>> {
    const rows = await this.#db.query<{
      user_id: string;
      email: string;
      name: string;
      role: MembershipRole;
      status: MembershipStatus;
      encryption_public_key: Uint8Array;
      signing_public_key: Uint8Array;
      keyset_version: number;
      self_signature: Uint8Array;
      certificate: StoredCertificate | null;
      certificate_signature: Uint8Array | null;
      invite_statement: Record<string, unknown> | null;
      invite_signature: Uint8Array | null;
      invite_proof: Uint8Array | null;
    }>(
      `SELECT m.user_id, u.email, u.name, m.role, m.status, u.encryption_public_key, u.signing_public_key,
              u.keyset_version, u.self_signature, m.certificate, m.certificate_signature,
              i.statement AS invite_statement, i.signature AS invite_signature, i.proof AS invite_proof
         FROM memberships m JOIN users u ON u.id = m.user_id
         LEFT JOIN LATERAL (
           SELECT statement, signature, proof FROM invites
            WHERE org_id = m.org_id AND email = u.email AND used_at IS NOT NULL
            ORDER BY used_at DESC LIMIT 1) i ON true
        WHERE m.org_id = $1
        ORDER BY u.email`,
      [orgId],
    );

    return rows.map((row) => ({
      userId: row.user_id,
      email: row.email,
      name: row.name,
      role: row.role,
      status: row.status,
      encryptionPublicKey: row.encryption_public_key,
      signingPublicKey: row.signing_public_key,
      keysetVersion: row.keyset_version,
      selfSignature: row.self_signature,
      certificate: row.certificate ?? undefined,
      certificateSignature: row.certificate_signature ?? undefined,
      invite:
        row.invite_statement === null || row.invite_signature === null
          ? undefined
          : {
              statement: row.invite_statement,
              signature: row.invite_signature,
              proof: row.invite_proof ?? undefined,
            },
    }));
  }

  /**
   * ### lockForCertification
   *
   * @see {@link MembershipRepository.lockForCertification}
   */
  async lockForCertification(userId: string): Promise<
    | {
        email: string;
        orgId: string;
        role: MembershipRole;
        status: MembershipStatus;
        encryptionPublicKey: Uint8Array;
        signingPublicKey: Uint8Array;
        keysetVersion: number;
      }
    | undefined
  > {
    const [row] = await this.#db.query<{
      email: string;
      org_id: string;
      role: MembershipRole;
      status: MembershipStatus;
      encryption_public_key: Uint8Array;
      signing_public_key: Uint8Array;
      keyset_version: number;
    }>(
      `SELECT u.email, m.org_id, m.role, m.status, u.encryption_public_key, u.signing_public_key, u.keyset_version
         FROM users u JOIN memberships m ON m.user_id = u.id
        WHERE u.id = $1
        FOR UPDATE OF m`,
      [userId],
    );

    return row === undefined
      ? undefined
      : {
          email: row.email,
          orgId: row.org_id,
          role: row.role,
          status: row.status,
          encryptionPublicKey: row.encryption_public_key,
          signingPublicKey: row.signing_public_key,
          keysetVersion: row.keyset_version,
        };
  }

  /**
   * ### certify
   *
   * @see {@link MembershipRepository.certify}
   */
  async certify(
    userId: string,
    certificate: StoredCertificate,
    signature: Uint8Array,
    by: string,
    at: Date,
  ): Promise<void> {
    await this.#db.query(
      `UPDATE memberships SET status = 'confirmed', certificate = $1, certificate_signature = $2,
              confirmed_by = $4, confirmed_at = $5
        WHERE user_id = $3`,
      [JSON.stringify(certificate), signature, userId, by, at],
    );
  }

  /**
   * ### lockRole
   *
   * @see {@link MembershipRepository.lockRole}
   */
  async lockRole(
    orgId: string,
    userId: string,
  ): Promise<MembershipRole | undefined> {
    const [row] = await this.#db.query<{ role: MembershipRole }>(
      "SELECT role FROM memberships WHERE user_id = $1 AND org_id = $2 FOR UPDATE",
      [userId, orgId],
    );

    return row?.role;
  }

  /**
   * ### suspend
   *
   * @see {@link MembershipRepository.suspend}
   */
  async suspend(orgId: string, userId: string): Promise<void> {
    await lockChangeFeed(this.#db);

    await this.#db.query(
      "UPDATE memberships SET status = 'suspended' WHERE user_id = $1 AND org_id = $2",
      [userId, orgId],
    );
  }

  /**
   * ### lockState
   *
   * @see {@link MembershipRepository.lockState}
   */
  async lockState(
    orgId: string,
    userId: string,
  ): Promise<{ role: MembershipRole; status: MembershipStatus } | undefined> {
    const [row] = await this.#db.query<{
      role: MembershipRole;
      status: MembershipStatus;
    }>(
      "SELECT role, status FROM memberships WHERE user_id = $1 AND org_id = $2 FOR UPDATE",
      [userId, orgId],
    );

    return row;
  }

  /**
   * ### status
   *
   * @see {@link MembershipRepository.status}
   */
  async status(userId: string): Promise<MembershipStatus | undefined> {
    const [row] = await this.#db.query<{ status: MembershipStatus }>(
      "SELECT status FROM memberships WHERE user_id = $1",
      [userId],
    );

    return row?.status;
  }

  /**
   * ### confirmation
   *
   * @see {@link MembershipRepository.confirmation}
   */
  async confirmation(userId: string): Promise<{
    confirmedBy: string | undefined;
    confirmedAt: Date | undefined;
  }> {
    const [row] = await this.#db.query<{
      confirmed_by: string | null;
      confirmed_at: Date | null;
    }>(
      "SELECT confirmed_by, confirmed_at FROM memberships WHERE user_id = $1",
      [userId],
    );

    return {
      confirmedBy: row?.confirmed_by ?? undefined,
      confirmedAt: row?.confirmed_at ?? undefined,
    };
  }

  /**
   * ### freeze
   *
   * @see {@link MembershipRepository.freeze}
   */
  async freeze(userId: string): Promise<boolean> {
    const rows = await this.#db.query(
      "UPDATE memberships SET status = 'recovering' WHERE user_id = $1 AND status = 'confirmed' RETURNING user_id",
      [userId],
    );

    return rows.length > 0;
  }

  /**
   * ### resetForRekey
   *
   * @see {@link MembershipRepository.resetForRekey}
   */
  async resetForRekey(userId: string): Promise<void> {
    await this.#db.query(
      "UPDATE memberships SET status = 'accepted', certificate = NULL, certificate_signature = NULL WHERE user_id = $1",
      [userId],
    );
  }
}
