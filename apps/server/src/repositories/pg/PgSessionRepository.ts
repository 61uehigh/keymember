import type { Queryable } from "../../db/Database.js";
import type {
  MembershipRole,
  MembershipStatus,
} from "../../domain/membership.js";
import type {
  NewSession,
  AuthenticatedSession,
  RefreshableSession,
  SessionRepository,
} from "../SessionRepository.js";

/**
 * ### PgSessionRepository
 *
 * {@link SessionRepository} on PostgreSQL.
 */
export class PgSessionRepository implements SessionRepository {
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
   * ### insert
   *
   * @see {@link SessionRepository.insert}
   */
  async insert(session: NewSession): Promise<void> {
    await this.#db.query(
      `INSERT INTO sessions (access_hash, refresh_hash, family_id, user_id, device_id, device_name, access_expires_at, refresh_expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        session.accessHash,
        session.refreshHash,
        session.familyId,
        session.userId,
        session.deviceId,
        session.deviceName,
        session.accessExpiresAt,
        session.refreshExpiresAt,
      ],
    );
  }

  /**
   * ### authenticate
   *
   * @see {@link SessionRepository.authenticate}
   */
  async authenticate(
    accessHash: Uint8Array,
    now: Date,
  ): Promise<AuthenticatedSession | undefined> {
    const [row] = await this.#db.query<{
      user_id: string;
      email: string;
      org_id: string;
      role: MembershipRole;
      status: MembershipStatus;
      family_id: string;
      totp_missing: boolean;
      sso_missing: boolean;
    }>(
      `SELECT s.user_id, u.email, m.org_id, m.role, m.status, s.family_id,
              (o.require_totp AND u.totp_secret IS NULL) AS totp_missing,
              (o.require_sso AND NOT EXISTS (
                 SELECT 1 FROM sso_sessions ss WHERE ss.family_id = s.family_id)) AS sso_missing
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         JOIN memberships m ON m.user_id = s.user_id
         JOIN organizations o ON o.id = m.org_id
        WHERE s.access_hash = $1 AND s.revoked_at IS NULL AND s.access_expires_at > $2`,
      [accessHash, now],
    );

    return row === undefined
      ? undefined
      : {
          userId: row.user_id,
          email: row.email,
          orgId: row.org_id,
          role: row.role,
          status: row.status,
          familyId: row.family_id,
          totpMissing: row.totp_missing,
          ssoMissing: row.sso_missing,
        };
  }

  /**
   * ### refreshTarget
   *
   * @see {@link SessionRepository.refreshTarget}
   */
  async refreshTarget(refreshHash: Uint8Array): Promise<
    | {
        familyId: string;
        userId: string;
        orgId: string;
        requireSso: boolean;
      }
    | undefined
  > {
    const [row] = await this.#db.query<{
      family_id: string;
      user_id: string;
      org_id: string;
      require_sso: boolean;
    }>(
      `SELECT s.family_id, s.user_id, m.org_id, o.require_sso
         FROM sessions s
         JOIN memberships m ON m.user_id = s.user_id
         JOIN organizations o ON o.id = m.org_id
        WHERE s.refresh_hash = $1 AND s.rotated_at IS NULL AND s.revoked_at IS NULL`,
      [refreshHash],
    );

    return row === undefined
      ? undefined
      : {
          familyId: row.family_id,
          userId: row.user_id,
          orgId: row.org_id,
          requireSso: row.require_sso,
        };
  }

  /**
   * ### lockForRefresh
   *
   * @see {@link SessionRepository.lockForRefresh}
   */
  async lockForRefresh(
    refreshHash: Uint8Array,
  ): Promise<RefreshableSession | undefined> {
    const [row] = await this.#db.query<{
      family_id: string;
      user_id: string;
      device_id: string;
      device_name: string;
      refresh_expires_at: Date;
      rotated_at: Date | null;
      revoked_at: Date | null;
      org_id: string;
    }>(
      `SELECT s.family_id, s.user_id, s.device_id, s.device_name, s.refresh_expires_at, s.rotated_at, s.revoked_at, m.org_id
         FROM sessions s JOIN memberships m ON m.user_id = s.user_id
        WHERE s.refresh_hash = $1
        FOR UPDATE OF s`,
      [refreshHash],
    );

    return row === undefined
      ? undefined
      : {
          familyId: row.family_id,
          userId: row.user_id,
          orgId: row.org_id,
          deviceId: row.device_id,
          deviceName: row.device_name,
          refreshExpiresAt: row.refresh_expires_at,
          spent: row.rotated_at !== null || row.revoked_at !== null,
        };
  }

  /**
   * ### markRotated
   *
   * @see {@link SessionRepository.markRotated}
   */
  async markRotated(refreshHash: Uint8Array, at: Date): Promise<void> {
    await this.#db.query(
      "UPDATE sessions SET rotated_at = $1, revoked_at = $1 WHERE refresh_hash = $2",
      [at, refreshHash],
    );
  }

  /**
   * ### revokeFamily
   *
   * @see {@link SessionRepository.revokeFamily}
   */
  async revokeFamily(familyId: string, at: Date): Promise<void> {
    await this.#db.query(
      "UPDATE sessions SET revoked_at = $1 WHERE family_id = $2 AND revoked_at IS NULL",
      [at, familyId],
    );
  }

  /**
   * ### revokeOthers
   *
   * @see {@link SessionRepository.revokeOthers}
   */
  async revokeOthers(
    userId: string,
    keepFamilyId: string,
    at: Date,
  ): Promise<void> {
    await this.#db.query(
      "UPDATE sessions SET revoked_at = $1 WHERE user_id = $2 AND family_id <> $3 AND revoked_at IS NULL",
      [at, userId, keepFamilyId],
    );
  }

  /**
   * ### revokeAll
   *
   * @see {@link SessionRepository.revokeAll}
   */
  async revokeAll(userId: string, at: Date): Promise<void> {
    await this.#db.query(
      "UPDATE sessions SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL",
      [at, userId],
    );
  }

  /**
   * ### isFamilyActive
   *
   * @see {@link SessionRepository.isFamilyActive}
   */
  async isFamilyActive(familyId: string): Promise<boolean> {
    return (
      (
        await this.#db.query(
          "SELECT 1 FROM sessions WHERE family_id = $1 AND revoked_at IS NULL",
          [familyId],
        )
      ).length > 0
    );
  }

  /**
   * ### knownDevice
   *
   * @see {@link SessionRepository.knownDevice}
   */
  async knownDevice(userId: string, deviceId: string): Promise<boolean> {
    return (
      (
        await this.#db.query(
          "SELECT 1 FROM sessions WHERE user_id = $1 AND device_id = $2 LIMIT 1",
          [userId, deviceId],
        )
      ).length > 0
    );
  }

  /**
   * ### purgeExpired
   *
   * @see {@link SessionRepository.purgeExpired}
   */
  async purgeExpired(now: Date, limit: number): Promise<number> {
    return (
      await this.#db.query(
        `DELETE FROM sessions WHERE access_hash IN (
           SELECT access_hash FROM sessions WHERE refresh_expires_at < $1 LIMIT $2)
         RETURNING 1`,
        [now, limit],
      )
    ).length;
  }
}
