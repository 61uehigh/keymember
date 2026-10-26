import type { Queryable } from "../../db/Database.js";
import type {
  OrganizationProfile,
  OrganizationRepository,
} from "../OrganizationRepository.js";

/**
 * ### PgOrganizationRepository
 *
 * {@link OrganizationRepository} on PostgreSQL.
 */
export class PgOrganizationRepository implements OrganizationRepository {
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
   * ### hasRecoveryKey
   *
   * @see {@link OrganizationRepository.hasRecoveryKey}
   */
  async hasRecoveryKey(orgId: string): Promise<boolean> {
    const [org] = await this.#db.query<{ has_key: boolean }>(
      "SELECT recovery_public_key IS NOT NULL AS has_key FROM organizations WHERE id = $1",
      [orgId],
    );

    return org?.has_key === true;
  }

  /**
   * ### isBootstrapped
   *
   * @see {@link OrganizationRepository.isBootstrapped}
   */
  async isBootstrapped(): Promise<boolean> {
    return (
      (await this.#db.query("SELECT 1 FROM organizations LIMIT 1")).length > 0
    );
  }

  /**
   * ### lockForBootstrap
   *
   * @see {@link OrganizationRepository.lockForBootstrap}
   */
  async lockForBootstrap(): Promise<boolean> {
    await this.#db.query("LOCK TABLE organizations IN EXCLUSIVE MODE");

    return (await this.#db.query("SELECT 1 FROM organizations")).length > 0;
  }

  /**
   * ### insert
   *
   * @see {@link OrganizationRepository.insert}
   */
  async insert(orgId: string, name: string): Promise<void> {
    await this.#db.query(
      "INSERT INTO organizations (id, name) VALUES ($1, $2)",
      [orgId, name],
    );
  }

  /**
   * ### profile
   *
   * @see {@link OrganizationRepository.profile}
   */
  async profile(orgId: string): Promise<OrganizationProfile | undefined> {
    const [row] = await this.#db.query<{
      id: string;
      name: string;
      require_totp: boolean;
      require_sso: boolean;
      recovery_public_key: Uint8Array | null;
      recovery_key_signature: Uint8Array | null;
      recovery_key_signer: string | null;
    }>(
      `SELECT id, name, require_totp, require_sso, recovery_public_key, recovery_key_signature, recovery_key_signer
         FROM organizations WHERE id = $1`,
      [orgId],
    );

    return row === undefined
      ? undefined
      : {
          id: row.id,
          name: row.name,
          requireTotp: row.require_totp,
          requireSso: row.require_sso,
          recoveryKey:
            row.recovery_public_key === null ||
            row.recovery_key_signature === null ||
            row.recovery_key_signer === null
              ? undefined
              : {
                  publicKey: row.recovery_public_key,
                  signature: row.recovery_key_signature,
                  signerId: row.recovery_key_signer,
                },
        };
  }

  /**
   * ### lockRecoveryKey
   *
   * @see {@link OrganizationRepository.lockRecoveryKey}
   */
  async lockRecoveryKey(orgId: string): Promise<boolean | undefined> {
    const [row] = await this.#db.query<{ has_key: boolean }>(
      "SELECT recovery_public_key IS NOT NULL AS has_key FROM organizations WHERE id = $1 FOR UPDATE",
      [orgId],
    );

    return row?.has_key;
  }

  /**
   * ### setRecoveryKey
   *
   * @see {@link OrganizationRepository.setRecoveryKey}
   */
  async setRecoveryKey(
    orgId: string,
    key: { publicKey: Uint8Array; signature: Uint8Array; signerId: string },
  ): Promise<void> {
    await this.#db.query(
      `UPDATE organizations
          SET recovery_public_key = $2, recovery_key_signature = $3, recovery_key_signer = $4
        WHERE id = $1`,
      [orgId, key.publicKey, key.signature, key.signerId],
    );
  }

  /**
   * ### recoveryKeyCopy
   *
   * @see {@link OrganizationRepository.recoveryKeyCopy}
   */
  async recoveryKeyCopy(
    orgId: string,
    adminId: string,
  ): Promise<Uint8Array | undefined> {
    const [row] = await this.#db.query<{ wrapped_private_key: Uint8Array }>(
      "SELECT wrapped_private_key FROM recovery_key_access WHERE org_id = $1 AND admin_id = $2",
      [orgId, adminId],
    );

    return row?.wrapped_private_key;
  }

  /**
   * ### putRecoveryKeyCopy
   *
   * @see {@link OrganizationRepository.putRecoveryKeyCopy}
   */
  async putRecoveryKeyCopy(
    orgId: string,
    adminId: string,
    wrappedPrivateKey: Uint8Array,
  ): Promise<void> {
    await this.#db.query(
      `INSERT INTO recovery_key_access (org_id, admin_id, wrapped_private_key) VALUES ($1, $2, $3)
       ON CONFLICT (org_id, admin_id) DO UPDATE SET wrapped_private_key = EXCLUDED.wrapped_private_key`,
      [orgId, adminId, wrappedPrivateKey],
    );
  }

  /**
   * ### updatePolicies
   *
   * @see {@link OrganizationRepository.updatePolicies}
   */
  async updatePolicies(
    orgId: string,
    policies: {
      requireTotp?: boolean | undefined;
      requireSso?: boolean | undefined;
    },
  ): Promise<void> {
    await this.#db.query(
      `UPDATE organizations
          SET require_totp = COALESCE($2, require_totp), require_sso = COALESCE($3, require_sso)
        WHERE id = $1`,
      [orgId, policies.requireTotp ?? null, policies.requireSso ?? null],
    );
  }

  /**
   * ### removeRecoveryKeyCopies
   *
   * @see {@link OrganizationRepository.removeRecoveryKeyCopies}
   */
  async removeRecoveryKeyCopies(adminId: string): Promise<void> {
    await this.#db.query(
      "DELETE FROM recovery_key_access WHERE admin_id = $1",
      [adminId],
    );
  }
}
