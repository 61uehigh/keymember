import type { KdfParams } from "@keymember/core";
import type { Queryable } from "../../db/Database.js";
import type {
  MembershipRole,
  MembershipStatus,
} from "../../domain/membership.js";
import type {
  NewUser,
  LoginAccount,
  UserRepository,
} from "../UserRepository.js";

/**
 * ### PgUserRepository
 *
 * {@link UserRepository} on PostgreSQL.
 */
export class PgUserRepository implements UserRepository {
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
   * ### signingPublicKey
   *
   * @see {@link UserRepository.signingPublicKey}
   */
  async signingPublicKey(userId: string): Promise<Uint8Array | undefined> {
    const [row] = await this.#db.query<{ signing_public_key: Uint8Array }>(
      "SELECT signing_public_key FROM users WHERE id = $1",
      [userId],
    );

    return row?.signing_public_key;
  }

  /**
   * ### isRegistered
   *
   * @see {@link UserRepository.isRegistered}
   */
  async isRegistered(user: {
    id: string;
    email: string;
    accountId: string;
  }): Promise<boolean> {
    return (
      (
        await this.#db.query(
          "SELECT 1 FROM users WHERE id = $1 OR email = $2 OR account_id = $3",
          [user.id, user.email, user.accountId],
        )
      ).length > 0
    );
  }

  /**
   * ### insert
   *
   * @see {@link UserRepository.insert}
   */
  async insert(user: NewUser): Promise<void> {
    await this.#db.query(
      `INSERT INTO users (id, email, name, account_id, salt, kdf, auth_public_key, enc_account_key, enc_private_keys,
                          encryption_public_key, signing_public_key, keyset_version, self_signature)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
      [
        user.id,
        user.email,
        user.name,
        user.accountId,
        user.salt,
        JSON.stringify(user.kdf),
        user.loginPublicKey,
        user.keyset.encryptedAccountKey,
        user.keyset.encryptedPrivateKeys,
        user.keyset.encryptionPublicKey,
        user.keyset.signingPublicKey,
        user.keyset.keysetVersion,
        user.keyset.selfSignature,
      ],
    );
  }

  /**
   * ### prelogin
   *
   * @see {@link UserRepository.prelogin}
   */
  async prelogin(
    email: string,
  ): Promise<
    { salt: Uint8Array; kdf: KdfParams; legacy: boolean } | undefined
  > {
    const [row] = await this.#db.query<{
      salt: Uint8Array;
      kdf: KdfParams;
      legacy: boolean;
    }>(
      "SELECT salt, kdf, auth_public_key IS NULL AS legacy FROM users WHERE email = $1",
      [email],
    );

    return row;
  }

  /**
   * ### loginAccount
   *
   * @see {@link UserRepository.loginAccount}
   */
  async loginAccount(
    by: { email: string } | { id: string },
  ): Promise<LoginAccount | undefined> {
    const [row] = await this.#db.query<{
      id: string;
      email: string;
      name: string;
      auth_verifier: Uint8Array | null;
      auth_public_key: Uint8Array | null;
      totp_secret: Uint8Array | null;
      totp_last_step: string | null;
      sso_subject: string | null;
      org_id: string;
      role: MembershipRole;
      status: MembershipStatus;
      require_sso: boolean;
      enc_account_key: Uint8Array;
      enc_private_keys: Uint8Array;
      encryption_public_key: Uint8Array;
      signing_public_key: Uint8Array;
      keyset_version: number;
      self_signature: Uint8Array;
    }>(
      `SELECT u.*, m.org_id, m.role, m.status, o.require_sso
         FROM users u
         JOIN memberships m ON m.user_id = u.id
         JOIN organizations o ON o.id = m.org_id
        WHERE ${"email" in by ? "u.email" : "u.id"} = $1`,
      ["email" in by ? by.email : by.id],
    );

    return row === undefined
      ? undefined
      : {
          id: row.id,
          email: row.email,
          name: row.name,
          authVerifier: row.auth_verifier ?? undefined,
          authPublicKey: row.auth_public_key ?? undefined,
          totpSecret: row.totp_secret ?? undefined,
          totpLastStep:
            row.totp_last_step === null
              ? undefined
              : Number(row.totp_last_step),
          ssoSubject: row.sso_subject ?? undefined,
          orgId: row.org_id,
          role: row.role,
          status: row.status,
          requireSso: row.require_sso,
          keyset: {
            encryptedAccountKey: row.enc_account_key,
            encryptedPrivateKeys: row.enc_private_keys,
            encryptionPublicKey: row.encryption_public_key,
            signingPublicKey: row.signing_public_key,
            keysetVersion: row.keyset_version,
            selfSignature: row.self_signature,
          },
        };
  }

  /**
   * ### claimTotpStep
   *
   * @see {@link UserRepository.claimTotpStep}
   */
  async claimTotpStep(userId: string, step: number): Promise<boolean> {
    const claimed = await this.#db.query(
      `UPDATE users SET totp_last_step = $1
        WHERE id = $2 AND (totp_last_step IS NULL OR totp_last_step < $1) RETURNING id`,
      [step, userId],
    );

    return claimed.length > 0;
  }

  /**
   * ### adoptLoginKey
   *
   * @see {@link UserRepository.adoptLoginKey}
   */
  async adoptLoginKey(
    userId: string,
    loginPublicKey: Uint8Array,
  ): Promise<void> {
    await this.#db.query(
      "UPDATE users SET auth_public_key = $2, auth_verifier = NULL WHERE id = $1 AND auth_public_key IS NULL",
      [userId, loginPublicKey],
    );
  }

  /**
   * ### credentialsForUpdate
   *
   * @see {@link UserRepository.credentialsForUpdate}
   */
  async credentialsForUpdate(userId: string): Promise<
    | {
        authVerifier: Uint8Array | undefined;
        authPublicKey: Uint8Array | undefined;
      }
    | undefined
  > {
    const [row] = await this.#db.query<{
      auth_verifier: Uint8Array | null;
      auth_public_key: Uint8Array | null;
    }>(
      "SELECT auth_verifier, auth_public_key FROM users WHERE id = $1 FOR UPDATE",
      [userId],
    );

    return row === undefined
      ? undefined
      : {
          authVerifier: row.auth_verifier ?? undefined,
          authPublicKey: row.auth_public_key ?? undefined,
        };
  }

  /**
   * ### changePassword
   *
   * @see {@link UserRepository.changePassword}
   */
  async changePassword(
    userId: string,
    change: {
      salt: Uint8Array;
      kdf: KdfParams;
      loginPublicKey: Uint8Array;
      encryptedAccountKey: Uint8Array;
    },
  ): Promise<void> {
    await this.#db.query(
      "UPDATE users SET salt = $1, kdf = $2, auth_public_key = $3, auth_verifier = NULL, enc_account_key = $4 WHERE id = $5",
      [
        change.salt,
        JSON.stringify(change.kdf),
        change.loginPublicKey,
        change.encryptedAccountKey,
        userId,
      ],
    );
  }

  /**
   * ### totpState
   *
   * @see {@link UserRepository.totpState}
   */
  async totpState(userId: string): Promise<
    | {
        pendingSecret: Uint8Array | undefined;
        secret: Uint8Array | undefined;
        lastStep: number | undefined;
      }
    | undefined
  > {
    const [row] = await this.#db.query<{
      totp_pending_secret: Uint8Array | null;
      totp_secret: Uint8Array | null;
      totp_last_step: string | null;
    }>(
      "SELECT totp_pending_secret, totp_secret, totp_last_step FROM users WHERE id = $1",
      [userId],
    );

    return row === undefined
      ? undefined
      : {
          pendingSecret: row.totp_pending_secret ?? undefined,
          secret: row.totp_secret ?? undefined,
          lastStep:
            row.totp_last_step === null
              ? undefined
              : Number(row.totp_last_step),
        };
  }

  /**
   * ### setPendingTotp
   *
   * @see {@link UserRepository.setPendingTotp}
   */
  async setPendingTotp(userId: string, secret: Uint8Array): Promise<void> {
    await this.#db.query(
      "UPDATE users SET totp_pending_secret = $1 WHERE id = $2",
      [secret, userId],
    );
  }

  /**
   * ### confirmTotp
   *
   * @see {@link UserRepository.confirmTotp}
   */
  async confirmTotp(userId: string, step: number): Promise<void> {
    await this.#db.query(
      "UPDATE users SET totp_secret = totp_pending_secret, totp_pending_secret = NULL, totp_last_step = $1 WHERE id = $2",
      [step, userId],
    );
  }

  /**
   * ### accountIdTakenByOther
   *
   * @see {@link UserRepository.accountIdTakenByOther}
   */
  async accountIdTakenByOther(
    accountId: string,
    userId: string,
  ): Promise<boolean> {
    return (
      (
        await this.#db.query(
          "SELECT 1 FROM users WHERE account_id = $1 AND id <> $2",
          [accountId, userId],
        )
      ).length > 0
    );
  }

  /**
   * ### rekey
   *
   * @see {@link UserRepository.rekey}
   */
  async rekey(
    userId: string,
    rekey: Omit<NewUser, "email" | "id" | "name">,
  ): Promise<void> {
    await this.#db.query(
      `UPDATE users
          SET account_id = $2, salt = $3, kdf = $4, auth_public_key = $5, auth_verifier = NULL, enc_account_key = $6, enc_private_keys = $7,
              encryption_public_key = $8, signing_public_key = $9, keyset_version = $10, self_signature = $11,
              totp_secret = NULL, totp_pending_secret = NULL, totp_last_step = NULL,
              trusted_roots = NULL, trusted_roots_signature = NULL
        WHERE id = $1`,
      [
        userId,
        rekey.accountId,
        rekey.salt,
        JSON.stringify(rekey.kdf),
        rekey.loginPublicKey,
        rekey.keyset.encryptedAccountKey,
        rekey.keyset.encryptedPrivateKeys,
        rekey.keyset.encryptionPublicKey,
        rekey.keyset.signingPublicKey,
        rekey.keyset.keysetVersion,
        rekey.keyset.selfSignature,
      ],
    );
  }

  /**
   * ### trustedRoots
   *
   * @see {@link UserRepository.trustedRoots}
   */
  async trustedRoots(
    userId: string,
  ): Promise<
    { statement: Record<string, unknown>; signature: Uint8Array } | undefined
  > {
    const [row] = await this.#db.query<{
      trusted_roots: Record<string, unknown> | null;
      trusted_roots_signature: Uint8Array | null;
    }>(
      "SELECT trusted_roots, trusted_roots_signature FROM users WHERE id = $1",
      [userId],
    );

    return row?.trusted_roots == null || row.trusted_roots_signature === null
      ? undefined
      : {
          statement: row.trusted_roots,
          signature: row.trusted_roots_signature,
        };
  }

  /**
   * ### setTrustedRoots
   *
   * @see {@link UserRepository.setTrustedRoots}
   */
  async setTrustedRoots(
    userId: string,
    statement: Record<string, unknown>,
    signature: Uint8Array,
  ): Promise<void> {
    await this.#db.query(
      "UPDATE users SET trusted_roots = $2, trusted_roots_signature = $3 WHERE id = $1",
      [userId, JSON.stringify(statement), signature],
    );
  }
}
