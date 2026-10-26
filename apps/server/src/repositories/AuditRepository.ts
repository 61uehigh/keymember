/**
 * ### AuditAction
 *
 * Every action the server records. Client-reported events (viewed, copied, filled) are not
 * included yet; when added they must be labelled as client-reported because a client can forge them.
 */
export type AuditAction =
  | "org.bootstrapped"
  | "user.signed_up"
  | "auth.login"
  | "auth.login_failed"
  | "auth.refresh_reuse_detected"
  | "auth.sso_verified"
  | "auth.sso_failed"
  | "auth.sso_revoked"
  | "share.created"
  | "share.opened"
  | "share.revoked"
  | "account.totp_enabled"
  | "account.totp_replace_locked"
  | "account.password_changed"
  | "org.invite_created"
  | "org.member_confirmed"
  | "org.member_suspended"
  | "vault.created"
  | "vault.access_granted"
  | "vault.access_revoked"
  | "item.created"
  | "item.updated"
  | "item.deleted"
  | "org.recovery_key_set"
  | "org.policy_updated"
  | "vault.key_rotated"
  | "recovery.requested"
  | "recovery.approved"
  | "recovery.rekeyed"
  | "recovery.completed"
  | "recovery.cancelled"
  | "group.created"
  | "group.member_added"
  | "group.rotated"
  | "group.deleted";

/**
 * ### AuditEntry
 *
 * One audit record to write.
 */
export interface AuditEntry {
  /**
   * ### orgId
   *
   * Organisation the event belongs to.
   */
  readonly orgId: string;

  /**
   * ### actorId
   *
   * User who acted; `undefined` for anonymous attempts such as a failed login for an unknown email.
   */
  readonly actorId: string | undefined;

  /**
   * ### action
   *
   * What happened.
   */
  readonly action: AuditAction;

  /**
   * ### targetId
   *
   * Object acted on (user, vault or item id), when there is one.
   */
  readonly targetId?: string;

  /**
   * ### detail
   *
   * Non-secret context. Must never contain ciphertext, tokens or key material.
   */
  readonly detail?: Readonly<Record<string, string | number | boolean>>;

  /**
   * ### ip
   *
   * Client IP as seen by the server.
   */
  readonly ip: string;
}

/**
 * ### AuditEvent
 *
 * A stored audit record.
 */
export interface AuditEvent {
  readonly id: number;
  readonly actorId: string | undefined;
  readonly action: string;
  readonly targetId: string | undefined;
  readonly detail: Record<string, unknown>;
  readonly ip: string | undefined;
  readonly at: Date;
}

/**
 * ### AuditRepository
 *
 * The append-only audit log.
 */
export interface AuditRepository {
  /**
   * ### record
   *
   * Appends a record. Use the transaction of the change it describes, so both commit or roll
   * back together.
   *
   * @param entry Record to append
   */
  record(entry: AuditEntry): Promise<void>;

  /**
   * ### latest
   *
   * An organisation's newest records, newest first.
   *
   * @param orgId Organisation
   * @param limit Maximum number of records
   * @returns The records
   */
  latest(orgId: string, limit: number): Promise<Array<AuditEvent>>;
}
