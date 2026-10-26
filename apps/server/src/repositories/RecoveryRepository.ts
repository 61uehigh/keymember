import type { VaultPermission } from "./VaultRepository.js";

/**
 * ### RecoveryStatus
 *
 * Lifecycle of an account recovery:
 * `pending` (requested by one admin) → `approved` (a second admin agreed; the account is
 * frozen and a one-time token exists) → `rekeyed` (the user enrolled new credentials and
 * keys) → `completed` (an admin re-wrapped the user's vault keys). `cancelled` ends it early.
 */
export type RecoveryStatus =
  "pending" | "approved" | "rekeyed" | "completed" | "cancelled";

/**
 * ### AccessSnapshot
 *
 * What a member could open when their recovery was requested or approved; completing the
 * recovery restores exactly this, never more.
 */
export interface AccessSnapshot {
  readonly vaults: ReadonlyArray<{
    vaultId: string;
    permission: VaultPermission;
  }>;
  readonly groups: ReadonlyArray<string>;
}

/**
 * ### RecoveryRecord
 *
 * A recovery as stored, with the email of the member being recovered.
 */
export interface RecoveryRecord {
  readonly id: string;
  readonly orgId: string;
  readonly userId: string;
  readonly email: string;
  readonly requestedBy: string;
  readonly approvedBy: string | undefined;
  readonly status: RecoveryStatus;
  readonly snapshot: AccessSnapshot;
  /** The requesting admin's signature over the request */
  readonly requestSignature: Uint8Array | undefined;
  readonly createdAt: Date;
}

/**
 * ### RecoveryRepository
 *
 * Account recoveries: requested by one admin, approved by another, completed after the user
 * re-enrols.
 */
export interface RecoveryRepository {
  /**
   * ### cancelOpen
   *
   * Cancels a user's `pending` and `approved` recoveries.
   *
   * @param userId User being recovered
   * @param at Time of cancellation
   * @returns Ids of the recoveries cancelled
   */
  cancelOpen(userId: string, at: Date): Promise<Array<string>>;

  /**
   * ### cancelInvolving
   *
   * Cancels every unfinished recovery of a user and every one they requested as an admin, when
   * they are suspended.
   *
   * @param userId User
   * @param at Time of cancellation
   */
  cancelInvolving(userId: string, at: Date): Promise<void>;

  /**
   * ### find
   *
   * A recovery of an organisation.
   *
   * @param orgId Organisation
   * @param recoveryId Recovery
   * @returns The recovery, or `undefined`
   */
  find(orgId: string, recoveryId: string): Promise<RecoveryRecord | undefined>;

  /**
   * ### list
   *
   * An organisation's latest 100 recoveries, newest first.
   *
   * @param orgId Organisation
   * @returns The recoveries
   */
  list(orgId: string): Promise<Array<RecoveryRecord>>;

  /**
   * ### hasOpen
   *
   * Whether a member has a recovery that has not finished.
   *
   * @param userId Member
   * @returns Whether one is pending, approved or rekeyed
   */
  hasOpen(userId: string): Promise<boolean>;

  /**
   * ### insert
   *
   * Opens a pending recovery with the requesting admin's signature and a snapshot of what the
   * member can open now.
   *
   * @param recovery The request
   * @param at Time of the request
   */
  insert(
    recovery: {
      id: string;
      orgId: string;
      userId: string;
      requestedBy: string;
      requestSignature: Uint8Array;
      snapshot: AccessSnapshot;
    },
    at: Date,
  ): Promise<void>;

  /**
   * ### approve
   *
   * Approves a pending recovery and stores the hash of the one-time token for the user.
   *
   * @param recoveryId Recovery
   * @param approvedBy Second admin
   * @param token Token hash and expiry
   * @param at Time of approval
   * @returns Whether it was still pending
   */
  approve(
    recoveryId: string,
    approvedBy: string,
    token: { hash: Uint8Array; expiresAt: Date },
    at: Date,
  ): Promise<boolean>;

  /**
   * ### replaceSnapshot
   *
   * Updates what a recovery will restore.
   *
   * @param recoveryId Recovery
   * @param snapshot New snapshot
   */
  replaceSnapshot(recoveryId: string, snapshot: AccessSnapshot): Promise<void>;

  /**
   * ### cancel
   *
   * Cancels a recovery that has not finished.
   *
   * @param recoveryId Recovery
   * @param at Time of cancellation
   * @returns Whether it was still open
   */
  cancel(recoveryId: string, at: Date): Promise<boolean>;

  /**
   * ### approvedByToken
   *
   * The approved recovery an unexpired one-time token belongs to.
   *
   * @param tokenHash Hash of the presented token
   * @param now Current time
   * @returns The recovery with the user's current key version and the organisation's name
   */
  approvedByToken(
    tokenHash: Uint8Array,
    now: Date,
  ): Promise<
    (RecoveryRecord & { keysetVersion: number; orgName: string }) | undefined
  >;

  /**
   * ### markRekeyed
   *
   * Records that the user re-enrolled, using up the token.
   *
   * @param recoveryId Recovery
   * @param at Time of re-enrolment
   * @returns Whether it was still approved
   */
  markRekeyed(recoveryId: string, at: Date): Promise<boolean>;

  /**
   * ### complete
   *
   * Finishes a re-keyed recovery.
   *
   * @param recoveryId Recovery
   * @param at Time of completion
   * @returns Whether it was still re-keyed
   */
  complete(recoveryId: string, at: Date): Promise<boolean>;
}
