import type { MembershipRole, MembershipStatus } from "../domain/membership.js";

/**
 * ### NewSession
 *
 * One token pair of a login, stored as hashes only.
 */
export interface NewSession {
  readonly accessHash: Uint8Array;
  readonly refreshHash: Uint8Array;
  /** Every token pair of one login shares this id; revoking it ends the login */
  readonly familyId: string;
  readonly userId: string;
  readonly deviceId: string;
  readonly deviceName: string;
  readonly accessExpiresAt: Date;
  readonly refreshExpiresAt: Date;
}

/**
 * ### AuthenticatedSession
 *
 * Who presented a valid access token, and what their organisation's policies still ask of them.
 */
export interface AuthenticatedSession {
  readonly userId: string;
  readonly email: string;
  readonly orgId: string;
  readonly role: MembershipRole;
  readonly status: MembershipStatus;
  readonly familyId: string;
  /** The organisation requires two-factor login and the user has not enrolled */
  readonly totpMissing: boolean;
  /** The organisation requires SSO and this login has not passed it */
  readonly ssoMissing: boolean;
}

/**
 * ### RefreshableSession
 *
 * The token pair a refresh token belongs to, locked for rotation.
 */
export interface RefreshableSession {
  readonly familyId: string;
  readonly userId: string;
  readonly orgId: string;
  readonly deviceId: string;
  readonly deviceName: string;
  readonly refreshExpiresAt: Date;
  /** The refresh token was already swapped or revoked: presenting it again means it was copied */
  readonly spent: boolean;
}

/**
 * ### SessionRepository
 *
 * Storage of logins: token pairs by hash, grouped into families, one family per login.
 */
export interface SessionRepository {
  /**
   * ### insert
   *
   * Stores a new token pair.
   *
   * @param session The pair's hashes, owner and expiries
   */
  insert(session: NewSession): Promise<void>;

  /**
   * ### authenticate
   *
   * Looks up the live login an access token belongs to.
   *
   * @param accessHash Hash of the presented access token
   * @param now Current time
   * @returns The caller, or `undefined` for an unknown, expired or revoked token
   */
  authenticate(
    accessHash: Uint8Array,
    now: Date,
  ): Promise<AuthenticatedSession | undefined>;

  /**
   * ### refreshTarget
   *
   * The login an unused, unrevoked refresh token belongs to, with its organisation's SSO policy.
   *
   * @param refreshHash Hash of the presented refresh token
   * @returns The login, or `undefined`
   */
  refreshTarget(refreshHash: Uint8Array): Promise<
    | {
        familyId: string;
        userId: string;
        orgId: string;
        requireSso: boolean;
      }
    | undefined
  >;

  /**
   * ### lockForRefresh
   *
   * Locks the token pair a refresh token belongs to, spent or not.
   *
   * @param refreshHash Hash of the presented refresh token
   * @returns The pair, or `undefined` for an unknown token
   */
  lockForRefresh(
    refreshHash: Uint8Array,
  ): Promise<RefreshableSession | undefined>;

  /**
   * ### markRotated
   *
   * Spends a refresh token once it has been swapped for a new pair.
   *
   * @param refreshHash Hash of the swapped token
   * @param at Time of the swap
   */
  markRotated(refreshHash: Uint8Array, at: Date): Promise<void>;

  /**
   * ### revokeFamily
   *
   * Ends one login on every token pair it has.
   *
   * @param familyId Login
   * @param at Time of revocation
   */
  revokeFamily(familyId: string, at: Date): Promise<void>;

  /**
   * ### revokeOthers
   *
   * Ends every login of a user except one, as a password change does.
   *
   * @param userId User
   * @param keepFamilyId The login to keep
   * @param at Time of revocation
   */
  revokeOthers(userId: string, keepFamilyId: string, at: Date): Promise<void>;

  /**
   * ### revokeAll
   *
   * Ends every login of a user.
   *
   * @param userId User
   * @param at Time of revocation
   */
  revokeAll(userId: string, at: Date): Promise<void>;

  /**
   * ### isFamilyActive
   *
   * Whether a login still has an unrevoked token pair.
   *
   * @param familyId Login
   * @returns Whether it does
   */
  isFamilyActive(familyId: string): Promise<boolean>;

  /**
   * ### knownDevice
   *
   * Whether the user has signed in from the device before, within the life of a refresh token
   * (revoked and rotated token pairs count; expired ones are purged).
   *
   * @param userId User
   * @param deviceId Device the client says it is
   * @returns Whether it has
   */
  knownDevice(userId: string, deviceId: string): Promise<boolean>;

  /**
   * ### purgeExpired
   *
   * Deletes token pairs whose refresh token has expired, a page at a time. Revoked but unexpired
   * pairs stay, since reuse detection needs them until they expire.
   *
   * @param now Current time
   * @param limit Most token pairs to delete
   * @returns How many were deleted; fewer than `limit` means none are left
   */
  purgeExpired(now: Date, limit: number): Promise<number>;
}
