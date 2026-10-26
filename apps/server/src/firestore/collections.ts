import { toBase64Url } from "@keymember/core";

/**
 * ### COLLECTIONS
 *
 * The Firestore collection standing in for each SQL table. Every repository that reads a table
 * uses these names, and lays documents out by the same rules:
 *
 * - Each SQL column becomes a field named in camelCase (`enc_item_key` → `encItemKey`), primary
 *   key columns included, so documents can be found by any part of a composite key. Every field
 *   is always present; SQL `NULL` is `null`.
 * - `timestamptz` is a `Date`, `bytea` a `Uint8Array`, `integer` and `bigint` a number,
 *   `jsonb` a JSON string, so it reads back exactly as written.
 * - Columns with a database default (`created_at`, `revision`, `views`) are written explicitly.
 * - `revision` columns take numbers from the {@link REVISION_SEQUENCE} counter.
 * - Fields added after launch are missing from older documents: readers treat missing as
 *   `null`, and queries never filter on such a field being `null`.
 * - Document ids follow {@link documentId}; composite keys join their parts with `:`.
 */
export const COLLECTIONS = {
  auditEvents: "auditEvents",
  groupMembers: "groupMembers",
  groups: "groups",
  invites: "invites",
  itemMoves: "itemMoves",
  items: "items",
  loginChallenges: "loginChallenges",
  memberships: "memberships",
  organizations: "organizations",
  recoveries: "recoveries",
  recoveryKeyAccess: "recoveryKeyAccess",
  sessions: "sessions",
  uniqueKeys: "uniqueKeys",
  shares: "shares",
  ssoSessions: "ssoSessions",
  ssoTickets: "ssoTickets",
  users: "users",
  vaultAccess: "vaultAccess",
  vaultRecovery: "vaultRecovery",
  vaults: "vaults",
} as const;

/**
 * ### REVISION_SEQUENCE
 *
 * Counter that stands in for SQL's `change_seq`, shared by every table with a `revision` column.
 */
export const REVISION_SEQUENCE = "change";

/**
 * ### documentId
 *
 * Document id for each table, from its SQL primary key.
 */
export const documentId = {
  /**
   * ### auditEvent
   *
   * Zero-padded event id, so ids sort in time order.
   *
   * @param id Event id
   * @returns The document id
   */
  auditEvent: (id: number): string => String(id).padStart(16, "0"),

  /**
   * ### groupMember
   *
   * @param groupId Group
   * @param userId Member
   * @returns The id
   */
  groupMember: (groupId: string, userId: string): string =>
    `${groupId}:${userId}`,

  /**
   * ### invite
   *
   * @param tokenHash Hash of the invite token
   * @returns The id
   */
  invite: (tokenHash: Uint8Array): string => toBase64Url(tokenHash),

  /**
   * ### membership
   *
   * @param orgId Organisation
   * @param userId Member
   * @returns The id
   */
  membership: (orgId: string, userId: string): string => `${orgId}:${userId}`,

  /**
   * ### recoveryKeyAccess
   *
   * @param orgId Organisation
   * @param adminId Admin holding the copy
   * @returns The id
   */
  recoveryKeyAccess: (orgId: string, adminId: string): string =>
    `${orgId}:${adminId}`,

  /**
   * ### session
   *
   * @param accessHash Hash of the access token
   * @returns The id
   */
  session: (accessHash: Uint8Array): string => toBase64Url(accessHash),

  /**
   * ### vaultAccess
   *
   * @param vaultId Vault
   * @param principalId User or group
   * @returns The id
   */
  vaultAccess: (vaultId: string, principalId: string): string =>
    `${vaultId}:${principalId}`,
} as const;
