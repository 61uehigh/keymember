import type { Session } from "./Session.js";

/**
 * ### VaultReader
 *
 * Reading the synced vaults and items.
 */
export type VaultReader = Pick<
  Session,
  "getItem" | "listItems" | "listVaults" | "sync"
>;

/**
 * ### ItemEditing
 *
 * Creating, changing and deleting items.
 */
export type ItemEditing = Pick<
  Session,
  "createItem" | "deleteItem" | "updateItem"
>;

/**
 * ### VaultAccessControl
 *
 * Creating vaults and deciding who can open them.
 */
export type VaultAccessControl = Pick<
  Session,
  | "createVault"
  | "directory"
  | "grantAccess"
  | "grantGroupAccess"
  | "groups"
  | "revokeAccess"
  | "rotateVaultKey"
  | "user"
  | "vaultAccess"
>;

/**
 * ### ShareLinkControl
 *
 * Share links for people outside a vault.
 */
export type ShareLinkControl = Pick<
  Session,
  "createShareLink" | "getItem" | "revokeShareLink" | "shareLinks"
>;

/**
 * ### OrganisationAdministration
 *
 * What an admin console does: members, groups, recoveries and policies.
 */
export type OrganisationAdministration = Pick<
  Session,
  | "directory"
  | "groupAdmin"
  | "groups"
  | "linkSso"
  | "orgAdmin"
  | "policies"
  | "recovery"
  | "user"
>;

/**
 * ### OwnerCheck
 *
 * Comparing the owner's fingerprint before trusting the organisation.
 */
export type OwnerCheck = Pick<Session, "fingerprint" | "ownerCandidates">;
