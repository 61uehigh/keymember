import type {
  AccountKeyset,
  EncryptionKeyPair,
  GroupCertificate,
  ItemOverview,
  MemberCertificate,
  MemberRole,
} from "@keymember/core";
import type { z } from "zod";

import type { orgResponseSchema } from "./schemas.js";
import type { ApiRequest } from "./transport.js";

/**
 * ### OrgResponse
 *
 * Validated but unverified response of `GET /api/org`.
 */
export type OrgResponse = z.infer<typeof orgResponseSchema>;

/**
 * ### VaultPermission
 *
 * Access level on a vault.
 */
export type VaultPermission = "view" | "edit" | "manage";

/**
 * ### MembershipStatus
 *
 * Membership lifecycle as reported by the server.
 */
export type MembershipStatus =
  "accepted" | "confirmed" | "suspended" | "recovering";

/**
 * ### SessionUser
 *
 * The logged-in user as reported by the server at login.
 */
export interface SessionUser {
  /**
   * ### id
   *
   * User id.
   */
  readonly id: string;

  /**
   * ### email
   *
   * Login email.
   */
  readonly email: string;

  /**
   * ### name
   *
   * Display name.
   */
  readonly name: string;

  /**
   * ### role
   *
   * Role in the organisation.
   */
  readonly role: MemberRole;

  /**
   * ### status
   *
   * Membership status at login time.
   */
  readonly status: MembershipStatus;
}

/**
 * ### DirectoryMember
 *
 * A member of the organisation, with `certificate` set only when their keys are vouched for
 * by a certificate chain from the pinned roots. Only such members may receive keys.
 */
export interface DirectoryMember {
  /**
   * ### userId
   *
   * User id.
   */
  readonly userId: string;

  /**
   * ### email
   *
   * Email as reported by the server; trustworthy only when `certificate` is set.
   */
  readonly email: string;

  /**
   * ### name
   *
   * Display name as reported by the server.
   */
  readonly name: string;

  /**
   * ### role
   *
   * Role as reported by the server; the certified role is in `certificate`.
   */
  readonly role: MemberRole;

  /**
   * ### status
   *
   * Membership status as reported by the server.
   */
  readonly status: MembershipStatus;

  /**
   * ### fingerprint
   *
   * Fingerprint of the member's published keys, for out-of-band comparison.
   */
  readonly fingerprint: string;

  /**
   * ### certificate
   *
   * The member's certificate when it verified against the roots, otherwise `undefined`.
   */
  readonly certificate: MemberCertificate | undefined;

  /**
   * ### publishedKeys
   *
   * Keys the server publishes for the member, used when certifying them.
   */
  readonly publishedKeys: {
    readonly encryption: Uint8Array;
    readonly signing: Uint8Array;
    readonly version: number;
  };
}

/**
 * ### OrgPolicies
 *
 * Organisation-wide policies.
 */
export interface OrgPolicies {
  /**
   * ### requireTotp
   *
   * Whether members must enrol two-factor login before using vaults.
   */
  readonly requireTotp: boolean;

  /**
   * ### requireSso
   *
   * Whether every login must also pass the organisation's identity provider.
   */
  readonly requireSso: boolean;

  /**
   * ### ssoAvailable
   *
   * Whether the server has an identity provider configured.
   */
  readonly ssoAvailable: boolean;

  /**
   * ### ssoLinked
   *
   * Whether the current login passed the identity provider. Required before switching
   * `requireSso` on, so a broken provider cannot lock everyone out.
   */
  readonly ssoLinked: boolean;
}

/**
 * ### OffboardingReport
 *
 * What {@link Session.offboard} did, and what is left for others.
 */
export interface OffboardingReport {
  /**
   * ### groupsRotated
   *
   * Groups the member was in whose key was replaced.
   */
  readonly groupsRotated: ReadonlyArray<string>;

  /**
   * ### vaultsRotated
   *
   * Vaults the member could open whose key the admin replaced.
   */
  readonly vaultsRotated: ReadonlyArray<string>;

  /**
   * ### vaultsPending
   *
   * Vaults the admin cannot rotate, with the members who manage them and should. An empty
   * `managerIds` means nobody can: the vault had no other manager.
   */
  readonly vaultsPending: ReadonlyArray<{
    readonly vaultId: string;
    readonly managerIds: ReadonlyArray<string>;
  }>;
}

/**
 * ### InvitedCertification
 *
 * What {@link OrgAdmin.certifyInvited} did with the members who joined through this admin's
 * invite links.
 */
export interface InvitedCertification {
  /**
   * ### certified
   *
   * Emails of the members certified now.
   */
  readonly certified: ReadonlyArray<string>;

  /**
   * ### needsFingerprint
   *
   * Emails of members the link alone may not vouch for: admin invites (an admin also receives
   * the recovery key), links older than the grace period, an invite used by more than one
   * account, and members who had keys certified before. Compare fingerprints with them.
   */
  readonly needsFingerprint: ReadonlyArray<string>;

  /**
   * ### failed
   *
   * Members whose certification failed, with the reason.
   */
  readonly failed: ReadonlyArray<{
    readonly email: string;
    readonly reason: string;
  }>;
}

/**
 * ### PrincipalType
 *
 * Who a vault key is shared with: a member or a group.
 */
export type PrincipalType = "user" | "group";

/**
 * ### GroupView
 *
 * A group of the organisation, with `certificate` set only when a trusted admin vouched for
 * its key. Only such groups may receive vault keys.
 */
export interface GroupView {
  /**
   * ### id
   *
   * Group id.
   */
  readonly id: string;

  /**
   * ### name
   *
   * Name as reported by the server; trustworthy only when `certificate` is set.
   */
  readonly name: string;

  /**
   * ### keysetVersion
   *
   * Current group key version.
   */
  readonly keysetVersion: number;

  /**
   * ### memberIds
   *
   * Members holding the current group key.
   */
  readonly memberIds: ReadonlyArray<string>;

  /**
   * ### certificate
   *
   * The group's certificate when it verified against the roots, otherwise `undefined`.
   */
  readonly certificate: GroupCertificate | undefined;
}

/**
 * ### RecipientKeys
 *
 * Verified keys of everyone about to receive a vault key.
 */
export interface RecipientKeys {
  /**
   * ### members
   *
   * Certified encryption keys by user id.
   */
  readonly members: ReadonlyMap<string, Uint8Array>;

  /**
   * ### groups
   *
   * Certified group keys and their versions by group id.
   */
  readonly groups: ReadonlyMap<
    string,
    { readonly publicKey: Uint8Array; readonly keysetVersion: number }
  >;

  /**
   * ### recovery
   *
   * The verified recovery key, when the organisation has one.
   */
  readonly recovery: Uint8Array | undefined;

  /**
   * ### orgId
   *
   * Organisation id.
   */
  readonly orgId: string;
}

/**
 * ### VaultView
 *
 * A vault the user can open.
 */
export interface VaultView {
  /**
   * ### id
   *
   * Vault id.
   */
  readonly id: string;

  /**
   * ### name
   *
   * Decrypted display name.
   */
  readonly name: string;

  /**
   * ### kind
   *
   * Personal or shared.
   */
  readonly kind: "personal" | "shared";

  /**
   * ### permission
   *
   * The user's access level.
   */
  readonly permission: VaultPermission;

  /**
   * ### rotationDue
   *
   * Whether someone who could open the vault left; a manager should rotate its key.
   */
  readonly rotationDue: boolean;
}

/**
 * ### ItemSummary
 *
 * An item's decrypted overview with its location and revision.
 */
export interface ItemSummary {
  /**
   * ### id
   *
   * Item id.
   */
  readonly id: string;

  /**
   * ### vaultId
   *
   * Vault holding the item.
   */
  readonly vaultId: string;

  /**
   * ### revision
   *
   * Revision to pass back when updating or deleting.
   */
  readonly revision: number;

  /**
   * ### overview
   *
   * Decrypted listing fields.
   */
  readonly overview: ItemOverview;
}

/**
 * ### SessionInternals
 *
 * The narrow slice of a session that companion admin helpers need. Not exported from the package.
 */
export interface SessionInternals {
  /**
   * ### user
   *
   * Logged-in user.
   */
  readonly user: SessionUser;

  /**
   * ### keyset
   *
   * Unlocked account keyset.
   */
  readonly keyset: AccountKeyset;

  /**
   * ### request
   *
   * Sends an authenticated request.
   */
  request(request: Omit<ApiRequest, "token">): Promise<unknown>;

  /**
   * ### fetchOrg
   *
   * Fetches the organisation, its policies, recovery key and directory.
   */
  fetchOrg(): Promise<OrgResponse>;

  /**
   * ### roots
   *
   * The issuer keys this session trusts, for passing on in invite links.
   */
  roots(): ReadonlyMap<string, Uint8Array>;

  /**
   * ### trust
   *
   * Verifies the organisation's member certificates from the session's roots, the one trust
   * anchor every check uses.
   *
   * @param org Organisation document
   * @returns Verified certificates by user id, and the keys trusted to issue statements
   */
  trust(org: OrgResponse): {
    certified: Map<string, MemberCertificate>;
    issuers: Map<string, Uint8Array>;
  };

  /**
   * ### recoveryKeyPair
   *
   * Unwraps the caller's copy of the recovery key, verifying the published public key first.
   */
  recoveryKeyPair(): Promise<EncryptionKeyPair>;

  /**
   * ### recipientKeys
   *
   * Resolves certified keys for members and groups about to receive a key, refusing any
   * without a certificate chain from the roots.
   */
  recipientKeys(
    userIds: ReadonlyArray<string>,
    groupIds?: ReadonlyArray<string>,
  ): Promise<RecipientKeys>;

  /**
   * ### groups
   *
   * Lists the organisation's groups, verified against the roots.
   */
  groups(): Promise<Array<GroupView>>;

  /**
   * ### sync
   *
   * Refreshes the session's cache.
   */
  sync(): Promise<void>;
}

/**
 * ### GroupAdminDeps
 *
 * What {@link GroupAdmin} needs from a session: keys to wrap group keys to, the recovery key
 * for groups the admin is not in, and the groups themselves.
 */
export type GroupAdminDeps = Pick<
  SessionInternals,
  | "fetchOrg"
  | "groups"
  | "keyset"
  | "recipientKeys"
  | "recoveryKeyPair"
  | "request"
  | "sync"
  | "trust"
  | "user"
>;

/**
 * ### RecoveryAdminDeps
 *
 * What {@link RecoveryAdmin} needs from a session: the verified directory, the recovery key and
 * the groups whose keys a recovery restores.
 */
export type RecoveryAdminDeps = Pick<
  SessionInternals,
  | "fetchOrg"
  | "groups"
  | "keyset"
  | "recoveryKeyPair"
  | "request"
  | "trust"
  | "user"
>;

/**
 * ### OrgAdminDeps
 *
 * What {@link OrgAdmin} needs from a session's internals: the verified directory, the recovery
 * key to hand to new admins, and the signing key for certificates and invites.
 */
export type OrgAdminDeps = Pick<
  SessionInternals,
  | "fetchOrg"
  | "keyset"
  | "recoveryKeyPair"
  | "request"
  | "roots"
  | "trust"
  | "user"
>;
