import {
  DEFAULT_KDF_PARAMS,
  deriveAccountSecrets,
  formatSecretKey,
  generateSalt,
  loginPublicKey,
  parseSecretKey,
  publicKeyFingerprint,
  sealAccountKeyset,
  symmetricKeyFromBytes,
} from "@keymember/core";
import type {
  AccountKeyset,
  ItemDetails,
  ItemOverview,
  SecretKey,
} from "@keymember/core";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { z } from "zod";

import { GroupAdmin } from "./GroupAdmin.js";
import { challengeSignature } from "./loginChallenge.js";
import { OrgAdmin } from "./OrgAdmin.js";
import { RecoveryAdmin } from "./RecoveryAdmin.js";
import {
  encode,
  parseResponse,
  preloginResponseSchema,
  sessionSnapshotSchema,
} from "./schemas.js";
import type { SessionSnapshot } from "./schemas.js";
import { AuthorizedApi } from "./session/AuthorizedApi.js";
import { ItemWriter } from "./session/ItemWriter.js";
import { ShareLinkIssuer } from "./session/ShareLinkIssuer.js";
import { TrustContext } from "./session/TrustContext.js";
import { TrustedRootsStore } from "./session/TrustedRootsStore.js";
import { VaultCache } from "./session/VaultCache.js";
import { VaultSharing } from "./session/VaultSharing.js";
import type {
  DirectoryMember,
  GroupView,
  ItemSummary,
  OrgPolicies,
  PrincipalType,
  SessionInternals,
  SessionUser,
  VaultPermission,
  VaultView,
} from "./Session.type.js";
import type { ShareField, ShareLink, ShareLinkSummary } from "./shareLinks.js";
import { completeSso, ssoTicketSchema } from "./sso.js";
import type { SsoHandler } from "./sso.js";
import { send } from "./transport.js";
import type { Transport } from "./transport.js";

/**
 * ### Session
 *
 * An authenticated, unlocked session: the public face of one login. It holds the account
 * keyset and puts together the parts that do the work, each with one concern:
 * {@link AuthorizedApi} (tokens and refresh), {@link TrustContext} (whose keys to believe),
 * {@link VaultCache} (the synced vaults and items), {@link VaultSharing} (who holds each vault
 * key), {@link ItemWriter} (item changes) and {@link ShareLinkIssuer} (share links). Admin work
 * goes through {@link Session.orgAdmin}, {@link Session.groupAdmin} and {@link Session.recovery}.
 * Call {@link Session.logOut} when done; dropping the object does not revoke the tokens.
 */
export class Session {
  /**
   * ### user
   *
   * The logged-in user.
   */
  readonly user: SessionUser;

  /**
   * ### recoveryCancelled
   *
   * Whether this login cancelled a recovery an admin had started on the account. A client
   * should tell the user, because it means someone tried to take over their account access.
   */
  readonly recoveryCancelled: boolean;

  readonly #keyset: AccountKeyset;
  readonly #secretKey: SecretKey;
  readonly #api: AuthorizedApi;
  readonly #trust: TrustContext;
  readonly #cache: VaultCache;
  readonly #sharing: VaultSharing;
  readonly #items: ItemWriter;
  readonly #shares: ShareLinkIssuer;
  readonly #trustedRoots: TrustedRootsStore;

  /**
   * ### constructor
   *
   * Created by {@link logIn}; not meant to be constructed directly.
   *
   * @param transport Transport to the server
   * @param user Logged-in user
   * @param keyset Unlocked account keyset
   * @param tokens Initial token pair
   * @param secretKey Secret Key, kept for password changes
   * @param recoveryCancelled Whether the login cancelled an open recovery
   */
  constructor(
    transport: Transport,
    user: SessionUser,
    keyset: AccountKeyset,
    tokens: { accessToken: string; refreshToken: string },
    secretKey: SecretKey,
    recoveryCancelled = false,
  ) {
    this.user = user;
    this.recoveryCancelled = recoveryCancelled;
    this.#keyset = keyset;
    this.#secretKey = secretKey;
    this.#api = new AuthorizedApi(transport, tokens);
    this.#trust = new TrustContext(this.#api.request, user, keyset);
    this.#cache = new VaultCache(this.#api.request, this.#trust, user, keyset);
    this.#sharing = new VaultSharing(
      this.#api.request,
      this.#trust,
      this.#cache,
      user.id,
      keyset.signing.privateKey,
    );
    this.#items = new ItemWriter(this.#api.request, this.#cache);
    this.#shares = new ShareLinkIssuer(
      this.#api.request,
      this.#cache,
      user.name,
    );
    this.#trustedRoots = new TrustedRootsStore(
      this.#api.request,
      this.#trust,
      user.id,
      keyset.signing,
    );
  }

  /**
   * ### setRoots
   *
   * Pins the issuer keys (normally the owner's) this session trusts. Sync accepts vault keys
   * granted by this user or by members certified from these roots, and group keys certified by
   * their admins; until roots are set, only the user's own grants are accepted.
   *
   * @param roots Pinned issuer keys by user id
   */

  setRoots(roots: ReadonlyMap<string, Uint8Array>): void {
    this.#trust.setRoots(roots);
  }

  /**
   * ### fromSnapshot
   *
   * Restores a session from {@link Session.toSnapshot}, for clients whose process can be
   * stopped at any time (an MV3 service worker). The local vault cache is not part of the
   * snapshot; call {@link Session.sync} after restoring. Throws when the snapshot is malformed.
   *
   * @param transport Transport to the server
   * @param snapshot Value read back from memory-only storage
   * @returns The restored session
   */

  static fromSnapshot(transport: Transport, snapshot: unknown): Session {
    const parsed = parseResponse(sessionSnapshotSchema, snapshot);
    const secretKey = parseSecretKey(parsed.secretKey);

    if (secretKey === undefined) {
      throw new Error("Snapshot holds an invalid Secret Key");
    }

    const keyset: AccountKeyset = {
      userId: parsed.user.id,
      accountKey: symmetricKeyFromBytes(
        parsed.keyset.accountKeyId,
        parsed.keyset.accountKey,
      ),
      encryption: {
        privateKey: parsed.keyset.encryptionPrivateKey,
        publicKey: x25519.getPublicKey(parsed.keyset.encryptionPrivateKey),
      },
      signing: {
        privateKey: parsed.keyset.signingPrivateKey,
        publicKey: ed25519.getPublicKey(parsed.keyset.signingPrivateKey),
      },
      keysetVersion: parsed.keyset.keysetVersion,
    };

    return new Session(
      transport,
      parsed.user,
      keyset,
      parsed.tokens,
      secretKey,
    );
  }

  /**
   * ### toSnapshot
   *
   * Serialises everything needed to resume this session: tokens and the unlocked keyset.
   * The result is as sensitive as the vault itself. Keep it only in memory-only storage
   * (for example `chrome.storage.session`), never on disk, and drop it on lock.
   *
   * @returns A JSON-compatible snapshot
   */

  toSnapshot(): SessionSnapshot {
    return {
      v: 1,
      user: this.user,
      tokens: this.#api.tokens,
      secretKey: formatSecretKey(this.#secretKey),
      keyset: {
        accountKeyId: encode(this.#keyset.accountKey.id),
        accountKey: encode(this.#keyset.accountKey.bytes),
        encryptionPrivateKey: encode(this.#keyset.encryption.privateKey),
        signingPrivateKey: encode(this.#keyset.signing.privateKey),
        keysetVersion: this.#keyset.keysetVersion,
      },
    };
  }

  /**
   * ### onTokensChanged
   *
   * Registers a callback for token refreshes, so a holder of a snapshot can store the new
   * tokens; an old refresh token is single-use and would end the session if replayed.
   *
   * @param listener Called after every refresh; replaces any previous listener
   */

  onTokensChanged(listener: () => void): void {
    this.#api.onTokensChanged(listener);
  }

  /**
   * ### onEnded
   *
   * Registers a callback for when the server ends this login: a request or the refresh was
   * refused because the login was revoked or expired, or the server answered 403
   * `membership_ended` because an admin suspended the member or started a recovery (the same
   * failures `loginEnded` recognises). The keys are still in memory; the app should lock
   * and drop the session.
   *
   * @param listener Called once when the login ends
   * @returns Removes the listener
   */
  onEnded(listener: () => void): () => void {
    return this.#api.onEnded(listener);
  }

  /**
   * ### signingPublicKey
   *
   * The user's own signing public key: the trust root an owner pins for their organisation.
   */

  get signingPublicKey(): Uint8Array {
    return this.#keyset.signing.publicKey;
  }

  /**
   * ### fingerprint
   *
   * Fingerprint of the user's own keys, computed locally. The user reads it out to the
   * admin who certifies them, so the admin can detect a substituted key on the server.
   */

  get fingerprint(): string {
    return publicKeyFingerprint({
      userId: this.user.id,
      encryptionPublicKey: this.#keyset.encryption.publicKey,
      signingPublicKey: this.#keyset.signing.publicKey,
      keysetVersion: this.#keyset.keysetVersion,
    });
  }

  /**
   * ### recovery
   *
   * Admin helper for account recoveries.
   *
   * @returns A recovery admin bound to this session
   */

  recovery(): RecoveryAdmin {
    return new RecoveryAdmin(this.#internals());
  }

  /**
   * ### groupAdmin
   *
   * Admin helper for creating groups and changing their members.
   *
   * @returns A group admin bound to this session
   */

  groupAdmin(): GroupAdmin {
    return new GroupAdmin(this.#internals());
  }

  /**
   * ### orgAdmin
   *
   * Admin helper for the organisation: invites, certification, policies, suspension and
   * offboarding.
   *
   * @returns The helper
   */

  orgAdmin(): OrgAdmin {
    return new OrgAdmin(this, this.#internals());
  }

  /**
   * ### groups
   *
   * Fetches the organisation's groups and marks which group keys a trusted admin vouched for,
   * judged from the session's roots.
   *
   * @returns Every live group, verified or not
   */

  groups(): Promise<Array<GroupView>> {
    return this.#trust.groups();
  }

  /**
   * ### directory
   *
   * Fetches the member directory and marks which members' keys are vouched for by the
   * session's roots.
   *
   * @returns Every member, verified or not
   */

  directory(): Promise<Array<DirectoryMember>> {
    return this.#trust.directory();
  }

  /**
   * ### ownerCandidates
   *
   * Lists the owners the server reports, with fingerprints, so a client can pin one on first use.
   * The fingerprint must be compared out of band before pinning; this call proves nothing by itself.
   *
   * @returns Owner user ids with their signing keys and fingerprints
   */

  ownerCandidates(): ReturnType<TrustContext["ownerCandidates"]> {
    return this.#trust.ownerCandidates();
  }

  /**
   * ### policies
   *
   * Reads the organisation's policies.
   *
   * @returns Current policies
   */

  async policies(): Promise<OrgPolicies> {
    return (await this.#trust.fetchOrg()).policies;
  }

  /**
   * ### linkSso
   *
   * Has the current login pass the organisation's identity provider, so it keeps working once
   * SSO is required and is re-checked with the provider on every token refresh.
   *
   * @param handler Opens or shows the provider sign-in
   */

  async linkSso(handler: SsoHandler): Promise<void> {
    const ticket = parseResponse(
      ssoTicketSchema,
      await this.#api.request({ method: "POST", path: "/api/auth/sso/link" }),
    );

    await completeSso(this.#api.transport, ticket, handler);
  }

  /**
   * ### createVault
   *
   * Creates a vault and shares its key with the given members, groups and the recovery key.
   * The caller always gets `manage`.
   *
   * @param name Display name, encrypted before upload
   * @param kind Personal or shared
   * @param members Other members and their permissions
   * @param groups Groups and their permissions
   * @returns The new vault id
   */

  createVault(
    name: string,
    kind: "personal" | "shared",
    members: ReadonlyArray<{ userId: string; permission: VaultPermission }>,
    groups: ReadonlyArray<{
      groupId: string;
      permission: VaultPermission;
    }> = [],
  ): Promise<string> {
    return this.#sharing.createVault(name, kind, members, groups);
  }

  /**
   * ### grantAccess
   *
   * Shares an existing vault with a member, or changes their permission.
   *
   * @param vaultId Vault to share
   * @param userId Member receiving access
   * @param permission Access level
   */

  grantAccess(
    vaultId: string,
    userId: string,
    permission: VaultPermission,
  ): Promise<void> {
    return this.#sharing.grant(vaultId, {
      principalType: "user",
      principalId: userId,
      permission,
    });
  }

  /**
   * ### grantGroupAccess
   *
   * Shares an existing vault with a group, or changes its permission. Everyone holding the
   * group's key gets access, now and as members are added later.
   *
   * @param vaultId Vault to share
   * @param groupId Group receiving access
   * @param permission Access level
   */

  grantGroupAccess(
    vaultId: string,
    groupId: string,
    permission: VaultPermission,
  ): Promise<void> {
    return this.#sharing.grant(vaultId, {
      principalType: "group",
      principalId: groupId,
      permission,
    });
  }

  /**
   * ### vaultAccess
   *
   * Lists who can open a vault. Managers only.
   *
   * @param vaultId Vault to inspect
   * @returns Principals and their permissions
   */

  vaultAccess(vaultId: string): Promise<
    Array<{
      principalType: PrincipalType;
      principalId: string;
      permission: VaultPermission;
    }>
  > {
    return this.#sharing.access(vaultId);
  }

  /**
   * ### revokeAccess
   *
   * Removes a member's or group's access entry without rotating the key. Prefer
   * {@link Session.rotateVaultKey} with the principal in `removePrincipalIds`, which also
   * protects future changes from anyone who kept the old key.
   *
   * @param vaultId Vault to unshare
   * @param principalId Member or group losing access
   */

  revokeAccess(vaultId: string, principalId: string): Promise<void> {
    return this.#sharing.revoke(vaultId, principalId);
  }

  /**
   * ### rotateVaultKey
   *
   * Replaces a vault's key and every item key in it, re-encrypts all items, and re-shares the
   * new key with the remaining members, groups and the recovery key. Removed principals (or
   * anyone who copied old keys) cannot read anything written after this. Items they already
   * read stay exposed, so change those passwords too.
   *
   * Members and groups whose current grant is not signed by a trusted member are dropped
   * unless `keepUnverified` is set.
   *
   * @param vaultId Vault to rotate
   * @param removePrincipalIds Members or groups to drop in the same step
   * @param options `keepUnverified` keeps principals whose grant does not verify
   */

  rotateVaultKey(
    vaultId: string,
    removePrincipalIds: ReadonlyArray<string> = [],
    options: { readonly keepUnverified?: boolean } = {},
  ): Promise<void> {
    return this.#sharing.rotate(vaultId, removePrincipalIds, options);
  }

  /**
   * ### sync
   *
   * Pulls changes since the last sync and updates the local cache. Vaults that disappeared
   * from the server response, and their items, are dropped.
   */

  sync(): Promise<void> {
    return this.#cache.sync();
  }

  /**
   * ### createShareLink
   *
   * Makes a share link for one item: a snapshot of its title, URLs and the chosen fields, sealed
   * under a fresh key that only the link carries. Later edits to the item do not reach the link.
   *
   * @param itemId Item to share
   * @param options Fields to include, lifetime, number of views, and an optional passphrase
   * @returns The link; build the URL with `shareLinkUrl` and send the passphrase separately
   */

  createShareLink(
    itemId: string,
    options: {
      fields: ReadonlyArray<ShareField>;
      expiresInMs: number;
      maxViews: number;
      passphrase?: string | undefined;
    },
  ): Promise<ShareLink> {
    return this.#shares.create(itemId, options);
  }

  /**
   * ### shareLinks
   *
   * Lists share links this user made, optionally for one item; admins can list everyone's.
   *
   * @param options Item to filter by, and whether to include other members' links (admins)
   * @returns The links, newest first
   */

  shareLinks(
    options: { itemId?: string; all?: boolean } = {},
  ): Promise<Array<ShareLinkSummary>> {
    return this.#shares.list(options);
  }

  /**
   * ### revokeShareLink
   *
   * Closes a share link. Its sender or an admin can do this.
   *
   * @param shareId Link to close
   */

  revokeShareLink(shareId: string): Promise<void> {
    return this.#shares.revoke(shareId);
  }

  /**
   * ### listVaults
   *
   * Vaults in the local cache. Call {@link Session.sync} first for fresh data.
   *
   * @returns Every vault the user can open
   */

  listVaults(): Array<VaultView> {
    return this.#cache.listVaults();
  }

  /**
   * ### listItems
   *
   * Decrypts the overview of every cached item, optionally limited to one vault.
   *
   * @param vaultId Vault to limit the listing to
   * @returns Item summaries
   */

  listItems(vaultId?: string): Array<ItemSummary> {
    return this.#cache.listItems(vaultId);
  }

  /**
   * ### getItem
   *
   * Decrypts one item fully.
   *
   * @param itemId Item to open
   * @returns The overview and secret details
   */

  getItem(itemId: string): { overview: ItemOverview; details: ItemDetails } {
    return this.#cache.getItem(itemId);
  }

  /**
   * ### createItem
   *
   * Encrypts and uploads a new item.
   *
   * @param vaultId Vault to store the item in
   * @param overview Listing fields
   * @param details Secret fields
   * @returns The new item id
   */

  createItem(
    vaultId: string,
    overview: ItemOverview,
    details: ItemDetails,
  ): Promise<string> {
    return this.#items.create(vaultId, overview, details);
  }

  /**
   * ### updateItem
   *
   * Re-encrypts and uploads an item, optionally moving it to another vault. Fails with an
   * {@link ApiError} coded `revision_conflict` when someone else changed it since the last sync.
   *
   * @param itemId Item to update
   * @param overview New listing fields
   * @param details New secret fields
   * @param targetVaultId Vault to move the item to; omit to keep it where it is
   */

  updateItem(
    itemId: string,
    overview: ItemOverview,
    details: ItemDetails,
    targetVaultId?: string,
  ): Promise<void> {
    return this.#items.update(itemId, overview, details, targetVaultId);
  }

  /**
   * ### deleteItem
   *
   * Moves an item to the trash.
   *
   * @param itemId Item to delete
   */

  deleteItem(itemId: string): Promise<void> {
    return this.#items.delete(itemId);
  }

  /**
   * ### setupTotp
   *
   * Starts two-factor enrolment.
   *
   * @returns The base32 secret and `otpauth://` URI to load into an authenticator app
   */

  async setupTotp(): Promise<{ secret: string; uri: string }> {
    return parseResponse(
      z.object({ secret: z.string(), uri: z.string() }),
      await this.#api.request({
        method: "POST",
        path: "/api/account/totp/setup",
      }),
    );
  }

  /**
   * ### confirmTotp
   *
   * Finishes two-factor enrolment with a code from the authenticator app. Replacing an
   * authenticator that is already set up also needs a code from the old one.
   *
   * @param code Current six-digit code from the new authenticator
   * @param currentCode Code from the authenticator being replaced, if any
   */

  async confirmTotp(code: string, currentCode?: string): Promise<void> {
    await this.#api.request({
      method: "POST",
      path: "/api/account/totp/confirm",
      body: { code, ...(currentCode === undefined ? {} : { currentCode }) },
    });
  }

  /**
   * ### changePassword
   *
   * Changes the account password. The keyset stays the same; only its wrapping changes.
   * Other devices are logged out.
   *
   * @param currentPassword Current password, proving the change is intended
   * @param newPassword New password
   */

  async changePassword(
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    const prelogin = parseResponse(
      preloginResponseSchema,
      await send(this.#api.transport, {
        method: "POST",
        path: "/api/auth/prelogin",
        body: { email: this.user.email },
      }),
    );
    const current = await deriveAccountSecrets(
      currentPassword,
      this.#secretKey,
      prelogin.salt,
      prelogin.kdf,
    );
    const salt = generateSalt();
    const next = await deriveAccountSecrets(
      newPassword,
      this.#secretKey,
      salt,
      DEFAULT_KDF_PARAMS,
    );

    await this.#api.request({
      method: "POST",
      path: "/api/account/password",
      body: {
        ...(prelogin.method === "legacy"
          ? { currentAuthKey: encode(current.authenticationKey) }
          : {
              currentChallengeId: prelogin.challengeId,
              currentSignature: challengeSignature(
                current.loginSigningSeed,
                prelogin,
                "change-password",
                this.user.email,
                "",
              ),
            }),
        salt: encode(salt),
        kdf: DEFAULT_KDF_PARAMS,
        loginPublicKey: encode(loginPublicKey(next.loginSigningSeed)),
        encryptedAccountKey: encode(
          sealAccountKeyset(this.#keyset, next.accountUnlockKey)
            .encryptedAccountKey,
        ),
      },
    });
  }

  /**
   * ### saveTrustedRoots
   *
   * Stores the roots this session trusts, signed by the user, so the user's other devices adopt
   * them without a fingerprint check ({@link Session.storedTrustedRoots}).
   */
  saveTrustedRoots(): Promise<void> {
    return this.#trustedRoots.save();
  }

  /**
   * ### storedTrustedRoots
   *
   * The roots the user saved from another device, verified with the user's own key.
   *
   * @returns The roots, or `undefined` when there are none to trust
   */
  storedTrustedRoots(): Promise<ReadonlyMap<string, Uint8Array> | undefined> {
    return this.#trustedRoots.load();
  }

  /**
   * ### logOut
   *
   * Revokes this login's tokens on the server.
   */

  async logOut(): Promise<void> {
    await this.#api.request({ method: "POST", path: "/api/auth/logout" });
  }

  /**
   * ### #internals
   *
   * The slice of this session that admin helpers use.
   *
   * @returns Session internals
   */
  #internals(): SessionInternals {
    return {
      user: this.user,
      keyset: this.#keyset,
      request: this.#api.request,
      fetchOrg: () => this.#trust.fetchOrg(),
      roots: () => this.#trust.roots(),
      trust: (org) => this.#trust.trust(org),
      recoveryKeyPair: () => this.#trust.recoveryKeyPair(),
      recipientKeys: (userIds, groupIds) =>
        this.#trust.recipientKeys(userIds, groupIds),
      groups: () => this.#trust.groups(),
      sync: () => this.#cache.sync(),
    };
  }
}
