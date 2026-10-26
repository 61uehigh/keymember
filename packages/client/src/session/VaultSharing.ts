import {
  decryptItemDetails,
  decryptItemOverview,
  encryptItem,
  generateVaultKey,
  openItemKey,
  sealVaultName,
} from "@keymember/core";
import type { SymmetricKey } from "@keymember/core";
import { z } from "zod";

import { grantVaultKey, recoveryCopy } from "../grants.js";
import { b64, encode, parseResponse } from "../schemas.js";
import type {
  PrincipalType,
  RecipientKeys,
  VaultPermission,
} from "../Session.type.js";
import type { AuthorizedRequest } from "./AuthorizedApi.js";
import type { TrustContext } from "./TrustContext.js";
import { grantVerifies } from "./verification.js";
import { itemRequestBody } from "./VaultCache.js";
import type { VaultCache } from "./VaultCache.js";

/**
 * ### AccessPrincipal
 *
 * Someone who holds a vault's key, and what they may do with it.
 */
export interface AccessPrincipal {
  principalType: PrincipalType;
  principalId: string;
  permission: VaultPermission;
}

/**
 * ### VaultSharing
 *
 * Who holds each vault's key. Creating, sharing and rotating a vault all wrap its key only to
 * recipients the trust context verified, sign each grant, and keep a copy for the
 * organisation's recovery key.
 */
export class VaultSharing {
  readonly #request: AuthorizedRequest;
  readonly #trust: Pick<
    TrustContext,
    "fetchOrg" | "granters" | "recipientKeys" | "trust"
  >;
  readonly #cache: Pick<VaultCache, "itemsIn" | "sync" | "vault">;
  readonly #userId: string;
  readonly #signingKey: Uint8Array;

  /**
   * ### constructor
   *
   * @param request Authenticated requests to the server
   * @param trust Verifies recipients' keys
   * @param cache The session's vaults and items
   * @param userId The logged-in user, who always manages the vaults they create
   * @param signingKey The user's signing private key, for grant signatures
   */
  constructor(
    request: AuthorizedRequest,
    trust: Pick<
      TrustContext,
      "fetchOrg" | "granters" | "recipientKeys" | "trust"
    >,
    cache: Pick<VaultCache, "itemsIn" | "sync" | "vault">,
    userId: string,
    signingKey: Uint8Array,
  ) {
    this.#request = request;
    this.#trust = trust;
    this.#cache = cache;
    this.#userId = userId;
    this.#signingKey = signingKey;
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
  async createVault(
    name: string,
    kind: "personal" | "shared",
    members: ReadonlyArray<{ userId: string; permission: VaultPermission }>,
    groups: ReadonlyArray<{
      groupId: string;
      permission: VaultPermission;
    }> = [],
  ): Promise<string> {
    const vaultId = crypto.randomUUID();
    const vaultKey = generateVaultKey();
    const principals: Array<AccessPrincipal> = [
      {
        principalType: "user",
        principalId: this.#userId,
        permission: "manage",
      },
      ...members.map((member) => ({
        principalType: "user" as const,
        principalId: member.userId,
        permission: member.permission,
      })),
      ...groups.map((group) => ({
        principalType: "group" as const,
        principalId: group.groupId,
        permission: group.permission,
      })),
    ];
    const keys = await this.#keysFor(principals);
    const access = [];

    for (const principal of principals) {
      access.push(
        await this.#accessEntry(keys, principal, vaultKey, vaultId, 1),
      );
    }

    await this.#request({
      method: "POST",
      path: "/api/vaults",
      body: {
        id: vaultId,
        kind,
        encryptedName: encode(sealVaultName(vaultKey, vaultId, name)),
        access,
        ...(await recoveryCopy(vaultKey, vaultId, 1, keys.recovery)),
      },
    });
    await this.#cache.sync();

    return vaultId;
  }

  /**
   * ### grant
   *
   * Shares an existing vault with a member or group, or changes their permission, at the
   * vault's current key generation. Everyone holding a group's key gets access, now and as
   * members are added later.
   *
   * @param vaultId Vault to share
   * @param principal Recipient and permission
   */
  async grant(vaultId: string, principal: AccessPrincipal): Promise<void> {
    const vault = this.#cache.vault(vaultId);
    const entry = await this.#accessEntry(
      await this.#keysFor([principal]),
      principal,
      vault.key,
      vaultId,
      vault.keyGeneration,
    );

    await this.#request({
      method: "PUT",
      path: `/api/vaults/${vaultId}/access/${principal.principalId}`,
      body: { ...entry, keyGeneration: vault.keyGeneration },
    });
  }

  /**
   * ### access
   *
   * Lists who can open a vault. Managers only.
   *
   * @param vaultId Vault to inspect
   * @returns Principals and their permissions
   */
  async access(vaultId: string): Promise<Array<AccessPrincipal>> {
    return parseResponse(
      z.object({
        access: z.array(
          z.object({
            principalType: z.enum(["user", "group"]),
            principalId: z.string(),
            permission: z.enum(["view", "edit", "manage"]),
          }),
        ),
      }),
      await this.#request({
        method: "GET",
        path: `/api/vaults/${vaultId}/access`,
      }),
    ).access;
  }

  /**
   * ### revoke
   *
   * Removes a member's or group's access entry without rotating the key. Prefer
   * {@link VaultSharing.rotate} with the principal removed, which also protects future
   * changes from anyone who kept the old key.
   *
   * @param vaultId Vault to unshare
   * @param principalId Member or group losing access
   */
  async revoke(vaultId: string, principalId: string): Promise<void> {
    await this.#request({
      method: "DELETE",
      path: `/api/vaults/${vaultId}/access/${principalId}`,
    });
  }

  /**
   * ### rotate
   *
   * Replaces a vault's key and every item key in it, re-encrypts all items, and re-shares the
   * new key with the remaining members, groups and the recovery key. Removed principals (or
   * anyone who copied old keys) cannot read anything written after this. Items they already
   * read stay exposed, so change those passwords too.
   *
   * Only principals holding a grant signed by a trusted member keep access: a server that
   * slips someone into the access list does not get them a fresh, validly signed key from this
   * manager. When the server does not send grant signatures, everyone listed is kept.
   *
   * @param vaultId Vault to rotate
   * @param removePrincipalIds Members or groups to drop in the same step
   * @param options `keepUnverified` also keeps principals whose current grant does not verify,
   * after the caller confirmed them
   */
  async rotate(
    vaultId: string,
    removePrincipalIds: ReadonlyArray<string> = [],
    options: { readonly keepUnverified?: boolean } = {},
  ): Promise<void> {
    await this.#cache.sync();

    const vault = this.#cache.vault(vaultId);
    const removed = new Set(removePrincipalIds);
    const remaining = (await this.#verifiedAccess(vaultId)).filter(
      (entry) =>
        !removed.has(entry.principalId) &&
        (entry.verified || options.keepUnverified === true),
    );
    const keys = await this.#keysFor(remaining);
    const nextGeneration = vault.keyGeneration + 1;
    const nextKey = generateVaultKey();
    const access = [];

    for (const entry of remaining) {
      access.push(
        await this.#accessEntry(keys, entry, nextKey, vaultId, nextGeneration),
      );
    }

    const items = this.#cache.itemsIn(vaultId).map((item) => {
      const itemKey = openItemKey(vault.key, item.encrypted);

      // A fresh item key per item: old item keys may be known to whoever is being removed
      const reencrypted = encryptItem(
        nextKey,
        { vaultId, itemId: item.encrypted.id },
        decryptItemOverview(itemKey, item.encrypted),
        decryptItemDetails(itemKey, item.encrypted),
      );

      return { ...itemRequestBody(reencrypted), baseRevision: item.revision };
    });

    await this.#request({
      method: "POST",
      path: `/api/vaults/${vaultId}/rotate`,
      body: {
        keyGeneration: nextGeneration,
        encryptedName: encode(sealVaultName(nextKey, vaultId, vault.view.name)),
        access,
        items,
        ...(await recoveryCopy(
          nextKey,
          vaultId,
          nextGeneration,
          keys.recovery,
        )),
      },
    });
    await this.#cache.sync();
  }

  /**
   * ### #verifiedAccess
   *
   * The vault's access list, each entry marked by whether its current grant carries a valid
   * signature from a trusted member.
   *
   * @param vaultId Vault
   * @returns Principals, permissions and whether their grant verified
   */
  async #verifiedAccess(
    vaultId: string,
  ): Promise<Array<AccessPrincipal & { readonly verified: boolean }>> {
    const response = parseResponse(
      z.object({
        access: z.array(
          z.object({
            principalType: z.enum(["user", "group"]),
            principalId: z.string(),
            permission: z.enum(["view", "edit", "manage"]),
            // Sent by servers that expose grants; older ones send only the three fields above
            wrappedKey: b64.optional(),
            keyGeneration: z.number().int().optional(),
            grantedBy: z.string().nullable().optional(),
            grantSignature: b64.nullable().optional(),
          }),
        ),
      }),
      await this.#request({
        method: "GET",
        path: `/api/vaults/${vaultId}/access`,
      }),
    );
    const signed = response.access.some(
      (entry) => entry.grantSignature !== undefined,
    );

    if (!signed) {
      return response.access.map((entry) => ({
        principalType: entry.principalType,
        principalId: entry.principalId,
        permission: entry.permission,
        verified: true,
      }));
    }

    const { certified } = this.#trust.trust(await this.#trust.fetchOrg());
    const granters = this.#trust.granters(certified);

    return response.access.map((entry) => ({
      principalType: entry.principalType,
      principalId: entry.principalId,
      permission: entry.permission,
      verified:
        entry.wrappedKey !== undefined &&
        entry.keyGeneration !== undefined &&
        grantVerifies(
          vaultId,
          {
            principalType: entry.principalType,
            principalId: entry.principalId,
            wrappedKey: entry.wrappedKey,
            keyGeneration: entry.keyGeneration,
            grantedBy: entry.grantedBy ?? null,
            grantSignature: entry.grantSignature ?? null,
          },
          granters,
        ),
    }));
  }

  /**
   * ### #keysFor
   *
   * Verified keys of the given principals and of the recovery key.
   *
   * @param principals Members and groups about to receive a key
   * @returns Their verified keys
   */
  #keysFor(principals: ReadonlyArray<AccessPrincipal>): Promise<RecipientKeys> {
    return this.#trust.recipientKeys(
      principals
        .filter((entry) => entry.principalType === "user")
        .map((entry) => entry.principalId),
      principals
        .filter((entry) => entry.principalType === "group")
        .map((entry) => entry.principalId),
    );
  }

  /**
   * ### #accessEntry
   *
   * Wraps a vault key to one recipient, as an access entry for the vault routes.
   *
   * @param keys Verified recipient keys
   * @param principal Recipient and the permission they get
   * @param vaultKey Vault key to wrap
   * @param vaultId Vault id
   * @param keyGeneration Vault key generation
   * @returns The access entry
   */
  async #accessEntry(
    keys: RecipientKeys,
    principal: AccessPrincipal,
    vaultKey: SymmetricKey,
    vaultId: string,
    keyGeneration: number,
  ): Promise<Record<string, unknown>> {
    const group =
      principal.principalType === "group"
        ? keys.groups.get(principal.principalId)
        : undefined;
    const publicKey =
      principal.principalType === "group"
        ? group?.publicKey
        : keys.members.get(principal.principalId);

    if (publicKey === undefined) {
      throw new Error(`No key for ${principal.principalId}`);
    }

    return {
      principalType: principal.principalType,
      principalId: principal.principalId,
      permission: principal.permission,
      ...(group === undefined
        ? {}
        : { groupKeysetVersion: group.keysetVersion }),
      ...(await grantVaultKey(this.#signingKey, vaultKey, {
        vaultId,
        keyGeneration,
        principalType: principal.principalType,
        principalId: principal.principalId,
        encryptionPublicKey: publicKey,
      })),
    };
  }
}
