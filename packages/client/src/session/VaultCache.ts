import {
  decryptItemDetails,
  decryptItemOverview,
  openItemKey,
  openVaultName,
  unwrapGroupPrivateKey,
  unwrapVaultKey,
} from "@keymember/core";
import type {
  AccountKeyset,
  EncryptedItem,
  EncryptionKeyPair,
  ItemDetails,
  ItemOverview,
  SymmetricKey,
} from "@keymember/core";

import { encode, parseResponse, syncResponseSchema } from "../schemas.js";
import type {
  ItemSummary,
  SessionUser,
  VaultPermission,
  VaultView,
} from "../Session.type.js";
import type { AuthorizedRequest } from "./AuthorizedApi.js";
import type { TrustContext } from "./TrustContext.js";
import { certifiedGroup, grantVerifies } from "./verification.js";

/**
 * ### CachedVault
 *
 * A vault the session can open: its key at the current generation and what the user sees.
 */
export interface CachedVault {
  readonly view: VaultView;
  readonly key: SymmetricKey;
  readonly keyGeneration: number;
}

/**
 * ### CachedItem
 *
 * An item as last synced, still encrypted, with the revision edits must name.
 */
export interface CachedItem {
  readonly encrypted: EncryptedItem;
  readonly revision: number;
}

const PERMISSION_RANK: Readonly<Record<VaultPermission, number>> = {
  view: 0,
  edit: 1,
  manage: 2,
};

/**
 * ### itemRequestBody
 *
 * Encodes an encrypted item for an API request.
 *
 * @param item Encrypted item
 * @returns The JSON body fields
 */
export function itemRequestBody(item: EncryptedItem): Record<string, string> {
  return {
    id: item.id,
    vaultId: item.vaultId,
    encryptedItemKey: encode(item.encryptedItemKey),
    encryptedOverview: encode(item.encryptedOverview),
    encryptedDetails: encode(item.encryptedDetails),
  };
}

/**
 * ### VaultCache
 *
 * The vaults and items this session can read, kept in memory and brought up to date by
 * {@link VaultCache.sync}. Sync opens only vault keys whose grant was signed by someone the
 * trust context vouches for, and group keys whose certificate a trusted admin signed; anything
 * else the server sends is ignored.
 */
export class VaultCache {
  readonly #request: AuthorizedRequest;
  readonly #trust: Pick<TrustContext, "fetchOrg" | "granters" | "trust">;
  readonly #user: SessionUser;
  readonly #keyset: AccountKeyset;
  readonly #vaults = new Map<string, CachedVault>();
  readonly #items = new Map<string, CachedItem>();
  #revision = 0;
  #syncing: Promise<void> | undefined;

  /**
   * ### constructor
   *
   * @param request Authenticated requests to the server
   * @param trust Whose grants and group keys to believe
   * @param user The logged-in user
   * @param keyset The user's unlocked keyset
   */
  constructor(
    request: AuthorizedRequest,
    trust: Pick<TrustContext, "fetchOrg" | "granters" | "trust">,
    user: SessionUser,
    keyset: AccountKeyset,
  ) {
    this.#request = request;
    this.#trust = trust;
    this.#user = user;
    this.#keyset = keyset;
  }

  /**
   * ### sync
   *
   * Pulls changes since the last sync and updates the cache. Vaults that disappeared from the
   * server response, and their items, are dropped. Calls made while a sync runs share it, so
   * an older response can never be applied after a newer one.
   */
  sync(): Promise<void> {
    this.#syncing ??= this.#pull().finally(() => {
      this.#syncing = undefined;
    });

    return this.#syncing;
  }

  /**
   * ### #pull
   *
   * One sync round. When the server says the cache is ahead of it (its data was restored from
   * a backup), drops every cached item and pulls everything again.
   */
  async #pull(): Promise<void> {
    let response = parseResponse(
      syncResponseSchema,
      await this.#request({
        method: "GET",
        path: `/api/sync?since=${String(this.#revision)}`,
      }),
    );

    if (response.reset === true && this.#revision !== 0) {
      this.#items.clear();
      this.#revision = 0;
      response = parseResponse(
        syncResponseSchema,
        await this.#request({ method: "GET", path: "/api/sync?since=0" }),
      );
    }
    const visible = new Set(response.vaults.map((vault) => vault.id));
    const groupKeys = new Map<string, EncryptionKeyPair>();
    const org = await this.#trust.fetchOrg();
    const { certified, issuers } = this.#trust.trust(org);
    const granters = this.#trust.granters(certified);

    for (const group of response.groups) {
      // A copy of a superseded group key opens nothing current, and an uncertified group key
      // could be one the server made up
      if (
        group.memberKeysetVersion !== group.keysetVersion ||
        !certifiedGroup(group, org.org.id, issuers)
      ) {
        continue;
      }

      groupKeys.set(
        group.id,
        await unwrapGroupPrivateKey(
          group.wrappedPrivateKey,
          group.id,
          group.keysetVersion,
          this.#user.id,
          this.#keyset.encryption,
          group.certificate.encryptionPublicKey,
        ),
      );
    }

    for (const vault of response.vaults) {
      // Paths the session can open at the vault's current generation, own entry first
      const usable = vault.access
        .filter(
          (path) =>
            path.keyGeneration === vault.keyGeneration &&
            (path.principalType === "user"
              ? path.principalId === this.#user.id
              : groupKeys.has(path.principalId)) &&
            grantVerifies(vault.id, path, granters),
        )
        .sort((a, b) =>
          a.principalType === b.principalType
            ? 0
            : a.principalType === "user"
              ? -1
              : 1,
        );
      const [path] = usable;
      const holder =
        path?.principalType === "user"
          ? this.#keyset.encryption
          : groupKeys.get(path?.principalId ?? "");

      if (path === undefined || holder === undefined) {
        continue;
      }

      const key = await unwrapVaultKey(
        path.wrappedKey,
        vault.id,
        vault.keyGeneration,
        path.principalId,
        holder,
      );
      const permission = usable.reduce<VaultPermission>(
        (best, candidate) =>
          PERMISSION_RANK[candidate.permission] > PERMISSION_RANK[best]
            ? candidate.permission
            : best,
        "view",
      );

      this.#vaults.set(vault.id, {
        key,
        keyGeneration: vault.keyGeneration,
        view: {
          id: vault.id,
          kind: vault.kind,
          name: openVaultName(key, vault.id, vault.encryptedName),
          permission,
          rotationDue: vault.rotationDue,
        },
      });
    }

    for (const vaultId of this.#vaults.keys()) {
      if (!visible.has(vaultId)) {
        this.#vaults.delete(vaultId);
      }
    }

    for (const item of response.items) {
      this.#items.set(item.id, {
        revision: item.revision,
        encrypted: {
          id: item.id,
          vaultId: item.vaultId,
          encryptedItemKey: item.encryptedItemKey,
          encryptedOverview: item.encryptedOverview,
          encryptedDetails: item.encryptedDetails,
        },
      });
    }

    for (const itemId of response.deletedItemIds) {
      this.#items.delete(itemId);
    }

    for (const [itemId, item] of this.#items) {
      if (!visible.has(item.encrypted.vaultId)) {
        this.#items.delete(itemId);
      }
    }

    this.#revision = response.revision;
  }

  /**
   * ### listVaults
   *
   * Vaults in the cache.
   *
   * @returns Every vault the user can open
   */
  listVaults(): Array<VaultView> {
    return [...this.#vaults.values()].map((vault) => vault.view);
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
    return this.itemsIn(vaultId).map((item) => ({
      id: item.encrypted.id,
      vaultId: item.encrypted.vaultId,
      revision: item.revision,
      overview: decryptItemOverview(this.#itemKey(item), item.encrypted),
    }));
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
    const item = this.item(itemId);
    const itemKey = this.#itemKey(item);

    return {
      overview: decryptItemOverview(itemKey, item.encrypted),
      details: decryptItemDetails(itemKey, item.encrypted),
    };
  }

  /**
   * ### itemsIn
   *
   * The cached, still encrypted items, optionally of one vault.
   *
   * @param vaultId Vault to limit to
   * @returns Cached items
   */
  itemsIn(vaultId?: string): Array<CachedItem> {
    return [...this.#items.values()].filter(
      (item) => vaultId === undefined || item.encrypted.vaultId === vaultId,
    );
  }

  /**
   * ### vault
   *
   * Looks up a cached vault or throws when the user cannot open it.
   *
   * @param vaultId Vault to look up
   * @returns The cached vault
   */
  vault(vaultId: string): CachedVault {
    const vault = this.#vaults.get(vaultId);

    if (vault === undefined) {
      throw new Error(`Can't open vault ${vaultId}. Sync and try again.`);
    }

    return vault;
  }

  /**
   * ### item
   *
   * Looks up a cached item or throws when it is unknown.
   *
   * @param itemId Item to look up
   * @returns The cached item
   */
  item(itemId: string): CachedItem {
    const item = this.#items.get(itemId);

    if (item === undefined) {
      throw new Error(`Item ${itemId} isn't here yet. Sync and try again.`);
    }

    return item;
  }

  /**
   * ### #itemKey
   *
   * Opens a cached item's key with its vault's key.
   *
   * @param item Cached item
   * @returns The item key
   */
  #itemKey(item: CachedItem): SymmetricKey {
    return openItemKey(this.vault(item.encrypted.vaultId).key, item.encrypted);
  }
}
