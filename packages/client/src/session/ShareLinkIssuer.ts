import {
  deriveShareKeys,
  generateShareSecret,
  sealShare,
  shareAccessHash,
  toBase64Url,
  utf8Encode,
} from "@keymember/core";

import { encode, parseResponse } from "../schemas.js";
import { shareLinksResponseSchema } from "../shareLinks.js";
import type {
  ShareField,
  ShareLink,
  ShareLinkSummary,
  SharedSnapshot,
} from "../shareLinks.js";
import type { AuthorizedRequest } from "./AuthorizedApi.js";
import type { VaultCache } from "./VaultCache.js";

/**
 * ### ShareLinkIssuer
 *
 * Share links for people outside a vault: a snapshot of one item sealed under a key only the
 * link carries, plus listing and closing the links this user (or, for admins, anyone) made.
 */
export class ShareLinkIssuer {
  readonly #request: AuthorizedRequest;
  readonly #cache: Pick<VaultCache, "getItem" | "item">;
  readonly #senderName: string;

  /**
   * ### constructor
   *
   * @param request Authenticated requests to the server
   * @param cache The session's vaults and items
   * @param senderName Name shown to the recipient as the sender
   */
  constructor(
    request: AuthorizedRequest,
    cache: Pick<VaultCache, "getItem" | "item">,
    senderName: string,
  ) {
    this.#request = request;
    this.#cache = cache;
    this.#senderName = senderName;
  }

  /**
   * ### create
   *
   * Makes a share link for one item: a snapshot of its title, URLs and the chosen fields, sealed
   * under a fresh key that only the link carries. Later edits to the item do not reach the link.
   *
   * @param itemId Item to share
   * @param options Fields to include, lifetime, number of views, and an optional passphrase
   * @returns The link; build the URL with `shareLinkUrl` and send the passphrase separately
   */
  async create(
    itemId: string,
    options: {
      fields: ReadonlyArray<ShareField>;
      expiresInMs: number;
      maxViews: number;
      passphrase?: string | undefined;
    },
  ): Promise<ShareLink> {
    const item = this.#cache.item(itemId);
    const { overview, details } = this.#cache.getItem(itemId);
    const included = new Set(options.fields);
    const pick = (field: ShareField): Record<string, string> => {
      const value = details[field];

      return included.has(field) && value !== undefined && value !== ""
        ? { [field]: value }
        : {};
    };
    const snapshot: SharedSnapshot = {
      title: overview.title,
      urls: [...overview.urls],
      sharedBy: this.#senderName,
      ...pick("username"),
      ...pick("password"),
      ...pick("totp"),
      ...pick("notes"),
    };
    const shareId = crypto.randomUUID();
    const secret = generateShareSecret();
    const passphrase =
      options.passphrase === undefined || options.passphrase === ""
        ? undefined
        : options.passphrase;
    const keys = await deriveShareKeys(secret, shareId, passphrase);

    await this.#request({
      method: "POST",
      path: "/api/shares",
      body: {
        id: shareId,
        vaultId: item.encrypted.vaultId,
        itemId,
        ciphertext: encode(
          sealShare(keys, shareId, utf8Encode(JSON.stringify(snapshot))),
        ),
        accessHash: encode(shareAccessHash(keys.accessProof)),
        passphrase: passphrase !== undefined,
        lifetimeSeconds: Math.round(options.expiresInMs / 1000),
        maxViews: options.maxViews,
      },
    });

    return {
      shareId,
      secret: toBase64Url(secret),
      needsPassphrase: passphrase !== undefined,
    };
  }

  /**
   * ### list
   *
   * Lists share links this user made, optionally for one item; admins can list everyone's.
   *
   * @param options Item to filter by, and whether to include other members' links (admins)
   * @returns The links, newest first
   */
  async list(
    options: { itemId?: string; all?: boolean } = {},
  ): Promise<Array<ShareLinkSummary>> {
    const query = new URLSearchParams({
      ...(options.itemId === undefined ? {} : { itemId: options.itemId }),
      ...(options.all === true ? { all: "true" } : {}),
    });

    return parseResponse(
      shareLinksResponseSchema,
      await this.#request({
        method: "GET",
        path: `/api/shares?${query.toString()}`,
      }),
    ).shares;
  }

  /**
   * ### revoke
   *
   * Closes a share link. Its sender or an admin can do this.
   *
   * @param shareId Link to close
   */
  async revoke(shareId: string): Promise<void> {
    await this.#request({ method: "DELETE", path: `/api/shares/${shareId}` });
  }
}
