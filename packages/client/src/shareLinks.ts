import {
  deriveShareKeys,
  fromBase64Url,
  openShare,
  SHARE_SECRET_LENGTH,
  utf8Decode,
} from "@keymember/core";
import { z } from "zod";

import { b64, encode, parseResponse } from "./schemas.js";
import { send } from "./transport.js";
import type { Transport } from "./transport.js";

/**
 * ### ShareField
 *
 * Item fields a sender may include in a share link. The title and URLs always go along.
 */
export type ShareField = "username" | "password" | "totp" | "notes";

/**
 * ### SharedSnapshot
 *
 * What the recipient of a share link sees: a copy of the item taken when the link was made.
 */
export interface SharedSnapshot {
  /**
   * ### title
   *
   * Item title.
   */
  readonly title: string;

  /**
   * ### urls
   *
   * Item URLs.
   */
  readonly urls: ReadonlyArray<string>;

  /**
   * ### username
   *
   * Username, when the sender included it.
   */
  readonly username?: string;

  /**
   * ### password
   *
   * Password, when the sender included it.
   */
  readonly password?: string;

  /**
   * ### totp
   *
   * TOTP secret or `otpauth://` URI, when the sender included it.
   */
  readonly totp?: string;

  /**
   * ### notes
   *
   * Notes, when the sender included them.
   */
  readonly notes?: string;

  /**
   * ### sharedBy
   *
   * Sender's name as written by their client; the server cannot vouch for it.
   */
  readonly sharedBy: string;
}

/**
 * ### sharedSnapshotSchema
 *
 * Validates a decrypted snapshot.
 */
export const sharedSnapshotSchema = z.object({
  title: z.string(),
  urls: z.array(z.string()),
  username: z.string().optional(),
  password: z.string().optional(),
  totp: z.string().optional(),
  notes: z.string().optional(),
  sharedBy: z.string(),
});

/**
 * ### ShareLink
 *
 * A link the sender passes on. The secret must travel only inside the URL fragment.
 */
export interface ShareLink {
  /**
   * ### shareId
   *
   * Share id.
   */
  readonly shareId: string;

  /**
   * ### secret
   *
   * Base64url link secret.
   */
  readonly secret: string;

  /**
   * ### needsPassphrase
   *
   * Whether the recipient also needs the passphrase, passed on separately.
   */
  readonly needsPassphrase: boolean;
}

/**
 * ### ShareLinkSummary
 *
 * A link as listed for its sender or for admins. Never contains the secret.
 */
export interface ShareLinkSummary {
  readonly id: string;
  readonly vaultId: string;
  readonly itemId: string;
  readonly createdBy: string;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly maxViews: number;
  readonly views: number;
  readonly passphrase: boolean;
  readonly lastOpenedAt: string | null;
  readonly status: "active" | "expired" | "used_up" | "revoked";
}

/**
 * ### shareLinksResponseSchema
 *
 * Response of `GET /api/shares`.
 */
export const shareLinksResponseSchema = z.object({
  shares: z.array(
    z.object({
      id: z.string(),
      vaultId: z.string(),
      itemId: z.string(),
      createdBy: z.string(),
      createdAt: z.string(),
      expiresAt: z.string(),
      maxViews: z.number().int(),
      views: z.number().int(),
      passphrase: z.boolean(),
      lastOpenedAt: z.string().nullable(),
      status: z.enum(["active", "expired", "used_up", "revoked"]),
    }),
  ),
});

/**
 * ### shareLinkUrl
 *
 * Builds the URL to send: the web vault's share page, with everything secret in the fragment
 * so it never reaches the server or a proxy log.
 *
 * @param baseUrl Address of the keymember server that serves the web vault
 * @param link The link
 * @returns The URL
 */
export function shareLinkUrl(baseUrl: string, link: ShareLink): string {
  const params = new URLSearchParams({ k: link.secret });

  if (link.needsPassphrase) {
    params.set("p", "1");
  }

  return `${new URL("/", baseUrl).toString()}#/share/${link.shareId}?${params.toString()}`;
}

/**
 * ### parseShareLink
 *
 * Reads a share link from a full URL or from the web router's `share/<id>?k=…` path.
 *
 * @param text URL or path
 * @returns The link, or `undefined` when it is not a well-formed share link
 */
export function parseShareLink(text: string): ShareLink | undefined {
  const fragment = text.includes("#")
    ? text.slice(text.indexOf("#") + 1)
    : text;
  const match = /^\/?share\/([0-9a-f-]{36})\?(.*)$/i.exec(fragment);

  if (match === null) {
    return undefined;
  }

  const params = new URLSearchParams(match[2]);
  const secret = params.get("k") ?? "";

  if (fromBase64Url(secret)?.length !== SHARE_SECRET_LENGTH) {
    return undefined;
  }

  return {
    shareId: (match[1] ?? "").toLowerCase(),
    secret,
    needsPassphrase: params.get("p") === "1",
  };
}

/**
 * ### openShareLink
 *
 * Opens a share link without an account: proves possession of the link (and passphrase) to the
 * server, which counts one view, and decrypts the snapshot. A wrong passphrase is rejected by
 * the server before the view is counted.
 *
 * @param transport Transport to the server
 * @param link The link
 * @param passphrase Passphrase, when the link needs one
 * @returns The snapshot, when the link expires and how many views remain
 */
export async function openShareLink(
  transport: Transport,
  link: ShareLink,
  passphrase?: string,
): Promise<{
  snapshot: SharedSnapshot;
  expiresAt: string;
  viewsLeft: number;
}> {
  const secret = fromBase64Url(link.secret);

  if (secret === undefined) {
    throw new Error("Malformed share link");
  }

  const keys = await deriveShareKeys(
    secret,
    link.shareId,
    link.needsPassphrase ? passphrase : undefined,
  );
  const response = parseResponse(
    z.object({
      ciphertext: b64,
      expiresAt: z.string(),
      viewsLeft: z.number().int(),
    }),
    await send(transport, {
      method: "POST",
      path: `/api/shares/${link.shareId}/open`,
      body: { accessProof: encode(keys.accessProof) },
    }),
  );
  const snapshot = sharedSnapshotSchema.parse(
    JSON.parse(utf8Decode(openShare(keys, link.shareId, response.ciphertext))),
  );

  const optional = (key: ShareField): Partial<Record<ShareField, string>> => {
    const value = snapshot[key];

    return value === undefined ? {} : { [key]: value };
  };

  return {
    snapshot: {
      title: snapshot.title,
      urls: snapshot.urls,
      sharedBy: snapshot.sharedBy,
      ...optional("username"),
      ...optional("password"),
      ...optional("totp"),
      ...optional("notes"),
    },
    expiresAt: response.expiresAt,
    viewsLeft: response.viewsLeft,
  };
}
