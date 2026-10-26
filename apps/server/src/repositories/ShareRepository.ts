/**
 * ### ShareLinkRecord
 *
 * A share link as stored. `ciphertext` is the sealed item snapshot, `undefined` once the link
 * can no longer open (revoked, used up or expired), so nothing is kept that nobody may read.
 */
export interface ShareLinkRecord {
  readonly id: string;
  readonly orgId: string;
  readonly vaultId: string;
  readonly itemId: string;
  readonly createdBy: string;
  readonly ciphertext: Uint8Array | undefined;
  /** Hash of the proof only a link holder can compute */
  readonly accessHash: Uint8Array;
  /** Whether opening also needs a passphrase */
  readonly passphrase: boolean;
  readonly expiresAt: Date;
  readonly maxViews: number;
  readonly views: number;
  /** Wrong passphrases so far */
  readonly failedAttempts: number;
  readonly revokedAt: Date | undefined;
  readonly lastOpenedAt: Date | undefined;
  readonly createdAt: Date;
}

/**
 * ### NewShareLink
 *
 * What creating a link stores.
 */
export type NewShareLink = Pick<
  ShareLinkRecord,
  | "accessHash"
  | "createdBy"
  | "expiresAt"
  | "id"
  | "itemId"
  | "maxViews"
  | "orgId"
  | "passphrase"
  | "vaultId"
> & { readonly ciphertext: Uint8Array };

/**
 * ### ShareRepository
 *
 * Storage of share links.
 */
export interface ShareRepository {
  /**
   * ### exists
   *
   * Whether a link id is taken.
   *
   * @param shareId Link id
   * @returns Whether it exists
   */
  exists(shareId: string): Promise<boolean>;

  /**
   * ### insert
   *
   * Stores a new link, first dropping the ciphertext of links that have expired.
   *
   * @param share New link
   * @param now Current time
   */
  insert(share: NewShareLink, now: Date): Promise<void>;

  /**
   * ### list
   *
   * An organisation's links, newest first, at most 200.
   *
   * @param filter Organisation, optionally one creator and one item
   * @returns The links
   */
  list(filter: {
    orgId: string;
    createdBy?: string | undefined;
    itemId?: string | undefined;
  }): Promise<Array<ShareLinkRecord>>;

  /**
   * ### lock
   *
   * Locks a link for a change within the current transaction.
   *
   * @param shareId Link id
   * @param orgId Organisation it must belong to; any when omitted
   * @returns The link, or `undefined` when there is none
   */
  lock(shareId: string, orgId?: string): Promise<ShareLinkRecord | undefined>;

  /**
   * ### revoke
   *
   * Closes a link and drops its ciphertext. Revoking twice keeps the first time.
   *
   * @param shareId Link id
   * @param at Time of revocation
   */
  revoke(shareId: string, at: Date): Promise<void>;

  /**
   * ### revokeAllBy
   *
   * Closes every link a member made that can still open, when they leave.
   *
   * @param userId Member who made the links
   * @param at Time of revocation
   * @returns Number of links closed
   */
  revokeAllBy(userId: string, at: Date): Promise<number>;

  /**
   * ### recordFailedAttempt
   *
   * Counts a wrong passphrase, closing the link when it reaches the limit.
   *
   * @param shareId Link id
   * @param failedAttempts Count including this one
   * @param limit Count at which the link closes
   * @param at Time of the attempt
   */
  recordFailedAttempt(
    shareId: string,
    failedAttempts: number,
    limit: number,
    at: Date,
  ): Promise<void>;

  /**
   * ### recordView
   *
   * Counts an opening, dropping the ciphertext when the last view is used.
   *
   * @param shareId Link id
   * @param views Count including this one
   * @param at Time of the opening
   */
  recordView(shareId: string, views: number, at: Date): Promise<void>;
}
