import type {
  NewShareLink,
  ShareLinkRecord,
  ShareRepository,
} from "../repositories/ShareRepository.js";
import { COLLECTIONS } from "./collections.js";
import type { DocumentData, Documents } from "./Documents.js";
import {
  bytes,
  date,
  flag,
  integer,
  optionalBytes,
  optionalDate,
  text,
} from "./fields.js";
import { insertNew } from "./insertNew.js";

const SHARES = COLLECTIONS.shares;

/**
 * ### CLEARED
 *
 * Fields of a link that can no longer open: no ciphertext, and out of the `ciphertextUntil`
 * index the cleanup reads, since Firestore range queries skip `null`.
 */
const CLEARED = { ciphertext: null, ciphertextUntil: null } as const;

/**
 * ### CLEANUP_PAGE
 *
 * Most expired links cleared while creating one.
 */
const CLEANUP_PAGE = 20;

/**
 * ### LIST_LIMIT
 *
 * Most links {@link FirestoreShareRepository.list} returns, as the SQL `LIMIT`.
 */
const LIST_LIMIT = 200;

/**
 * ### FirestoreShareRepository
 *
 * {@link ShareRepository} on Firestore. Links are documents keyed by their id.
 */
export class FirestoreShareRepository implements ShareRepository {
  readonly #docs: Documents;

  /**
   * ### constructor
   *
   * @param docs Documents to work in, inside a transaction or not
   */
  constructor(docs: Documents) {
    this.#docs = docs;
  }

  /**
   * ### exists
   *
   * @see {@link ShareRepository.exists}
   */
  async exists(shareId: string): Promise<boolean> {
    return (await this.#docs.get(SHARES, shareId)) !== undefined;
  }

  /**
   * ### insert
   *
   * @see {@link ShareRepository.insert}
   */
  async insert(share: NewShareLink, now: Date): Promise<void> {
    // Links that can no longer open keep no ciphertext. Only links still holding one are read
    // (cleared links leave the index), a page at a time
    for (const expired of await this.#docs.findBefore(
      SHARES,
      "ciphertextUntil",
      now,
      CLEANUP_PAGE,
    )) {
      await this.#docs.update(SHARES, expired.id, CLEARED);
    }

    await insertNew(this.#docs, SHARES, share.id, {
      id: share.id,
      orgId: share.orgId,
      vaultId: share.vaultId,
      itemId: share.itemId,
      createdBy: share.createdBy,
      ciphertext: share.ciphertext,
      ciphertextUntil: share.expiresAt,
      accessHash: share.accessHash,
      passphrase: share.passphrase,
      expiresAt: share.expiresAt,
      maxViews: share.maxViews,
      views: 0,
      failedAttempts: 0,
      revokedAt: null,
      lastOpenedAt: null,
      // The SQL column defaults to now(), the database's clock rather than the request's
      createdAt: new Date(),
    });
  }

  /**
   * ### list
   *
   * @see {@link ShareRepository.list}
   */
  async list(filter: {
    orgId: string;
    createdBy?: string | undefined;
    itemId?: string | undefined;
  }): Promise<Array<ShareLinkRecord>> {
    const shares = await this.#docs.find(SHARES, [
      ["orgId", filter.orgId],
      ...(filter.createdBy === undefined
        ? []
        : [["createdBy", filter.createdBy] as const]),
      ...(filter.itemId === undefined
        ? []
        : [["itemId", filter.itemId] as const]),
    ]);

    return shares
      .map((share) => toRecord(share.id, share.data))
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(0, LIST_LIMIT);
  }

  /**
   * ### lock
   *
   * @see {@link ShareRepository.lock}
   */
  async lock(
    shareId: string,
    orgId?: string,
  ): Promise<ShareLinkRecord | undefined> {
    const share = await this.#docs.get(SHARES, shareId);

    if (
      share === undefined ||
      (orgId !== undefined && text(share, "orgId") !== orgId)
    ) {
      return undefined;
    }

    return toRecord(shareId, share);
  }

  /**
   * ### revoke
   *
   * @see {@link ShareRepository.revoke}
   */
  async revoke(shareId: string, at: Date): Promise<void> {
    const share = await this.#docs.get(SHARES, shareId);

    if (share === undefined) {
      return;
    }

    await this.#docs.update(SHARES, shareId, {
      revokedAt: optionalDate(share, "revokedAt") ?? at,
      ...CLEARED,
    });
  }

  /**
   * ### revokeAllBy
   *
   * @see {@link ShareRepository.revokeAllBy}
   */
  async revokeAllBy(userId: string, at: Date): Promise<number> {
    const open = (
      await this.#docs.find(SHARES, [
        ["createdBy", userId],
        ["revokedAt", null],
      ])
    ).filter((share) => share.data.ciphertext !== null);

    for (const share of open) {
      await this.#docs.update(SHARES, share.id, {
        revokedAt: at,
        ...CLEARED,
      });
    }

    return open.length;
  }

  /**
   * ### recordFailedAttempt
   *
   * @see {@link ShareRepository.recordFailedAttempt}
   */
  async recordFailedAttempt(
    shareId: string,
    failedAttempts: number,
    limit: number,
    at: Date,
  ): Promise<void> {
    await this.#docs.update(SHARES, shareId, {
      failedAttempts,
      ...(failedAttempts >= limit ? { revokedAt: at, ...CLEARED } : {}),
    });
  }

  /**
   * ### recordView
   *
   * @see {@link ShareRepository.recordView}
   */
  async recordView(shareId: string, views: number, at: Date): Promise<void> {
    const share = await this.#docs.get(SHARES, shareId);

    if (share === undefined) {
      return;
    }

    await this.#docs.update(SHARES, shareId, {
      views,
      lastOpenedAt: at,
      ...(views >= integer(share, "maxViews") ? CLEARED : {}),
    });
  }
}

/**
 * ### toRecord
 *
 * Maps a share document to a {@link ShareLinkRecord}.
 *
 * @param id Document id, the link id
 * @param data Document fields
 * @returns The record
 */
function toRecord(id: string, data: DocumentData): ShareLinkRecord {
  return {
    id,
    orgId: text(data, "orgId"),
    vaultId: text(data, "vaultId"),
    itemId: text(data, "itemId"),
    createdBy: text(data, "createdBy"),
    ciphertext: optionalBytes(data, "ciphertext"),
    accessHash: bytes(data, "accessHash"),
    passphrase: flag(data, "passphrase"),
    expiresAt: date(data, "expiresAt"),
    maxViews: integer(data, "maxViews"),
    views: integer(data, "views"),
    failedAttempts: integer(data, "failedAttempts"),
    revokedAt: optionalDate(data, "revokedAt"),
    lastOpenedAt: optionalDate(data, "lastOpenedAt"),
    createdAt: date(data, "createdAt"),
  };
}
