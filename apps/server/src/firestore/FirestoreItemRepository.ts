import type {
  ItemCiphertext,
  ItemRepository,
  ItemVersion,
  SyncedItem,
} from "../repositories/ItemRepository.js";
import { COLLECTIONS, REVISION_SEQUENCE } from "./collections.js";
import type { DocumentData, Documents } from "./Documents.js";
import { bytes, integer, optionalDate, text } from "./fields.js";
import { insertNew } from "./insertNew.js";

const ITEMS = COLLECTIONS.items;
const ITEM_MOVES = COLLECTIONS.itemMoves;

/**
 * ### FirestoreItemRepository
 *
 * {@link ItemRepository} on Firestore. Items are keyed by their id.
 */
export class FirestoreItemRepository implements ItemRepository {
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
   * @see {@link ItemRepository.exists}
   */
  async exists(itemId: string): Promise<boolean> {
    return (await this.#docs.get(ITEMS, itemId)) !== undefined;
  }

  /**
   * ### isLiveIn
   *
   * @see {@link ItemRepository.isLiveIn}
   */
  async isLiveIn(itemId: string, vaultId: string): Promise<boolean> {
    const item = await this.#docs.get(ITEMS, itemId);

    return (
      item !== undefined &&
      text(item, "vaultId") === vaultId &&
      optionalDate(item, "deletedAt") === undefined
    );
  }

  /**
   * ### insert
   *
   * @see {@link ItemRepository.insert}
   */
  async insert(item: ItemCiphertext, by: string, at: Date): Promise<number> {
    const revision = await this.#docs.nextSequence(REVISION_SEQUENCE);

    await insertNew(this.#docs, ITEMS, item.id, {
      id: item.id,
      vaultId: item.vaultId,
      encItemKey: item.encryptedItemKey,
      encOverview: item.encryptedOverview,
      encDetails: item.encryptedDetails,
      revision,
      createdBy: by,
      updatedBy: by,
      updatedAt: at,
      deletedAt: null,
    });

    return revision;
  }

  /**
   * ### lockLive
   *
   * @see {@link ItemRepository.lockLive}
   */
  async lockLive(itemId: string): Promise<ItemVersion | undefined> {
    const item = await this.#docs.get(ITEMS, itemId);

    return item === undefined || optionalDate(item, "deletedAt") !== undefined
      ? undefined
      : { vaultId: text(item, "vaultId"), revision: integer(item, "revision") };
  }

  /**
   * ### replace
   *
   * Like the SQL `UPDATE … RETURNING`, a missing item yields `NaN` and is not created.
   *
   * @see {@link ItemRepository.replace}
   */
  async replace(item: ItemCiphertext, by: string, at: Date): Promise<number> {
    const current = await this.#docs.get(ITEMS, item.id);

    if (current === undefined) {
      return Number.NaN;
    }

    const revision = await this.#docs.nextSequence(REVISION_SEQUENCE);
    const fromVaultId = text(current, "vaultId");

    // Members who see only the old vault learn from this to drop their copy
    if (fromVaultId !== item.vaultId) {
      await this.#docs.set(ITEM_MOVES, `${item.id}:${String(revision)}`, {
        itemId: item.id,
        fromVaultId,
        revision,
      });
    }

    await this.#docs.update(ITEMS, item.id, {
      vaultId: item.vaultId,
      encItemKey: item.encryptedItemKey,
      encOverview: item.encryptedOverview,
      encDetails: item.encryptedDetails,
      updatedBy: by,
      updatedAt: at,
      revision,
    });

    return revision;
  }

  /**
   * ### markDeleted
   *
   * @see {@link ItemRepository.markDeleted}
   */
  async markDeleted(itemId: string, at: Date): Promise<void> {
    if ((await this.#docs.get(ITEMS, itemId)) === undefined) {
      return;
    }

    await this.#docs.update(ITEMS, itemId, {
      deletedAt: at,
      revision: await this.#docs.nextSequence(REVISION_SEQUENCE),
    });
  }

  /**
   * ### lockLiveInVault
   *
   * @see {@link ItemRepository.lockLiveInVault}
   */
  async lockLiveInVault(
    vaultId: string,
  ): Promise<Array<{ id: string; revision: number }>> {
    return (await this.#docs.find(ITEMS, [["vaultId", vaultId]]))
      .filter((item) => optionalDate(item.data, "deletedAt") === undefined)
      .map((item) => ({
        id: item.id,
        revision: integer(item.data, "revision"),
      }));
  }

  /**
   * ### reencrypt
   *
   * @see {@link ItemRepository.reencrypt}
   */
  async reencrypt(
    item: Omit<ItemCiphertext, "vaultId">,
    by: string,
    at: Date,
  ): Promise<void> {
    if ((await this.#docs.get(ITEMS, item.id)) === undefined) {
      return;
    }

    await this.#docs.update(ITEMS, item.id, {
      encItemKey: item.encryptedItemKey,
      encOverview: item.encryptedOverview,
      encDetails: item.encryptedDetails,
      updatedBy: by,
      updatedAt: at,
      revision: await this.#docs.nextSequence(REVISION_SEQUENCE),
    });
  }

  /**
   * ### changesForSync
   *
   * @see {@link ItemRepository.changesForSync}
   */
  async changesForSync(
    vaultIds: ReadonlyArray<string>,
    since: number,
    wholeVaultIds: ReadonlyArray<string>,
  ): Promise<Array<SyncedItem>> {
    const whole = new Set(wholeVaultIds);
    const visible = new Set(vaultIds);
    const incremental = [...visible].some((vaultId) => !whole.has(vaultId));
    // Vaults the caller just gained are sent whole; the rest only as far as they changed, read
    // through the revision index so a quiet poll reads no items at all
    const [wholeVaults, changed, moves] = await Promise.all([
      Promise.all(
        [...visible]
          .filter((vaultId) => whole.has(vaultId))
          .map((vaultId) => this.#docs.find(ITEMS, [["vaultId", vaultId]])),
      ),
      incremental
        ? this.#docs.findAbove(ITEMS, "revision", since)
        : Promise.resolve([]),
      this.#docs.findAbove(ITEM_MOVES, "revision", since),
    ]);
    const rows: Array<DocumentData> = wholeVaults
      .flat()
      .map((item) => item.data);

    for (const item of changed) {
      const vaultId = text(item.data, "vaultId");

      if (visible.has(vaultId) && !whole.has(vaultId)) {
        rows.push(item.data);
      }
    }

    const movedAway = await this.#movedAway(moves, visible);

    return [
      ...rows
        .sort(
          (left, right) =>
            integer(left, "revision") - integer(right, "revision"),
        )
        .map((row): SyncedItem => {
          const common = {
            id: text(row, "id"),
            vaultId: text(row, "vaultId"),
            revision: integer(row, "revision"),
          };

          return optionalDate(row, "deletedAt") === undefined
            ? {
                deleted: false,
                ...common,
                encryptedItemKey: bytes(row, "encItemKey"),
                encryptedOverview: bytes(row, "encOverview"),
                encryptedDetails: bytes(row, "encDetails"),
              }
            : { deleted: true, ...common };
        }),
      ...movedAway,
    ].sort((left, right) => left.revision - right.revision);
  }

  /**
   * ### #movedAway
   *
   * Items that moved out of a vault the caller sees into one they do not, as deletions in the
   * vault they left, so the caller drops its copy.
   *
   * @param moves Moves since the caller's revision
   * @param visible Vaults the caller sees
   * @returns One deletion per item, at its latest move
   */
  async #movedAway(
    moves: ReadonlyArray<{ data: DocumentData }>,
    visible: ReadonlySet<string>,
  ): Promise<Array<SyncedItem>> {
    const latest = new Map<string, { fromVaultId: string; revision: number }>();

    for (const { data } of moves) {
      const fromVaultId = text(data, "fromVaultId");
      const revision = integer(data, "revision");
      const itemId = text(data, "itemId");

      if (
        visible.has(fromVaultId) &&
        revision > (latest.get(itemId)?.revision ?? 0)
      ) {
        latest.set(itemId, { fromVaultId, revision });
      }
    }

    const current = await Promise.all(
      [...latest.keys()].map(async (itemId) => ({
        itemId,
        item: await this.#docs.get(ITEMS, itemId),
      })),
    );

    return current.flatMap(({ itemId, item }) => {
      const move = latest.get(itemId);

      return move === undefined ||
        (item !== undefined && visible.has(text(item, "vaultId")))
        ? []
        : [
            {
              deleted: true,
              id: itemId,
              vaultId: move.fromVaultId,
              revision: move.revision,
            },
          ];
    });
  }
}
