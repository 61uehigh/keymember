import type { ChangeFeedRepository } from "../repositories/ChangeFeedRepository.js";
import { REVISION_SEQUENCE } from "./collections.js";
import type { Documents } from "./Documents.js";

/**
 * ### FirestoreChangeFeedRepository
 *
 * {@link ChangeFeedRepository} on Firestore. The {@link REVISION_SEQUENCE} counter stands in for
 * both the sequence and the advisory lock: a transaction that reads it holds it until commit.
 */
export class FirestoreChangeFeedRepository implements ChangeFeedRepository {
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
   * ### lock
   *
   * Reads the revision counter, so concurrent writers conflict on it and commit one at a time,
   * in revision order.
   *
   * @see {@link ChangeFeedRepository.lock}
   */
  async lock(): Promise<void> {
    await this.#docs.currentSequence(REVISION_SEQUENCE);
  }

  /**
   * ### latestRevision
   *
   * The counter's value. It can exceed every stored revision (vault and deleted-grant changes
   * also draw from it), but every revision up to it is committed, which is all sync relies on.
   *
   * @see {@link ChangeFeedRepository.latestRevision}
   */
  latestRevision(): Promise<number> {
    return this.#docs.currentSequence(REVISION_SEQUENCE);
  }
}
