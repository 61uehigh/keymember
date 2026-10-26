/**
 * ### FieldValue
 *
 * A value a stored document can hold. Dates and bytes come back as `Date` and `Uint8Array`
 * whichever backend stored them.
 */
export type FieldValue =
  | string
  | number
  | boolean
  | null
  | Date
  | Uint8Array
  | ReadonlyArray<FieldValue>;

/**
 * ### DocumentData
 *
 * The fields of one document. Absent values are written as `null`, never left out, so that
 * filters on them match. Documents written before a field existed lack it, so readers treat a
 * missing field as `null`, and queries never filter on `null` in a field added after launch.
 */
export type DocumentData = Readonly<Record<string, FieldValue>>;

/**
 * ### StoredDocument
 *
 * A document with its id, as a query returns it.
 */
export interface StoredDocument {
  /**
   * ### id
   *
   * Document id, unique within its collection.
   */
  readonly id: string;

  /**
   * ### data
   *
   * Document fields.
   */
  readonly data: DocumentData;
}

/**
 * ### Filter
 *
 * An equality condition on one field. Queries take equality filters only, so they never need
 * a composite index; repositories apply ranges and ordering to the (small) result in memory.
 */
export type Filter = readonly [field: string, value: FieldValue];

/**
 * ### Documents
 *
 * The document operations the Firestore repositories are written against. Inside a transaction,
 * reads see the transaction's own earlier writes and writes are held back until it commits;
 * outside one, every write takes effect at once.
 */
export interface Documents {
  /**
   * ### get
   *
   * Reads one document.
   *
   * @param collection Collection name
   * @param id Document id
   * @returns Its fields, or `undefined` when there is no such document
   */
  get(collection: string, id: string): Promise<DocumentData | undefined>;

  /**
   * ### find
   *
   * Reads every document whose fields equal all the given values.
   *
   * @param collection Collection name
   * @param filters Field values to match; none matches the whole collection
   * @returns The matching documents, in no particular order
   */
  find(
    collection: string,
    filters: ReadonlyArray<Filter>,
  ): Promise<Array<StoredDocument>>;

  /**
   * ### findAbove
   *
   * Reads every document whose number field is greater than `value`. Uses Firestore's automatic
   * single-field index, so it reads only the matching documents, which keeps polling cheap.
   *
   * @param collection Collection name
   * @param field Number field
   * @param value Exclusive lower bound
   * @returns The matching documents, in no particular order
   */
  findAbove(
    collection: string,
    field: string,
    value: number,
  ): Promise<Array<StoredDocument>>;

  /**
   * ### findBefore
   *
   * Reads up to `limit` documents whose field is earlier than `bound`, oldest first, through
   * Firestore's automatic single-field index. For removing expired records a page at a time.
   *
   * @param collection Collection name
   * @param field Date or number field
   * @param bound Exclusive upper bound
   * @param limit Most documents to return
   * @returns The matching documents
   */
  findBefore(
    collection: string,
    field: string,
    bound: Date | number,
    limit: number,
  ): Promise<Array<StoredDocument>>;

  /**
   * ### findLatest
   *
   * Reads the `limit` documents with the greatest values of a field, greatest first, through
   * Firestore's automatic single-field index.
   *
   * @param collection Collection name
   * @param field Date or number field to order by
   * @param limit Most documents to return
   * @returns The documents
   */
  findLatest(
    collection: string,
    field: string,
    limit: number,
  ): Promise<Array<StoredDocument>>;

  /**
   * ### create
   *
   * Creates a document only when none exists with that id.
   *
   * @param collection Collection name
   * @param id Document id
   * @param data Every field of the document
   * @returns Whether it was created; `false` when the id was taken
   */
  create(collection: string, id: string, data: DocumentData): Promise<boolean>;

  /**
   * ### atomic
   *
   * Runs `work` as one unit: inside a transaction, as part of it; outside one, in a transaction
   * of its own. For conditional writes ("use once", "only if newer") that must not be beaten by
   * a concurrent request. `work` may run more than once and must have no other effects.
   *
   * @param work Reads and writes to run together
   * @returns Whatever `work` resolves to
   */
  atomic<T>(work: (documents: Documents) => Promise<T>): Promise<T>;

  /**
   * ### set
   *
   * Creates or replaces a document.
   *
   * @param collection Collection name
   * @param id Document id
   * @param data Every field of the document
   */
  set(collection: string, id: string, data: DocumentData): Promise<void>;

  /**
   * ### update
   *
   * Changes some fields of a document, like SQL `UPDATE`: nothing happens when it does not exist.
   *
   * @param collection Collection name
   * @param id Document id
   * @param patch Fields to change
   */
  update(collection: string, id: string, patch: DocumentData): Promise<void>;

  /**
   * ### delete
   *
   * Removes a document; nothing happens when it does not exist.
   *
   * @param collection Collection name
   * @param id Document id
   */
  delete(collection: string, id: string): Promise<void>;

  /**
   * ### nextSequence
   *
   * Takes the next number of a named counter, like an SQL sequence. Inside a transaction the
   * counter stays locked until commit, so numbers are handed out in commit order and a rolled
   * back transaction gives its numbers back.
   *
   * @param name Counter name
   * @returns The next number, starting at 1
   */
  nextSequence(name: string): Promise<number>;

  /**
   * ### currentSequence
   *
   * Reads a named counter without advancing it.
   *
   * @param name Counter name
   * @returns The last number handed out, or 0
   */
  currentSequence(name: string): Promise<number>;
}

/**
 * ### matches
 *
 * Whether a document's fields equal every filter's value, as Firestore compares them.
 *
 * @param data Document fields
 * @param filters Equality filters
 * @returns Whether all filters hold
 */
export function matches(
  data: DocumentData,
  filters: ReadonlyArray<Filter>,
): boolean {
  return filters.every(
    ([field, value]) => field in data && sameValue(data[field] ?? null, value),
  );
}

/**
 * ### sameValue
 *
 * Deep equality for stored values: dates by instant and bytes by content.
 *
 * @param left One value
 * @param right The other value
 * @returns Whether they are equal
 */
function sameValue(left: FieldValue, right: FieldValue): boolean {
  if (left instanceof Date || right instanceof Date) {
    return (
      left instanceof Date &&
      right instanceof Date &&
      left.getTime() === right.getTime()
    );
  }

  if (left instanceof Uint8Array || right instanceof Uint8Array) {
    return (
      left instanceof Uint8Array &&
      right instanceof Uint8Array &&
      left.length === right.length &&
      left.every((byte, index) => byte === right[index])
    );
  }

  if (Array.isArray(left) || Array.isArray(right)) {
    return (
      Array.isArray(left) &&
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((item: FieldValue, index) =>
        sameValue(item, (right as ReadonlyArray<FieldValue>)[index] ?? null),
      )
    );
  }

  return left === right;
}
