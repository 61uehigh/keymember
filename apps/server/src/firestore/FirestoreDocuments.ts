import { Timestamp } from "@google-cloud/firestore";
import type {
  DocumentSnapshot,
  Firestore,
  Query,
  Transaction,
} from "@google-cloud/firestore";

import { matches } from "./Documents.js";
import type {
  DocumentData,
  Documents,
  FieldValue,
  Filter,
  StoredDocument,
} from "./Documents.js";

/**
 * ### SEQUENCES
 *
 * Collection holding one counter document per sequence name.
 */
const SEQUENCES = "sequences";

/**
 * ### NOT_FOUND
 *
 * gRPC status Firestore reports when `update` targets a missing document.
 */
const NOT_FOUND = 5;

/**
 * ### ALREADY_EXISTS
 *
 * gRPC status Firestore reports when `create` targets an existing document.
 */
const ALREADY_EXISTS = 6;

/**
 * ### DirectDocuments
 *
 * {@link Documents} outside a transaction: each call is one Firestore request.
 */
export class DirectDocuments implements Documents {
  readonly #db: Firestore;

  /**
   * ### constructor
   *
   * @param db Firestore client
   */
  constructor(db: Firestore) {
    this.#db = db;
  }

  /**
   * ### get
   *
   * @see {@link Documents.get}
   */
  async get(collection: string, id: string): Promise<DocumentData | undefined> {
    return decodeSnapshot(await this.#db.collection(collection).doc(id).get());
  }

  /**
   * ### find
   *
   * @see {@link Documents.find}
   */
  async find(
    collection: string,
    filters: ReadonlyArray<Filter>,
  ): Promise<Array<StoredDocument>> {
    return decodeQuery(await query(this.#db, collection, filters).get());
  }

  /**
   * ### findAbove
   *
   * @see {@link Documents.findAbove}
   */
  async findAbove(
    collection: string,
    field: string,
    value: number,
  ): Promise<Array<StoredDocument>> {
    return decodeQuery(
      await this.#db.collection(collection).where(field, ">", value).get(),
    );
  }

  /**
   * ### findBefore
   *
   * @see {@link Documents.findBefore}
   */
  async findBefore(
    collection: string,
    field: string,
    bound: Date | number,
    limit: number,
  ): Promise<Array<StoredDocument>> {
    return decodeQuery(
      await before(this.#db, collection, field, bound, limit).get(),
    );
  }

  /**
   * ### findLatest
   *
   * @see {@link Documents.findLatest}
   */
  async findLatest(
    collection: string,
    field: string,
    limit: number,
  ): Promise<Array<StoredDocument>> {
    return decodeQuery(await latest(this.#db, collection, field, limit).get());
  }

  /**
   * ### create
   *
   * @see {@link Documents.create}
   */
  async create(
    collection: string,
    id: string,
    data: DocumentData,
  ): Promise<boolean> {
    try {
      await this.#db.collection(collection).doc(id).create(data);

      return true;
    } catch (error) {
      if ((error as { code?: unknown }).code === ALREADY_EXISTS) {
        return false;
      }

      throw error;
    }
  }

  /**
   * ### atomic
   *
   * @see {@link Documents.atomic}
   */
  atomic<T>(work: (documents: Documents) => Promise<T>): Promise<T> {
    return runDocumentTransaction(this.#db, work);
  }

  /**
   * ### set
   *
   * @see {@link Documents.set}
   */
  async set(collection: string, id: string, data: DocumentData): Promise<void> {
    await this.#db.collection(collection).doc(id).set(data);
  }

  /**
   * ### update
   *
   * @see {@link Documents.update}
   */
  async update(
    collection: string,
    id: string,
    patch: DocumentData,
  ): Promise<void> {
    try {
      await this.#db.collection(collection).doc(id).update(patch);
    } catch (error) {
      // A missing document is not an error for an SQL-style update
      if ((error as { code?: unknown }).code !== NOT_FOUND) {
        throw error;
      }
    }
  }

  /**
   * ### delete
   *
   * @see {@link Documents.delete}
   */
  async delete(collection: string, id: string): Promise<void> {
    await this.#db.collection(collection).doc(id).delete();
  }

  /**
   * ### nextSequence
   *
   * Runs its own small transaction, since there is none to join.
   *
   * @see {@link Documents.nextSequence}
   */
  nextSequence(name: string): Promise<number> {
    return runDocumentTransaction(this.#db, (documents) =>
      documents.nextSequence(name),
    );
  }

  /**
   * ### currentSequence
   *
   * @see {@link Documents.currentSequence}
   */
  async currentSequence(name: string): Promise<number> {
    return sequenceValue(await this.get(SEQUENCES, name));
  }
}

/**
 * ### TransactionDocuments
 *
 * {@link Documents} inside a Firestore transaction. Firestore refuses reads after the first
 * write, so writes are kept here and sent by {@link TransactionDocuments.commit}; reads
 * overlay them, so the transaction still reads its own writes.
 */
export class TransactionDocuments implements Documents {
  readonly #db: Firestore;
  readonly #tx: Transaction;

  /**
   * ### #pending
   *
   * Writes not yet sent, by `collection/id`: the new fields, or `null` for a deletion.
   */
  readonly #pending = new Map<string, DocumentData | null>();

  /**
   * ### constructor
   *
   * @param db Firestore client
   * @param tx Transaction to read and write in
   */
  constructor(db: Firestore, tx: Transaction) {
    this.#db = db;
    this.#tx = tx;
  }

  /**
   * ### get
   *
   * @see {@link Documents.get}
   */
  async get(collection: string, id: string): Promise<DocumentData | undefined> {
    const pending = this.#pending.get(`${collection}/${id}`);

    if (pending !== undefined) {
      return pending ?? undefined;
    }

    return decodeSnapshot(
      await this.#tx.get(this.#db.collection(collection).doc(id)),
    );
  }

  /**
   * ### find
   *
   * @see {@link Documents.find}
   */
  async find(
    collection: string,
    filters: ReadonlyArray<Filter>,
  ): Promise<Array<StoredDocument>> {
    return this.#overlay(
      collection,
      decodeQuery(await this.#tx.get(query(this.#db, collection, filters))),
      (data) => matches(data, filters),
    );
  }

  /**
   * ### findAbove
   *
   * @see {@link Documents.findAbove}
   */
  async findAbove(
    collection: string,
    field: string,
    value: number,
  ): Promise<Array<StoredDocument>> {
    return this.#overlay(
      collection,
      decodeQuery(
        await this.#tx.get(
          this.#db.collection(collection).where(field, ">", value),
        ),
      ),
      (data) => {
        const current = data[field];

        return typeof current === "number" && current > value;
      },
    );
  }

  /**
   * ### #overlay
   *
   * Lays this transaction's pending writes over query results.
   *
   * @param collection Collection the query read
   * @param stored What Firestore returned
   * @param matching Whether a pending document satisfies the query
   * @returns The documents the query would return after the pending writes
   */
  #overlay(
    collection: string,
    stored: ReadonlyArray<StoredDocument>,
    matching: (data: DocumentData) => boolean,
  ): Array<StoredDocument> {
    const found = new Map(
      stored.map((document) => [document.id, document.data]),
    );

    for (const [path, data] of this.#pending) {
      const [pendingCollection, id] = splitPath(path);

      if (pendingCollection !== collection) {
        continue;
      }

      if (data !== null && matching(data)) {
        found.set(id, data);
      } else {
        found.delete(id);
      }
    }

    return [...found].map(([id, data]) => ({ id, data }));
  }

  /**
   * ### findBefore
   *
   * @see {@link Documents.findBefore}
   */
  async findBefore(
    collection: string,
    field: string,
    bound: Date | number,
    limit: number,
  ): Promise<Array<StoredDocument>> {
    return this.#overlay(
      collection,
      decodeQuery(
        await this.#tx.get(before(this.#db, collection, field, bound, limit)),
      ),
      (data) => {
        const current = data[field];

        return (
          (current instanceof Date || typeof current === "number") &&
          Number(current) < Number(bound)
        );
      },
    ).slice(0, limit);
  }

  /**
   * ### findLatest
   *
   * @see {@link Documents.findLatest}
   */
  async findLatest(
    collection: string,
    field: string,
    limit: number,
  ): Promise<Array<StoredDocument>> {
    return this.#overlay(
      collection,
      decodeQuery(
        await this.#tx.get(latest(this.#db, collection, field, limit)),
      ),
      (data) => data[field] instanceof Date || typeof data[field] === "number",
    )
      .sort(
        (left, right) =>
          Number(right.data[field] ?? 0) - Number(left.data[field] ?? 0),
      )
      .slice(0, limit);
  }

  /**
   * ### create
   *
   * @see {@link Documents.create}
   */
  async create(
    collection: string,
    id: string,
    data: DocumentData,
  ): Promise<boolean> {
    if ((await this.get(collection, id)) !== undefined) {
      return false;
    }

    this.#pending.set(`${collection}/${id}`, data);

    return true;
  }

  /**
   * ### atomic
   *
   * Already inside a transaction, so `work` simply joins it.
   *
   * @see {@link Documents.atomic}
   */
  atomic<T>(work: (documents: Documents) => Promise<T>): Promise<T> {
    return work(this);
  }

  /**
   * ### set
   *
   * @see {@link Documents.set}
   */
  set(collection: string, id: string, data: DocumentData): Promise<void> {
    this.#pending.set(`${collection}/${id}`, data);

    return Promise.resolve();
  }

  /**
   * ### update
   *
   * @see {@link Documents.update}
   */
  async update(
    collection: string,
    id: string,
    patch: DocumentData,
  ): Promise<void> {
    const current = await this.get(collection, id);

    if (current !== undefined) {
      this.#pending.set(`${collection}/${id}`, { ...current, ...patch });
    }
  }

  /**
   * ### delete
   *
   * @see {@link Documents.delete}
   */
  delete(collection: string, id: string): Promise<void> {
    this.#pending.set(`${collection}/${id}`, null);

    return Promise.resolve();
  }

  /**
   * ### nextSequence
   *
   * @see {@link Documents.nextSequence}
   */
  async nextSequence(name: string): Promise<number> {
    const next = (await this.currentSequence(name)) + 1;

    await this.set(SEQUENCES, name, { value: next });

    return next;
  }

  /**
   * ### currentSequence
   *
   * @see {@link Documents.currentSequence}
   */
  async currentSequence(name: string): Promise<number> {
    return sequenceValue(await this.get(SEQUENCES, name));
  }

  /**
   * ### commit
   *
   * Hands the held writes to the transaction. Call once, after the last read; Firestore sends
   * them when the transaction function returns.
   */
  commit(): void {
    for (const [path, data] of this.#pending) {
      const [collection, id] = splitPath(path);
      const ref = this.#db.collection(collection).doc(id);

      if (data === null) {
        this.#tx.delete(ref);
      } else {
        this.#tx.set(ref, data);
      }
    }
  }
}

/**
 * ### sequenceValue
 *
 * Reads a counter document.
 *
 * @param counter Counter document, if it exists yet
 * @returns Its value, or 0 before the first number
 */
function sequenceValue(counter: DocumentData | undefined): number {
  const value = counter?.value ?? 0;

  if (typeof value !== "number") {
    throw new Error("Sequence counter is not a number");
  }

  return value;
}

/**
 * ### before
 *
 * Builds a query for documents whose field is earlier than a bound, oldest first.
 *
 * @param db Firestore client
 * @param collection Collection name
 * @param field Date or number field
 * @param bound Exclusive upper bound
 * @param limit Most documents to return
 * @returns The query
 */
function before(
  db: Firestore,
  collection: string,
  field: string,
  bound: Date | number,
  limit: number,
): Query {
  return db
    .collection(collection)
    .where(field, "<", bound)
    .orderBy(field)
    .limit(limit);
}

/**
 * ### latest
 *
 * Builds a query for the documents with the greatest values of a field. Firestore breaks ties by
 * document id in the same direction, so the order is stable without a composite index.
 *
 * @param db Firestore client
 * @param collection Collection name
 * @param field Date or number field
 * @param limit Most documents to return
 * @returns The query
 */
function latest(
  db: Firestore,
  collection: string,
  field: string,
  limit: number,
): Query {
  return db.collection(collection).orderBy(field, "desc").limit(limit);
}

/**
 * ### query
 *
 * Builds an equality query.
 *
 * @param db Firestore client
 * @param collection Collection name
 * @param filters Equality filters
 * @returns The query
 */
function query(
  db: Firestore,
  collection: string,
  filters: ReadonlyArray<Filter>,
): Query {
  return filters.reduce<Query>(
    (built, [field, value]) => built.where(field, "==", value),
    db.collection(collection),
  );
}

/**
 * ### splitPath
 *
 * Splits a `collection/id` key. Collection names never contain `/`; ids may.
 *
 * @param path Key of a pending write
 * @returns Collection and id
 */
function splitPath(path: string): [string, string] {
  const slash = path.indexOf("/");

  return [path.slice(0, slash), path.slice(slash + 1)];
}

/**
 * ### decodeSnapshot
 *
 * Converts a document snapshot to plain fields.
 *
 * @param snapshot Snapshot from Firestore
 * @returns Its fields, or `undefined` when the document does not exist
 */
function decodeSnapshot(snapshot: DocumentSnapshot): DocumentData | undefined {
  const data = snapshot.data();

  return data === undefined ? undefined : decodeFields(data);
}

/**
 * ### decodeQuery
 *
 * Converts query results to plain documents.
 *
 * @param snapshot Query results from Firestore
 * @returns The documents
 */
function decodeQuery(snapshot: {
  docs: ReadonlyArray<{ id: string; data(): Record<string, unknown> }>;
}): Array<StoredDocument> {
  return snapshot.docs.map((document) => ({
    id: document.id,
    data: decodeFields(document.data()),
  }));
}

/**
 * ### decodeFields
 *
 * Converts Firestore's field types to the ones repositories use.
 *
 * @param data Fields as Firestore returns them
 * @returns The same fields with dates and bytes converted
 */
function decodeFields(data: Record<string, unknown>): DocumentData {
  return Object.fromEntries(
    Object.entries(data).map(([field, value]) => [field, decodeValue(value)]),
  );
}

/**
 * ### decodeValue
 *
 * Converts one Firestore value: a `Timestamp` becomes a `Date` and a `Buffer` a plain `Uint8Array`.
 *
 * @param value Value as Firestore returns it
 * @returns The converted value
 */
function decodeValue(value: unknown): FieldValue {
  if (value instanceof Timestamp) {
    return value.toDate();
  }

  if (value instanceof Uint8Array) {
    return new Uint8Array(value);
  }

  if (Array.isArray(value)) {
    return value.map(decodeValue);
  }

  // Repositories only store the field types FieldValue allows
  return value as FieldValue;
}

/**
 * ### runDocumentTransaction
 *
 * Runs `work` in a Firestore transaction, sending its writes when it resolves. Firestore runs
 * `work` again when the transaction conflicts with another one.
 *
 * @param db Firestore client
 * @param work Work to run against the transaction's documents
 * @returns Whatever `work` resolves to
 */
export function runDocumentTransaction<T>(
  db: Firestore,
  work: (documents: Documents) => Promise<T>,
): Promise<T> {
  return db.runTransaction(async (tx) => {
    const documents = new TransactionDocuments(db, tx);
    const result = await work(documents);

    documents.commit();

    return result;
  });
}

/**
 * ### runDocumentSnapshot
 *
 * Runs read-only `work` in a read-only Firestore transaction: every read sees one consistent
 * moment, and nothing is locked, so writers are not held up by readers such as sync.
 *
 * @param db Firestore client
 * @param work Reads to run
 * @returns Whatever `work` resolves to
 */
export function runDocumentSnapshot<T>(
  db: Firestore,
  work: (documents: Documents) => Promise<T>,
): Promise<T> {
  return db.runTransaction((tx) => work(new TransactionDocuments(db, tx)), {
    readOnly: true,
  });
}
