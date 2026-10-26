/**
 * ### DuplicateKeyError
 *
 * A write would create a second record with a key that must be unique: an id a client chose,
 * an email, an account id, a provider subject, or a second open recovery for one member. Both
 * stores raise it (PostgreSQL from its constraints, Firestore from sentinel documents), so a
 * request that loses such a race gets a 409 rather than overwriting data or a 500.
 */
export class DuplicateKeyError extends Error {
  /**
   * ### constructor
   *
   * @param what The record and key that already exist
   * @param options The store's own error, when there is one
   */
  constructor(what: string, options?: { cause?: unknown }) {
    super(`${what} already exists`, options);
    this.name = "DuplicateKeyError";
  }
}
