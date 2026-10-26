import { PGlite } from "@electric-sql/pglite";
import pg from "pg";

import { DuplicateKeyError } from "../repositories/DuplicateKeyError.js";
import { SCHEMA_MIGRATIONS } from "./schema.js";

/**
 * ### Queryable
 *
 * Minimal SQL surface shared by a connection and a transaction.
 * Parameters are always bound (`$1`, `$2`, …); SQL text is never built from input.
 */
export interface Queryable {
  /**
   * ### query
   *
   * Runs one statement and returns its rows. Row shape is asserted by the caller.
   *
   * @param sql Statement with positional placeholders
   * @param params Values bound to the placeholders
   * @returns Every row the statement produced, empty for statements without results
   */
  query<Row>(sql: string, params?: ReadonlyArray<unknown>): Promise<Array<Row>>;
}

/**
 * ### Database
 *
 * A PostgreSQL connection that can also run work atomically.
 * Implemented by {@link PgDatabase} for production and {@link PgliteDatabase} for tests and local runs.
 */
export interface Database extends Queryable {
  /**
   * ### transaction
   *
   * Runs `work` in one transaction, committing when it resolves and rolling back when it throws.
   *
   * @param work Work to run against the transaction
   * @returns Whatever `work` resolves to
   */
  transaction<T>(work: (tx: Queryable) => Promise<T>): Promise<T>;

  /**
   * ### snapshot
   *
   * Runs read-only `work` in one `REPEATABLE READ READ ONLY` transaction, so every query sees
   * the same committed state and nothing is locked.
   *
   * @param work Reads to run
   * @returns Whatever `work` resolves to
   */
  snapshot<T>(work: (tx: Queryable) => Promise<T>): Promise<T>;

  /**
   * ### close
   *
   * Releases every connection. The instance must not be used afterwards.
   */
  close(): Promise<void>;
}

/**
 * ### PgDatabase
 *
 * {@link Database} backed by a `pg` connection pool.
 */
export class PgDatabase implements Database {
  readonly #pool: pg.Pool;

  /**
   * ### constructor
   *
   * Opens a pool lazily; no connection is made until the first query.
   *
   * @param connectionString PostgreSQL connection URL
   */
  constructor(connectionString: string) {
    this.#pool = new pg.Pool({ connectionString });
  }

  /**
   * ### query
   *
   * @see {@link Queryable.query}
   */
  async query<Row>(
    sql: string,
    params: ReadonlyArray<unknown> = [],
  ): Promise<Array<Row>> {
    try {
      // pg returns untyped rows; the caller's SQL determines the shape
      return (await this.#pool.query(sql, [...params])).rows as Array<Row>;
    } catch (error) {
      throw storeError(error);
    }
  }

  /**
   * ### transaction
   *
   * Retries the whole of `work` when PostgreSQL aborts it for a serialization failure or a
   * deadlock, as the {@link Database.transaction} contract allows.
   *
   * @see {@link Database.transaction}
   */
  async transaction<T>(work: (tx: Queryable) => Promise<T>): Promise<T> {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this.#run("BEGIN", work);
      } catch (error) {
        if (attempt >= TRANSACTION_ATTEMPTS || !isTransient(error)) {
          throw error;
        }
      }
    }
  }

  /**
   * ### snapshot
   *
   * @see {@link Database.snapshot}
   */
  snapshot<T>(work: (tx: Queryable) => Promise<T>): Promise<T> {
    return this.#run("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY", work);
  }

  /**
   * ### #run
   *
   * Runs `work` on one pooled connection between `begin` and `COMMIT`, rolling back when it
   * throws. A connection whose rollback fails is discarded rather than reused.
   *
   * @param begin Statement that opens the transaction
   * @param work Work to run against the transaction
   * @returns Whatever `work` resolves to
   */
  async #run<T>(
    begin: string,
    work: (tx: Queryable) => Promise<T>,
  ): Promise<T> {
    const client = await this.#pool.connect();
    let broken: Error | undefined;

    try {
      await client.query(begin);
      const result = await work({
        query: async <Row>(
          sql: string,
          params: ReadonlyArray<unknown> = [],
        ) => {
          try {
            // pg returns untyped rows; the caller's SQL determines the shape
            return (await client.query(sql, [...params])).rows as Array<Row>;
          } catch (error) {
            throw storeError(error);
          }
        },
      });

      await client.query("COMMIT");

      return result;
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch (rollbackError) {
        broken =
          rollbackError instanceof Error
            ? rollbackError
            : new Error("ROLLBACK failed");
      }

      // The original failure is what the caller needs, even when the rollback failed too
      throw storeError(error);
    } finally {
      client.release(broken);
    }
  }

  /**
   * ### close
   *
   * @see {@link Database.close}
   */
  async close(): Promise<void> {
    await this.#pool.end();
  }
}

/**
 * ### PgliteDatabase
 *
 * {@link Database} backed by an in-process PGlite instance: in memory when no directory
 * is given, otherwise persisted to that directory. Used by tests, local development, and the
 * self-hosted Docker image, where the directory is the data volume. One process must own the
 * directory; stop the server before copying it (deploy/backup.sh does).
 */
export class PgliteDatabase implements Database {
  readonly #db: PGlite;

  /**
   * ### constructor
   *
   * @param source Directory to persist data in, or a {@link PgliteDatabase.dump} to start an
   * in-memory database from; omit for an empty in-memory database
   */
  constructor(source?: string | Blob) {
    this.#db =
      source instanceof Blob
        ? new PGlite({ loadDataDir: source })
        : new PGlite(source);
  }

  /**
   * ### dump
   *
   * Copies the whole database, so tests can set up once and start every test from the copy.
   *
   * @returns The data directory as a tarball
   */
  async dump(): Promise<Blob> {
    return this.#db.dumpDataDir("none");
  }

  /**
   * ### query
   *
   * @see {@link Queryable.query}
   */
  async query<Row>(
    sql: string,
    params: ReadonlyArray<unknown> = [],
  ): Promise<Array<Row>> {
    try {
      return (await this.#db.query<Row>(sql, [...params])).rows;
    } catch (error) {
      throw storeError(error);
    }
  }

  /**
   * ### transaction
   *
   * PGlite runs one statement at a time in one process, so transactions never conflict and
   * need no retry.
   *
   * @see {@link Database.transaction}
   */
  async transaction<T>(work: (tx: Queryable) => Promise<T>): Promise<T> {
    return this.#db.transaction(async (tx) =>
      work({
        query: async <Row>(
          sql: string,
          params: ReadonlyArray<unknown> = [],
        ) => {
          try {
            return (await tx.query<Row>(sql, [...params])).rows;
          } catch (error) {
            throw storeError(error);
          }
        },
      }),
    );
  }

  /**
   * ### snapshot
   *
   * @see {@link Database.snapshot}
   */
  snapshot<T>(work: (tx: Queryable) => Promise<T>): Promise<T> {
    return this.transaction(async (tx) => {
      await tx.query(
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",
      );

      return work(tx);
    });
  }

  /**
   * ### close
   *
   * @see {@link Database.close}
   */
  async close(): Promise<void> {
    await this.#db.close();
  }
}

/**
 * ### MIGRATION_LOCK
 *
 * Advisory lock key that serialises migrations when several servers start at once.
 */
const MIGRATION_LOCK = 7312;

/**
 * ### migrate
 *
 * Applies every migration in {@link SCHEMA_MIGRATIONS} that has not run yet, each in its own
 * transaction. Each takes a transaction-level advisory lock and checks again whether it already
 * ran, so servers starting together apply each migration once instead of crashing on it.
 *
 * @param db Database to migrate
 * @param options `through`: stop after this migration id, for upgrade tests
 */
export async function migrate(
  db: Database,
  options: { through?: number } = {},
): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.query("SELECT pg_advisory_xact_lock($1)", [MIGRATION_LOCK]);
    await tx.query(
      "CREATE TABLE IF NOT EXISTS schema_migrations (id integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())",
    );
  });

  for (const migration of SCHEMA_MIGRATIONS) {
    if (options.through !== undefined && migration.id > options.through) {
      break;
    }

    await db.transaction(async (tx) => {
      await tx.query("SELECT pg_advisory_xact_lock($1)", [MIGRATION_LOCK]);

      const [applied] = await tx.query(
        "SELECT 1 FROM schema_migrations WHERE id = $1",
        [migration.id],
      );

      if (applied !== undefined) {
        return;
      }

      // Comment lines go first, so a semicolon in a comment cannot split a statement
      for (const statement of migration.sql
        .split("\n")
        .filter((line) => !line.trim().startsWith("--"))
        .join("\n")
        .split(";")
        .map((part) => part.trim())
        .filter((part) => part.length > 0)) {
        await tx.query(statement);
      }

      await tx.query("INSERT INTO schema_migrations (id) VALUES ($1)", [
        migration.id,
      ]);
    });
  }
}

/**
 * ### TRANSACTION_ATTEMPTS
 *
 * How many times a transaction runs before a serialization failure or deadlock is reported.
 */
const TRANSACTION_ATTEMPTS = 3;

/**
 * ### errorCode
 *
 * The SQLSTATE of an error from `pg` or PGlite.
 *
 * @param error Error thrown by a query
 * @returns Its SQLSTATE, if it has one
 */
function errorCode(error: unknown): string | undefined {
  const code =
    typeof error === "object" && error !== null && "code" in error
      ? error.code
      : undefined;

  return typeof code === "string" ? code : undefined;
}

/**
 * ### isTransient
 *
 * Whether PostgreSQL aborted a transaction that would succeed if run again: a serialization
 * failure (40001) or a deadlock (40P01).
 *
 * @param error Error the transaction failed with
 * @returns Whether to retry
 */
function isTransient(error: unknown): boolean {
  const code = errorCode(error);

  return code === "40001" || code === "40P01";
}

/**
 * ### storeError
 *
 * Turns a unique-constraint violation (23505) into the store-neutral {@link DuplicateKeyError};
 * other errors pass through unchanged.
 *
 * @param error Error thrown by a query
 * @returns The error to throw
 */
function storeError(error: unknown): unknown {
  if (errorCode(error) !== "23505") {
    return error;
  }

  const constraint =
    typeof error === "object" && error !== null && "constraint" in error
      ? String(error.constraint)
      : "A unique key";

  return new DuplicateKeyError(constraint, { cause: error });
}
