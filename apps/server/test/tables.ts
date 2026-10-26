import { Timestamp } from "@google-cloud/firestore";
import type { Firestore, Query } from "@google-cloud/firestore";

import type { Database } from "@keymember/server";

/**
 * ### NEXT_REVISION
 *
 * Column value for {@link Tables.insert} that takes the next change revision, like the
 * `revision` column's SQL default.
 */
export const NEXT_REVISION = Symbol("next revision");

/**
 * ### Row
 *
 * A table row keyed by SQL column name. `jsonb` columns hold parsed values.
 */
export type Row = Record<string, unknown>;

/**
 * ### Tables
 *
 * Raw access to the server's stored rows, for tests that check what the server keeps or play
 * a hostile server. Rows use SQL table and column names whichever store is behind them.
 */
export interface Tables {
  /**
   * ### select
   *
   * Reads the rows whose columns equal `where`.
   *
   * @param table SQL table name
   * @param where Column values to match; omit for every row
   * @returns The rows, in no particular order
   */
  select(table: string, where?: Row): Promise<Array<Row>>;

  /**
   * ### update
   *
   * Changes columns of the rows whose columns equal `where`.
   *
   * @param table SQL table name
   * @param where Column values to match
   * @param set Column values to write
   */
  update(table: string, where: Row, set: Row): Promise<void>;

  /**
   * ### insert
   *
   * Adds a row. Give every column; use {@link NEXT_REVISION} for `revision`.
   *
   * @param table SQL table name
   * @param row Every column of the row
   */
  insert(table: string, row: Row): Promise<void>;
}

/**
 * ### JSON_COLUMNS
 *
 * Columns stored as `jsonb` in SQL and as JSON strings in Firestore.
 */
const JSON_COLUMNS = new Set([
  "kdf",
  "certificate",
  "detail",
  "vault_snapshot",
  "group_snapshot",
  "statement",
  "trusted_roots",
]);

/**
 * ### sqlTables
 *
 * {@link Tables} on PostgreSQL or PGlite. Table and column names come from test code only.
 *
 * @param db Database the server uses
 * @returns Raw row access
 */
export function sqlTables(db: Database): Tables {
  const conditions = (where: Row, offset: number): [string, Array<unknown>] => {
    const columns = Object.keys(where);

    return [
      columns.length === 0
        ? "TRUE"
        : columns
            .map((column, index) =>
              where[column] === null
                ? `${column} IS NULL`
                : `${column} = $${String(offset + index + 1)}`,
            )
            .join(" AND "),
      columns.map((column) => where[column]).filter((value) => value !== null),
    ];
  };

  return {
    select: (table, where = {}) => {
      const [sql, params] = conditions(where, 0);

      return db.query<Row>(`SELECT * FROM ${table} WHERE ${sql}`, params);
    },
    update: async (table, where, set) => {
      const columns = Object.keys(set);
      const [sql, params] = conditions(where, columns.length);

      await db.query(
        `UPDATE ${table} SET ${columns
          .map((column, index) => `${column} = $${String(index + 1)}`)
          .join(", ")} WHERE ${sql}`,
        [...columns.map((column) => encodeSql(column, set[column])), ...params],
      );
    },
    insert: async (table, row) => {
      const columns = Object.keys(row);
      const values: Array<unknown> = [];
      const placeholders = columns.map((column) => {
        if (row[column] === NEXT_REVISION) {
          return "nextval('change_seq')";
        }

        values.push(encodeSql(column, row[column]));

        return `$${String(values.length)}`;
      });

      await db.query(
        `INSERT INTO ${table} (${columns.join(", ")}) VALUES (${placeholders.join(", ")})`,
        values,
      );
    },
  };
}

/**
 * ### firestoreTables
 *
 * {@link Tables} on Firestore, following the layout in `src/firestore/collections.ts`.
 *
 * @param db Firestore client of the server's project
 * @returns Raw row access
 */
export function firestoreTables(db: Firestore): Tables {
  const find = async (table: string, where: Row) => {
    let query: Query = db.collection(camelCase(table));

    for (const [column, value] of Object.entries(where)) {
      query = query.where(camelCase(column), "==", value);
    }

    return (await query.get()).docs;
  };

  return {
    select: async (table, where = {}) =>
      (await find(table, where)).map((doc) => toRow(doc.data())),
    update: async (table, where, set) => {
      for (const doc of await find(table, where)) {
        await doc.ref.update(toFields(set));
      }
    },
    insert: async (table, row) => {
      const fields = toFields(row);

      if (row.revision === NEXT_REVISION) {
        fields.revision = await db.runTransaction(async (tx) => {
          const counter = db.collection("sequences").doc("change");
          const current = (await tx.get(counter)).get("value") as
            number | undefined;
          const next = (current ?? 0) + 1;

          tx.set(counter, { value: next });

          return next;
        });
      }

      await db
        .collection(camelCase(table))
        .doc(documentIdOf(table, row))
        .set(fields);
    },
  };
}

/**
 * ### documentIdOf
 *
 * Document id of a row, for the tables tests insert into.
 *
 * @param table SQL table name
 * @param row The row
 * @returns Its document id
 */
function documentIdOf(table: string, row: Row): string {
  switch (table) {
    case "vault_access":
      return `${String(row.vault_id)}:${String(row.principal_id)}`;
    default:
      return String(row.id);
  }
}

/**
 * ### toFields
 *
 * Converts a row to Firestore fields.
 *
 * @param row Row keyed by column
 * @returns Fields keyed by camelCase name
 */
function toFields(row: Row): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(row).map(([column, value]) => [
      camelCase(column),
      JSON_COLUMNS.has(column) && value !== null
        ? JSON.stringify(value)
        : value,
    ]),
  );
}

/**
 * ### toRow
 *
 * Converts Firestore fields to a row.
 *
 * @param fields Fields keyed by camelCase name
 * @returns Row keyed by column
 */
function toRow(fields: Record<string, unknown>): Row {
  return Object.fromEntries(
    Object.entries(fields).map(([field, value]) => {
      const column = snakeCase(field);

      if (value instanceof Timestamp) {
        return [column, value.toDate()];
      }

      if (value instanceof Uint8Array) {
        return [column, new Uint8Array(value)];
      }

      return [
        column,
        JSON_COLUMNS.has(column) && typeof value === "string"
          ? (JSON.parse(value) as unknown)
          : value,
      ];
    }),
  );
}

/**
 * ### encodeSql
 *
 * Serialises `jsonb` values for a bound parameter.
 *
 * @param column Column name
 * @param value Value to bind
 * @returns The bound value
 */
function encodeSql(column: string, value: unknown): unknown {
  return JSON_COLUMNS.has(column) && value !== null
    ? JSON.stringify(value)
    : value;
}

/**
 * ### camelCase
 *
 * @param name snake_case name
 * @returns camelCase name
 */
function camelCase(name: string): string {
  return name.replace(/_([a-z])/g, (_match, letter: string) =>
    letter.toUpperCase(),
  );
}

/**
 * ### snakeCase
 *
 * @param name camelCase name
 * @returns snake_case name
 */
function snakeCase(name: string): string {
  return name.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`);
}
