import { detailsFrom, ImportFormatError } from "./ImportedItem.js";
import type { ImportedItem, ImportResult } from "./ImportedItem.js";

/**
 * ### parseCsvRows
 *
 * Parses RFC 4180 CSV: quoted fields, doubled quotes, and newlines inside quotes.
 *
 * @param text CSV text
 * @returns Rows of raw cell values
 */
export function parseCsvRows(text: string): Array<Array<string>> {
  const rows: Array<Array<string>> = [];
  let row: Array<string> = [];
  let cell = "";
  let quoted = false;

  // Drop a UTF-8 byte order mark, which Excel and some exporters prepend
  const input = text.startsWith("﻿") ? text.slice(1) : text;

  for (let i = 0; i < input.length; i += 1) {
    const char = input.charAt(i);

    if (quoted) {
      if (char === '"' && input.charAt(i + 1) === '"') {
        cell += '"';
        i += 1;
      } else if (char === '"') {
        quoted = false;
      } else {
        cell += char;
      }
    } else if (char === '"') {
      quoted = true;
    } else if (char === ",") {
      row.push(cell);
      cell = "";
    } else if (char === "\n" || char === "\r") {
      if (char === "\r" && input.charAt(i + 1) === "\n") {
        i += 1;
      }

      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
    } else {
      cell += char;
    }
  }

  if (cell.length > 0 || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }

  return rows.filter((cells) => cells.some((value) => value.length > 0));
}

/**
 * ### parseChromeCsv
 *
 * Reads a Chrome / Edge / Google Password Manager CSV export
 * (`name,url,username,password,note`). Column order is taken from the header row.
 * Throws {@link ImportFormatError} when the required columns are missing.
 *
 * @param text CSV file contents
 * @returns Parsed login items
 */
export function parseChromeCsv(text: string): ImportResult {
  const [header, ...rows] = parseCsvRows(text);
  const columns = (header ?? []).map((name) => name.trim().toLowerCase());
  const index = (name: string): number => columns.indexOf(name);

  if (index("url") === -1 || index("password") === -1) {
    throw new ImportFormatError(
      "Not a Chrome password CSV: expected url and password columns",
    );
  }

  const cell = (
    row: ReadonlyArray<string>,
    name: string,
  ): string | undefined => {
    const position = index(name);

    return position === -1 ? undefined : row[position];
  };
  const items: Array<ImportedItem> = [];
  const skipped: Array<string> = [];

  for (const row of rows) {
    const url = cell(row, "url") ?? "";
    const password = cell(row, "password") ?? "";

    if (url.length === 0 && password.length === 0) {
      skipped.push(`Empty row: ${row.join(",").slice(0, 40)}`);
      continue;
    }

    const name = cell(row, "name");

    items.push({
      overview: {
        type: "login",
        title: name !== undefined && name.length > 0 ? name : hostOf(url),
        urls: url.length > 0 ? [url] : [],
        tags: [],
      },
      details: detailsFrom({
        username: cell(row, "username"),
        password,
        notes: cell(row, "note"),
      }),
    });
  }

  return { items, skipped };
}

/**
 * ### hostOf
 *
 * Host name of a URL, for titling items that have no name; falls back to the raw text.
 *
 * @param url URL text from the export
 * @returns The host, or the input when it is not a URL
 */
function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    // Android app entries look like android://…; keep them readable rather than failing the import
    return url.length > 0 ? url : "Untitled";
  }
}
