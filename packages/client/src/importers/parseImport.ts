import type { ImportFormat, ImportResult } from "./ImportedItem.js";
import { parse1Pux } from "./parse1Pux.js";
import { parseBitwardenJson } from "./parseBitwardenJson.js";
import { parseChromeCsv } from "./parseChromeCsv.js";
import { isCxf, parseCxf } from "./parseCxf.js";

/**
 * ### detectImportFormat
 *
 * Guesses the export format from the file name and, for JSON, from its contents (Bitwarden
 * and Credential Exchange Format exports are both `.json`).
 *
 * @param fileName Name of the exported file
 * @param contents File contents, to tell JSON formats apart
 * @returns The format, or `undefined` when the extension is not recognised
 */
export function detectImportFormat(
  fileName: string,
  contents?: Uint8Array,
): ImportFormat | undefined {
  const lower = fileName.toLowerCase();

  if (lower.endsWith(".1pux")) {
    return "1password-1pux";
  }

  if (lower.endsWith(".json")) {
    return contents !== undefined && isCxf(new TextDecoder().decode(contents))
      ? "cxf-json"
      : "bitwarden-json";
  }

  if (lower.endsWith(".csv")) {
    return "chrome-csv";
  }

  return undefined;
}

/**
 * ### parseImport
 *
 * Parses an export file in the given format. Throws {@link ImportFormatError} when the
 * contents do not match the format.
 *
 * @param format Export format
 * @param contents Raw file bytes
 * @returns Parsed items and skipped entries
 */
export function parseImport(
  format: ImportFormat,
  contents: Uint8Array,
): ImportResult {
  switch (format) {
    case "1password-1pux":
      return parse1Pux(contents);
    case "bitwarden-json":
      return parseBitwardenJson(new TextDecoder().decode(contents));
    case "chrome-csv":
      return parseChromeCsv(new TextDecoder().decode(contents));
    case "cxf-json":
      return parseCxf(new TextDecoder().decode(contents));
  }
}
