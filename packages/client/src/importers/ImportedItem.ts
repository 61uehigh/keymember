import type { ItemDetails, ItemOverview } from "@keymember/core";

/**
 * ### ImportedItem
 *
 * One item parsed from another password manager's export, ready to encrypt and upload.
 * Parsers never upload anything; the caller decides which vault receives each item.
 */
export interface ImportedItem {
  /**
   * ### folder
   *
   * Folder, collection or vault name from the source, when it had one. Useful for choosing
   * or creating a matching vault.
   */
  readonly folder?: string;

  /**
   * ### overview
   *
   * Listing fields.
   */
  readonly overview: ItemOverview;

  /**
   * ### details
   *
   * Secret fields.
   */
  readonly details: ItemDetails;
}

/**
 * ### ImportResult
 *
 * Parsed items plus anything that was skipped, so the user can see what did not come across.
 */
export interface ImportResult {
  /**
   * ### items
   *
   * Items that parsed.
   */
  readonly items: ReadonlyArray<ImportedItem>;

  /**
   * ### skipped
   *
   * Human-readable reasons for entries that were left out (unsupported types, archived items).
   */
  readonly skipped: ReadonlyArray<string>;
}

/**
 * ### ImportFormat
 *
 * Export formats keymember can read.
 */
export type ImportFormat =
  "chrome-csv" | "bitwarden-json" | "1password-1pux" | "cxf-json";

/**
 * ### ImportFormatError
 *
 * The file is not in the expected format, or is an encrypted export that cannot be read.
 */
export class ImportFormatError extends Error {}

/**
 * ### detailsFrom
 *
 * Builds item details, omitting optional fields that are empty in the source.
 *
 * @param fields Candidate field values
 * @returns Item details without empty optional fields
 */
export function detailsFrom(fields: {
  username?: string | null | undefined;
  password?: string | null | undefined;
  totp?: string | null | undefined;
  notes?: string | null | undefined;
  custom?: ItemDetails["fields"];
  passwordHistory?: ItemDetails["passwordHistory"];
  passkeys?: ItemDetails["passkeys"];
}): ItemDetails {
  const present = (value: string | null | undefined): value is string =>
    typeof value === "string" && value.length > 0;

  return {
    ...(present(fields.username) ? { username: fields.username } : {}),
    ...(present(fields.password) ? { password: fields.password } : {}),
    ...(present(fields.totp) ? { totp: fields.totp } : {}),
    ...(present(fields.notes) ? { notes: fields.notes } : {}),
    fields: fields.custom ?? [],
    passwordHistory: fields.passwordHistory ?? [],
    ...(fields.passkeys === undefined || fields.passkeys.length === 0
      ? {}
      : { passkeys: fields.passkeys }),
  };
}
