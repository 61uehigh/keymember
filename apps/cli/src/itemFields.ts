import type { ItemDetails } from "@keymember/core";

/**
 * ### parseEnvMapping
 *
 * Parses a `NAME=item.field` mapping for `keymember run`. The item reference may itself
 * contain dots; the field is everything after the last dot.
 *
 * @param mapping Mapping as typed on the command line
 * @returns The variable name, item reference and field
 */
export function parseEnvMapping(mapping: string): {
  name: string;
  item: string;
  field: string;
} {
  const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.+)\.([^.]+)$/.exec(mapping);

  if (
    match?.[1] === undefined ||
    match[2] === undefined ||
    match[3] === undefined
  ) {
    throw new Error(
      `Invalid mapping "${mapping}"; expected NAME=<item title or id>.<field>`,
    );
  }

  return { name: match[1], item: match[2], field: match[3] };
}

/**
 * ### readField
 *
 * Reads one field of a decrypted item: a built-in field or a custom field by label.
 *
 * @param item Decrypted item
 * @param field Field name: `username`, `password`, `totp`, `notes`, `url` or a custom label
 * @returns The field value
 */
export function readField(
  item: { overview: { urls: ReadonlyArray<string> }; details: ItemDetails },
  field: string,
): string {
  const builtIn: Record<string, string | undefined> = {
    username: item.details.username,
    password: item.details.password,
    totp: item.details.totp,
    notes: item.details.notes,
    url: item.overview.urls[0],
  };
  const value =
    field in builtIn
      ? builtIn[field]
      : item.details.fields.find((custom) => custom.label === field)?.value;

  if (value === undefined) {
    throw new Error(`Item has no "${field}" field`);
  }

  return value;
}
