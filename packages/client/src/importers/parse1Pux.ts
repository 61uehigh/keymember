import { strFromU8, unzipSync } from "fflate";
import { z } from "zod";

import { detailsFrom, ImportFormatError } from "./ImportedItem.js";
import type { ImportedItem, ImportResult } from "./ImportedItem.js";

const fieldValueSchema = z.record(z.string(), z.unknown());

const itemSchema = z.object({
  state: z.string().optional(),
  categoryUuid: z.string().optional(),
  overview: z.object({
    title: z.string().optional(),
    url: z.string().optional(),
    urls: z.array(z.object({ url: z.string() })).optional(),
    tags: z.array(z.string()).optional(),
  }),
  details: z.object({
    loginFields: z
      .array(
        z.object({
          designation: z.string().optional(),
          value: z.string().optional(),
        }),
      )
      .optional(),
    notesPlain: z.string().optional(),
    password: z.string().optional(),
    sections: z
      .array(
        z.object({
          fields: z
            .array(
              z.object({
                title: z.string().optional(),
                value: fieldValueSchema.optional(),
              }),
            )
            .optional(),
        }),
      )
      .optional(),
    passwordHistory: z
      .array(z.object({ value: z.string(), time: z.number() }))
      .optional(),
  }),
});

const exportSchema = z.object({
  accounts: z.array(
    z.object({
      vaults: z.array(
        z.object({
          attrs: z.object({ name: z.string() }),
          items: z.array(itemSchema),
        }),
      ),
    }),
  ),
});

// 1Password category ids: 001 login, 003 secure note, 005 password, 112 API credential
const CATEGORY_TYPES: Readonly<
  Record<string, "login" | "secure-note" | "api-credential">
> = {
  "001": "login",
  "003": "secure-note",
  "005": "login",
  "112": "api-credential",
};

/**
 * ### parse1Pux
 *
 * Reads a 1Password `.1pux` export (a zip holding `export.data`). Logins, secure notes,
 * passwords and API credentials are imported, with the source vault name as the folder;
 * archived items and other categories are reported as skipped.
 * Throws {@link ImportFormatError} when the file is not a 1PUX archive.
 *
 * @param archive Raw `.1pux` file bytes
 * @returns Parsed items
 */
export function parse1Pux(archive: Uint8Array): ImportResult {
  let data: Uint8Array | undefined;

  try {
    data = unzipSync(archive, {
      filter: (file) => file.name === "export.data",
    })["export.data"];
  } catch (error) {
    throw new ImportFormatError("Not a 1PUX archive", { cause: error });
  }

  if (data === undefined) {
    throw new ImportFormatError("1PUX archive has no export.data");
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(strFromU8(data));
  } catch (error) {
    throw new ImportFormatError("export.data is not JSON", { cause: error });
  }

  const result = exportSchema.safeParse(parsed);

  if (!result.success) {
    throw new ImportFormatError(
      "export.data does not look like a 1Password export",
    );
  }

  const items: Array<ImportedItem> = [];
  const skipped: Array<string> = [];

  for (const vault of result.data.accounts.flatMap(
    (account) => account.vaults,
  )) {
    for (const item of vault.items) {
      const title = item.overview.title ?? "Untitled";
      const type = CATEGORY_TYPES[item.categoryUuid ?? ""];

      if (item.state === "archived") {
        skipped.push(`${title}: archived`);
        continue;
      }

      if (type === undefined) {
        skipped.push(
          `${title}: unsupported category ${item.categoryUuid ?? "unknown"}`,
        );
        continue;
      }

      const loginField = (designation: string): string | undefined =>
        item.details.loginFields?.find(
          (field) => field.designation === designation,
        )?.value;
      const custom = [];
      let totp: string | undefined;

      for (const field of (item.details.sections ?? []).flatMap(
        (section) => section.fields ?? [],
      )) {
        const [kind, value] = Object.entries(field.value ?? {})[0] ?? [];

        if (typeof value !== "string" || value.length === 0) {
          continue;
        }

        if (kind === "totp") {
          totp = value;
        } else {
          custom.push({
            label: field.title ?? kind ?? "",
            value,
            concealed: kind === "concealed",
          });
        }
      }

      const urls =
        item.overview.urls?.map((entry) => entry.url) ??
        (item.overview.url === undefined ? [] : [item.overview.url]);

      items.push({
        folder: vault.attrs.name,
        overview: { type, title, urls, tags: item.overview.tags ?? [] },
        details: detailsFrom({
          username: loginField("username"),
          password: loginField("password") ?? item.details.password,
          totp,
          notes: item.details.notesPlain,
          custom,
          passwordHistory: (item.details.passwordHistory ?? []).map(
            (entry) => ({
              password: entry.value,
              replacedAt: new Date(entry.time * 1000).toISOString(),
            }),
          ),
        }),
      });
    }
  }

  return { items, skipped };
}
