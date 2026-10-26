import { z } from "zod";

import { toBase64Url } from "@keymember/core";

import { importedPasskey } from "./importedPasskey.js";
import { detailsFrom, ImportFormatError } from "./ImportedItem.js";
import type { ImportedItem, ImportResult } from "./ImportedItem.js";

const exportSchema = z.object({
  encrypted: z.boolean().optional(),
  folders: z.array(z.object({ id: z.string(), name: z.string() })).optional(),
  collections: z
    .array(z.object({ id: z.string(), name: z.string() }))
    .optional(),
  items: z.array(
    z.object({
      type: z.number(),
      name: z.string().nullable().optional(),
      notes: z.string().nullable().optional(),
      folderId: z.string().nullable().optional(),
      collectionIds: z.array(z.string()).nullable().optional(),
      login: z
        .object({
          username: z.string().nullable().optional(),
          password: z.string().nullable().optional(),
          totp: z.string().nullable().optional(),
          fido2Credentials: z
            .array(
              z.object({
                credentialId: z.string(),
                keyType: z.string().optional(),
                keyAlgorithm: z.string().optional(),
                keyCurve: z.string().optional(),
                keyValue: z.string(),
                rpId: z.string(),
                userHandle: z.string().nullable().optional(),
                userName: z.string().nullable().optional(),
                userDisplayName: z.string().nullable().optional(),
                creationDate: z.string().nullable().optional(),
              }),
            )
            .nullable()
            .optional(),
          uris: z
            .array(z.object({ uri: z.string().nullable().optional() }))
            .nullable()
            .optional(),
        })
        .nullable()
        .optional(),
      fields: z
        .array(
          z.object({
            name: z.string().nullable().optional(),
            value: z.string().nullable().optional(),
            type: z.number().optional(),
          }),
        )
        .nullable()
        .optional(),
      passwordHistory: z
        .array(z.object({ password: z.string(), lastUsedDate: z.string() }))
        .nullable()
        .optional(),
    }),
  ),
});

// Bitwarden cipher types: 1 login, 2 secure note, 3 card, 4 identity, 5 SSH key
const LOGIN = 1;
const SECURE_NOTE = 2;
const HIDDEN_FIELD = 1;

/**
 * ### bitwardenCredentialId
 *
 * Bitwarden writes 16-byte credential ids as GUID strings and others as `b64.` + base64url;
 * returns the base64url form either way.
 *
 * @param stored Credential id as exported
 * @returns base64url credential id
 */
function bitwardenCredentialId(stored: string): string {
  if (stored.startsWith("b64.")) {
    return stored.slice("b64.".length);
  }

  const hex = stored.replace(/-/g, "");

  return /^[0-9a-f]{32}$/i.test(hex)
    ? toBase64Url(
        Uint8Array.from(hex.match(/../g) ?? [], (pair) => parseInt(pair, 16)),
      )
    : stored;
}

/**
 * ### parseBitwardenJson
 *
 * Reads a Bitwarden **unencrypted** JSON export (personal or organisation). Logins (with their
 * P-256 passkeys) and secure notes are imported; cards, identities and SSH keys are reported as skipped. Throws
 * {@link ImportFormatError} for encrypted exports, which only Bitwarden can open.
 *
 * @param text JSON file contents
 * @returns Parsed items
 */
export function parseBitwardenJson(text: string): ImportResult {
  let parsed: unknown;

  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new ImportFormatError("Not a JSON file", { cause: error });
  }

  const result = exportSchema.safeParse(parsed);

  if (!result.success) {
    throw new ImportFormatError("Not a Bitwarden JSON export");
  }

  if (result.data.encrypted === true) {
    throw new ImportFormatError(
      "This is an encrypted Bitwarden export; export again as unencrypted JSON",
    );
  }

  const folders = new Map(
    [...(result.data.folders ?? []), ...(result.data.collections ?? [])].map(
      (folder) => [folder.id, folder.name],
    ),
  );
  const items: Array<ImportedItem> = [];
  const skipped: Array<string> = [];

  for (const item of result.data.items) {
    const title = item.name ?? "Untitled";
    const folderId = item.folderId ?? item.collectionIds?.[0];
    const folder = folderId === undefined ? undefined : folders.get(folderId);

    if (item.type !== LOGIN && item.type !== SECURE_NOTE) {
      skipped.push(`${title}: unsupported item type ${String(item.type)}`);
      continue;
    }

    const passkeys = [];

    for (const credential of item.login?.fido2Credentials ?? []) {
      const passkey = importedPasskey({
        credentialId: bitwardenCredentialId(credential.credentialId),
        rpId: credential.rpId,
        userHandle: credential.userHandle ?? "",
        userName: credential.userName ?? "",
        userDisplayName: credential.userDisplayName ?? "",
        pkcs8: credential.keyValue,
        createdAt: credential.creationDate ?? new Date().toISOString(),
      });

      if (typeof passkey === "string") {
        skipped.push(`${title}: ${passkey}`);
      } else {
        passkeys.push(passkey);
      }
    }

    items.push({
      ...(folder === undefined ? {} : { folder }),
      overview: {
        type: item.type === LOGIN ? "login" : "secure-note",
        title,
        urls: (item.login?.uris ?? [])
          .map((entry) => entry.uri ?? "")
          .filter((uri) => uri.length > 0),
        tags: [],
      },
      details: detailsFrom({
        username: item.login?.username,
        password: item.login?.password,
        totp: item.login?.totp,
        notes: item.notes,
        custom: (item.fields ?? []).map((field) => ({
          label: field.name ?? "",
          value: field.value ?? "",
          concealed: field.type === HIDDEN_FIELD,
        })),
        passwordHistory: (item.passwordHistory ?? []).map((entry) => ({
          password: entry.password,
          replacedAt: entry.lastUsedDate,
        })),
        passkeys,
      }),
    });
  }

  return { items, skipped };
}
