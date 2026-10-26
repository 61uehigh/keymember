import { z } from "zod";

import { importedPasskey } from "./importedPasskey.js";
import { detailsFrom, ImportFormatError } from "./ImportedItem.js";
import type { ImportedItem, ImportResult } from "./ImportedItem.js";

const editableField = z.object({
  fieldType: z.string().optional(),
  value: z.string(),
  label: z.string().optional(),
});

const credentialSchema = z.looseObject({ type: z.string() });

const basicAuthSchema = z.object({
  type: z.literal("basic-auth"),
  username: editableField.optional(),
  password: editableField.optional(),
});

const passkeySchema = z.object({
  type: z.literal("passkey"),
  credentialId: z.string(),
  rpId: z.string(),
  username: z.string().optional(),
  userDisplayName: z.string().optional(),
  userHandle: z.string(),
  key: z.string(),
});

const totpSchema = z.object({
  type: z.literal("totp"),
  secret: z.string(),
  period: z.number().int().optional(),
  digits: z.number().int().optional(),
  username: z.string().optional(),
  algorithm: z.string().optional(),
  issuer: z.string().optional(),
});

const noteSchema = z.object({
  type: z.literal("note"),
  content: editableField,
});

const headerSchema = z.object({
  version: z.object({ major: z.number().int(), minor: z.number().int() }),
  exporterRpId: z.string(),
  exporterDisplayName: z.string().optional(),
  accounts: z.array(
    z.object({
      username: z.string().optional(),
      collections: z
        .array(
          z.object({
            title: z.string(),
            items: z.array(z.object({ item: z.string() })).optional(),
          }),
        )
        .optional(),
      items: z.array(
        z.object({
          id: z.string(),
          title: z.string().optional(),
          creationAt: z.number().optional(),
          scope: z.object({ urls: z.array(z.string()).optional() }).optional(),
          credentials: z.array(credentialSchema),
          tags: z.array(z.string()).optional(),
        }),
      ),
    }),
  ),
});

/**
 * ### isCxf
 *
 * Whether JSON text looks like an unencrypted FIDO Credential Exchange Format export.
 *
 * @param text File contents
 * @returns Whether it has the CXF header fields
 */
export function isCxf(text: string): boolean {
  try {
    const parsed: unknown = JSON.parse(text);

    return (
      typeof parsed === "object" &&
      parsed !== null &&
      "exporterRpId" in parsed &&
      "accounts" in parsed
    );
  } catch {
    // Not JSON at all, so certainly not CXF
    return false;
  }
}

/**
 * ### otpauthUri
 *
 * Turns a CXF TOTP credential into an `otpauth://` URI the vault understands.
 *
 * @param totp TOTP credential
 * @param fallbackLabel Label when the credential names no account
 * @returns The URI
 */
function otpauthUri(
  totp: z.infer<typeof totpSchema>,
  fallbackLabel: string,
): string {
  const label = [totp.issuer, totp.username ?? fallbackLabel]
    .filter((part) => part !== undefined && part !== "")
    .join(":");
  const params = new URLSearchParams({
    secret: totp.secret,
    ...(totp.issuer === undefined ? {} : { issuer: totp.issuer }),
    ...(totp.algorithm === undefined
      ? {}
      : { algorithm: totp.algorithm.toUpperCase() }),
    ...(totp.digits === undefined ? {} : { digits: String(totp.digits) }),
    ...(totp.period === undefined ? {} : { period: String(totp.period) }),
  });

  return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
}

/**
 * ### parseCxf
 *
 * Reads an **unencrypted** FIDO Credential Exchange Format (CXF 1.x) JSON export. Login
 * credentials, P-256 passkeys, TOTP secrets and notes are imported; other credential types
 * (cards, identities, Wi-Fi, …) are reported as skipped. The first collection an item belongs
 * to becomes its folder.
 *
 * @param text JSON file contents
 * @returns Parsed items
 */
export function parseCxf(text: string): ImportResult {
  let parsed: unknown;

  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new ImportFormatError("Not a JSON file", { cause: error });
  }

  const result = headerSchema.safeParse(parsed);

  if (!result.success) {
    throw new ImportFormatError("Not a Credential Exchange Format export");
  }

  if (result.data.version.major !== 1) {
    throw new ImportFormatError(
      `Unsupported CXF version ${String(result.data.version.major)}.${String(result.data.version.minor)}`,
    );
  }

  const items: Array<ImportedItem> = [];
  const skipped: Array<string> = [];

  for (const account of result.data.accounts) {
    const folders = new Map<string, string>();

    for (const collection of account.collections ?? []) {
      for (const link of collection.items ?? []) {
        if (!folders.has(link.item)) {
          folders.set(link.item, collection.title);
        }
      }
    }

    for (const item of account.items) {
      const title = item.title ?? "Untitled";
      let username: string | undefined;
      let password: string | undefined;
      let totp: string | undefined;
      const notes: Array<string> = [];
      const passkeys = [];
      const createdAt = new Date(
        (item.creationAt ?? Date.now() / 1000) * 1000,
      ).toISOString();

      for (const raw of item.credentials) {
        const basic = basicAuthSchema.safeParse(raw);
        const passkey = passkeySchema.safeParse(raw);
        const otp = totpSchema.safeParse(raw);
        const note = noteSchema.safeParse(raw);

        if (basic.success) {
          username ??= basic.data.username?.value;
          password ??= basic.data.password?.value;
        } else if (passkey.success) {
          const imported = importedPasskey({
            credentialId: passkey.data.credentialId,
            rpId: passkey.data.rpId,
            userHandle: passkey.data.userHandle,
            userName: passkey.data.username ?? "",
            userDisplayName: passkey.data.userDisplayName ?? "",
            pkcs8: passkey.data.key,
            createdAt,
          });

          if (typeof imported === "string") {
            skipped.push(`${title}: ${imported}`);
          } else {
            passkeys.push(imported);
          }
        } else if (otp.success) {
          totp ??= otpauthUri(otp.data, title);
        } else if (note.success) {
          notes.push(note.data.content.value);
        } else {
          skipped.push(`${title}: unsupported credential type ${raw.type}`);
        }
      }

      const isLogin =
        username !== undefined ||
        password !== undefined ||
        passkeys.length > 0 ||
        totp !== undefined;

      if (!isLogin && notes.length === 0) {
        skipped.push(`${title}: nothing importable`);
        continue;
      }

      const folder = folders.get(item.id);

      items.push({
        ...(folder === undefined ? {} : { folder }),
        overview: {
          type: isLogin ? "login" : "secure-note",
          title,
          urls: item.scope?.urls ?? [],
          tags: item.tags ?? [],
        },
        details: detailsFrom({
          username,
          password,
          totp,
          notes: notes.join("\n\n"),
          passkeys,
        }),
      });
    }
  }

  return { items, skipped };
}
