import { DuplicateKeyError } from "../repositories/DuplicateKeyError.js";
import { COLLECTIONS } from "./collections.js";
import type { Documents } from "./Documents.js";
import { text } from "./fields.js";

const UNIQUE_KEYS = COLLECTIONS.uniqueKeys;

/**
 * ### UniqueKind
 *
 * Values that may belong to one record only, as SQL's unique constraints keep them.
 */
export type UniqueKind =
  "email" | "accountId" | "ssoSubject" | "openRecovery" | "organization";

/**
 * ### uniqueKeyId
 *
 * Document id of a sentinel. Values are URI-encoded, since an id may not contain `/`.
 *
 * @param kind What the value is
 * @param value The value
 * @returns The id
 */
function uniqueKeyId(kind: UniqueKind, value: string): string {
  return `${kind}:${encodeURIComponent(value)}`;
}

/**
 * ### claimUnique
 *
 * Records that `owner` holds a unique value. Firestore has no unique constraints, so a sentinel
 * document keyed by the value stands in for one: written in the same transaction as the record,
 * it makes a second claim fail even when the caller skipped its own check.
 *
 * @param docs Documents to write in, normally a transaction
 * @param kind What the value is
 * @param value The value
 * @param owner Id of the record that holds it
 */
export async function claimUnique(
  docs: Pick<Documents, "create" | "get">,
  kind: UniqueKind,
  value: string,
  owner: string,
): Promise<void> {
  const id = uniqueKeyId(kind, value);

  if (await docs.create(UNIQUE_KEYS, id, { kind, value, owner })) {
    return;
  }

  const existing = await docs.get(UNIQUE_KEYS, id);

  if (existing === undefined || text(existing, "owner") !== owner) {
    throw new DuplicateKeyError(`${kind} ${value}`);
  }
}

/**
 * ### releaseUnique
 *
 * Gives up a unique value, when `owner` still holds it.
 *
 * @param docs Documents to write in, normally a transaction
 * @param kind What the value is
 * @param value The value
 * @param owner Id of the record that held it
 */
export async function releaseUnique(
  docs: Pick<Documents, "delete" | "get">,
  kind: UniqueKind,
  value: string,
  owner: string,
): Promise<void> {
  const id = uniqueKeyId(kind, value);
  const existing = await docs.get(UNIQUE_KEYS, id);

  if (existing !== undefined && text(existing, "owner") === owner) {
    await docs.delete(UNIQUE_KEYS, id);
  }
}
