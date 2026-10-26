import { DuplicateKeyError } from "../repositories/DuplicateKeyError.js";
import type { DocumentData, Documents } from "./Documents.js";

/**
 * ### insertNew
 *
 * Writes a new document and refuses, like an SQL primary key, when one with that id exists.
 * Plain `set` would silently replace it, which lets a client that picks a taken id overwrite
 * another record.
 *
 * @param docs Documents to write in
 * @param collection Collection name
 * @param id Document id
 * @param data Every field of the document
 */
export async function insertNew(
  docs: Pick<Documents, "create">,
  collection: string,
  id: string,
  data: DocumentData,
): Promise<void> {
  if (!(await docs.create(collection, id, data))) {
    throw new DuplicateKeyError(`${collection}/${id}`);
  }
}
