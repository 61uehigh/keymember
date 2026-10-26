import { fromBase64Url, toBase64Url } from "@keymember/core";

/**
 * ### StoredRoots
 *
 * Pinned organisation keys as apps store them: base64url signing keys by user id.
 */
export type StoredRoots = Readonly<Record<string, string>>;

/**
 * ### decodeRoots
 *
 * Decodes pinned owner keys as apps store them. Entries that do not decode are dropped.
 *
 * @param roots Stored roots, base64url by user id
 * @returns Root signing keys by user id
 */
export function decodeRoots(roots: StoredRoots): Map<string, Uint8Array> {
  return new Map(
    Object.entries(roots).flatMap(([userId, key]) => {
      const bytes = fromBase64Url(key);

      return bytes === undefined ? [] : [[userId, bytes] as const];
    }),
  );
}

/**
 * ### encodeRoots
 *
 * Encodes root keys for storage.
 *
 * @param roots Root signing keys by user id
 * @returns Stored roots, base64url by user id
 */
export function encodeRoots(
  roots: ReadonlyMap<string, Uint8Array>,
): Record<string, string> {
  return Object.fromEntries(
    [...roots].map(([userId, key]) => [userId, toBase64Url(key)]),
  );
}

/**
 * ### mergeRoots
 *
 * Adds root keys to stored ones; a key for a user already present replaces it.
 *
 * @param stored Roots stored now
 * @param added Root signing keys to add
 * @returns The combined stored roots
 */
export function mergeRoots(
  stored: StoredRoots,
  added: ReadonlyMap<string, Uint8Array>,
): Record<string, string> {
  return { ...stored, ...encodeRoots(added) };
}
