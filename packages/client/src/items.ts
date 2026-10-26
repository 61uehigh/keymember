import type { ItemDetails } from "@keymember/core";

import type { ItemSummary } from "./Session.type.js";
import { parseTotp, totpCode } from "./totp.js";

/**
 * ### matchesQuery
 *
 * Whether an item's title or one of its URLs contains the search text, ignoring case.
 * Empty text matches everything.
 *
 * @param item Item to test
 * @param query Search text as typed
 * @returns Whether it matches
 */
export function matchesQuery(item: ItemSummary, query: string): boolean {
  const needle = query.trim().toLowerCase();

  return (
    needle === "" ||
    item.overview.title.toLowerCase().includes(needle) ||
    item.overview.urls.some((url) => url.toLowerCase().includes(needle))
  );
}

/**
 * ### currentTotpCode
 *
 * The item's two-factor code for now, when it holds a secret that parses.
 *
 * @param details Decrypted item details
 * @param now Time to compute the code for
 * @returns The code, or `undefined` without a usable secret
 */
export function currentTotpCode(
  details: ItemDetails,
  now: Date = new Date(),
): string | undefined {
  const parameters =
    details.totp === undefined ? undefined : parseTotp(details.totp);

  return parameters === undefined ? undefined : totpCode(parameters, now).code;
}

/**
 * ### hasValidTotp
 *
 * Whether an item can produce a two-factor code; apps offer a code only then.
 *
 * @param details Decrypted item details
 * @returns Whether its secret parses
 */
export function hasValidTotp(details: ItemDetails): boolean {
  return details.totp !== undefined && parseTotp(details.totp) !== undefined;
}
