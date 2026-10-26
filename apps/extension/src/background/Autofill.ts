import {
  bestMatch,
  currentTotpCode,
  hasValidTotp,
  matchesQuery,
} from "@keymember/client";
import type { ItemSummary, Session } from "@keymember/client";
import { randomBytes, toBase64Url } from "@keymember/core";
import type { ItemDetails } from "@keymember/core";

import type { FieldKind, ItemRow } from "../shared/messages.js";
import { loadMenuTokens, setSessionValue } from "./storage.js";
import type { MenuToken } from "./storage.js";
import type { FillTarget, UnlockedSession } from "./Vault.js";

const MENU_TOKEN_TTL_MS = 2 * 60_000;

/**
 * ### vaultNamesOf
 *
 * Vault names by id, looked up once per listing rather than once per row.
 *
 * @param session Unlocked session
 * @returns Names by vault id
 */
function vaultNamesOf(session: Session): Map<string, string> {
  return new Map(session.listVaults().map((vault) => [vault.id, vault.name]));
}

/**
 * ### Autofill
 *
 * Everything that puts vault values into pages: matching items to a page, the inline menu's
 * one-time tokens, and the fill itself, which re-checks every frame's URL with the browser
 * before sending it anything. Pages and the menu only ever receive titles and user names, or
 * the exact values of one fill.
 */
export class Autofill {
  readonly #session: UnlockedSession;

  /**
   * ### constructor
   *
   * @param session The unlocked session, when there is one
   */
  constructor(session: UnlockedSession) {
    this.#session = session;
  }

  /**
   * ### rowsFor
   *
   * Items matching a page, best matches first. Items saved for https on an http page are
   * listed as insecure so the user understands why they cannot be filled.
   *
   * @param url Page or frame URL from the browser
   * @param kind Restrict to items useful for this field kind
   * @returns Displayable rows
   */
  async rowsFor(url: string, kind?: FieldKind): Promise<Array<ItemRow>> {
    const session = await this.#session.synced();

    if (session === undefined) {
      return [];
    }

    const ranked = session
      .listItems()
      .map((item) => ({ item, quality: bestMatch(item.overview.urls, url) }))
      .filter((entry) => entry.quality !== undefined)
      .sort(
        (a, b) =>
          (a.quality === "host" ? -1 : 0) - (b.quality === "host" ? -1 : 0),
      );

    const vaultNames = vaultNamesOf(session);

    return ranked
      .map(({ item, quality }) =>
        this.#row(session, item, vaultNames, quality === "insecure"),
      )
      .filter((row) => kind !== "otp" || row.hasTotp);
  }

  /**
   * ### search
   *
   * Items whose title or URL contains the query.
   *
   * @param query Search text
   * @returns Displayable rows
   */
  async search(query: string): Promise<Array<ItemRow>> {
    const session = await this.#session.synced();

    if (session === undefined) {
      return [];
    }

    const vaultNames = vaultNamesOf(session);

    return session
      .listItems()
      .filter((item) => matchesQuery(item, query))
      .slice(0, 50)
      .map((item) => this.#row(session, item, vaultNames, false));
  }

  /**
   * ### reveal
   *
   * One field of an item for the popup to copy or show. Two-factor fields return the current code.
   *
   * @param itemId Item to read
   * @param field Field to read
   * @returns The value, or `undefined` when the item has no such field
   */
  async reveal(
    itemId: string,
    field: "username" | "password" | "totp",
  ): Promise<string | undefined> {
    const session = await this.#session.require();
    const { details } = session.getItem(itemId);

    if (field === "totp") {
      return currentTotpCode(details);
    }

    return details[field];
  }

  /**
   * ### issueMenuToken
   *
   * Issues a one-time token letting the inline menu of one frame list and fill matching items.
   *
   * @param target Frame that opened the menu
   * @param kind Kind of the focused field
   * @returns The token, or `undefined` when locked or nothing matches
   */
  async issueMenuToken(
    target: FillTarget,
    kind: FieldKind,
  ): Promise<string | undefined> {
    if (
      (await this.rowsFor(target.url, kind)).length === 0 &&
      (await this.#session.current()) !== undefined
    ) {
      return undefined;
    }

    const now = Date.now();
    const token = toBase64Url(randomBytes(24));
    const tokens = await loadMenuTokens(now);

    tokens[token] = { ...target, kind, expiresAt: now + MENU_TOKEN_TTL_MS };
    await setSessionValue("menuTokens", tokens);

    return token;
  }

  /**
   * ### menuToken
   *
   * Resolves a menu token, refusing tokens presented from another tab.
   *
   * @param token Token from the menu
   * @param senderTabId Tab the menu iframe lives in, as reported by the browser
   * @returns The token's grant, or `undefined` when unknown, expired or misused
   */
  async menuToken(
    token: string,
    senderTabId: number | undefined,
  ): Promise<MenuToken | undefined> {
    const grant = (await loadMenuTokens(Date.now()))[token];

    return grant !== undefined && grant.tabId === senderTabId
      ? grant
      : undefined;
  }

  /**
   * ### consumeMenuToken
   *
   * Invalidates a token after use.
   *
   * @param token Token to drop
   */
  async consumeMenuToken(token: string): Promise<void> {
    const tokens = await loadMenuTokens(Date.now());

    await setSessionValue(
      "menuTokens",
      Object.fromEntries(
        Object.entries(tokens).filter(([key]) => key !== token),
      ),
    );
  }

  /**
   * ### fill
   *
   * Sends one item's values to frames whose current URL matches the item. Before sending, it
   * re-reads each frame's URL from the browser and refuses insecure (https item, http page)
   * and non-matching frames. For a one-time-code field only the current code is sent.
   *
   * @param itemId Item to fill
   * @param targets Candidate frames
   * @param kind Field kind the user is filling, when known
   * @returns Number of fields filled across frames
   */
  async fill(
    itemId: string,
    targets: ReadonlyArray<FillTarget>,
    kind?: FieldKind,
  ): Promise<number> {
    const session = await this.#session.require();
    const { overview, details } = session.getItem(itemId);
    let filled = 0;

    for (const target of targets) {
      const frame = await chrome.webNavigation.getFrame({
        tabId: target.tabId,
        frameId: target.frameId,
      });
      const quality =
        frame === null ? undefined : bestMatch(overview.urls, frame.url);

      if (
        frame?.url !== target.url ||
        quality === undefined ||
        quality === "insecure"
      ) {
        continue;
      }

      const values = this.#valuesFor(details, kind);
      const response: unknown = await chrome.tabs
        .sendMessage(
          target.tabId,
          {
            type: "fill",
            expectedUrl: frame.url,
            ...(kind === undefined ? {} : { kind }),
            ...values,
          },
          { frameId: target.frameId },
        )
        // The frame may have navigated away or have no content script; it simply fills nothing
        .catch(() => undefined);

      if (
        typeof response === "object" &&
        response !== null &&
        "filled" in response &&
        typeof response.filled === "number"
      ) {
        filled += response.filled;
      }
    }

    await this.#session.touch();

    return filled;
  }

  /**
   * ### #row
   *
   * Builds a displayable row for an item.
   *
   * @param session Unlocked session
   * @param item Item summary
   * @param vaultNames Vault names by id
   * @param insecure Whether the match is an https item on an http page
   * @returns The row
   */
  #row(
    session: Session,
    item: ItemSummary,
    vaultNames: ReadonlyMap<string, string>,
    insecure: boolean,
  ): ItemRow {
    const { overview, details } = session.getItem(item.id);
    const itemId = item.id;
    const vaultName = vaultNames.get(item.vaultId) ?? "";

    return {
      id: itemId,
      title: overview.title,
      vaultName,
      hasTotp: hasValidTotp(details),
      insecure,
      ...(details.username === undefined ? {} : { username: details.username }),
    };
  }

  /**
   * ### #valuesFor
   *
   * The values a fill may carry for a field kind: only the code for a code field.
   *
   * @param details Decrypted item details
   * @param kind Field kind being filled
   * @returns Values to send
   */
  #valuesFor(
    details: ItemDetails,
    kind: FieldKind | undefined,
  ): { username?: string; password?: string; totp?: string } {
    if (kind === "otp") {
      const totp = currentTotpCode(details);

      return totp === undefined ? {} : { totp };
    }

    return {
      ...(details.username === undefined ? {} : { username: details.username }),
      ...(details.password === undefined ? {} : { password: details.password }),
    };
  }
}
