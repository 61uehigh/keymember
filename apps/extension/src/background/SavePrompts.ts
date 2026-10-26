import { bestMatch, siteKeyOf } from "@keymember/client";
import type { ItemSummary, Session } from "@keymember/client";
import { randomBytes, toBase64Url } from "@keymember/core";

import { loadPending, setSessionValue } from "./storage.js";
import type { PendingSave } from "./storage.js";
import type { FillTarget, UnlockedSession } from "./Vault.js";

const PENDING_TTL_MS = 60_000;

/**
 * ### SavePrompts
 *
 * Offers to save credentials a page submitted: keeps them briefly in memory-only storage, tells
 * the popup what would be saved (never the password), and stores them as a new login or as a
 * changed password on the matching item.
 */
export class SavePrompts {
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
   * ### addPending
   *
   * Records credentials a page submitted, unless an item for the site already holds them.
   *
   * @param target Frame that submitted
   * @param username Submitted user name
   * @param password Submitted password
   * @returns Whether the user should be prompted
   */
  async addPending(
    target: FillTarget,
    username: string | undefined,
    password: string,
  ): Promise<boolean> {
    const session = await this.#session.synced();

    if (session === undefined) {
      return false;
    }

    const known = session
      .listItems()
      .filter((item) => bestMatch(item.overview.urls, target.url) !== undefined)
      .some((item) => {
        const { details } = session.getItem(item.id);

        return (
          details.password === password &&
          (username === undefined || details.username === username)
        );
      });

    if (known) {
      return false;
    }

    const now = Date.now();
    const pending = (await loadPending(now, PENDING_TTL_MS)).filter(
      (entry) => !(entry.tabId === target.tabId && entry.username === username),
    );

    pending.unshift({
      id: toBase64Url(randomBytes(12)),
      tabId: target.tabId,
      url: target.url,
      password,
      createdAt: now,
      ...(username === undefined ? {} : { username }),
    });
    await setSessionValue("pending", pending.slice(0, 5));

    return true;
  }

  /**
   * ### pending
   *
   * The newest pending save, described for the popup without its password.
   *
   * @returns The pending save with the existing item it would update, and writable vaults
   */
  async pending(): Promise<{
    pending?: {
      id: string;
      site: string;
      username?: string;
      updatesItemId?: string;
      updatesTitle?: string;
    };
    vaults: Array<{ id: string; name: string }>;
  }> {
    const session = await this.#session.synced();
    const [entry] = await loadPending(Date.now(), PENDING_TTL_MS);

    if (session === undefined) {
      return { vaults: [] };
    }

    const vaults = session
      .listVaults()
      .filter((vault) => vault.permission !== "view")
      .map((vault) => ({ id: vault.id, name: vault.name }));

    if (entry === undefined) {
      return { vaults };
    }

    const existing = this.#existingFor(session, entry);

    return {
      vaults,
      pending: {
        id: entry.id,
        site: new URL(entry.url).hostname,
        ...(entry.username === undefined ? {} : { username: entry.username }),
        ...(existing === undefined
          ? {}
          : {
              updatesItemId: existing.id,
              updatesTitle: existing.overview.title,
            }),
      },
    };
  }

  /**
   * ### savePending
   *
   * Saves a pending credential: updates the matching item (keeping the old password in its
   * history) or creates a new login in the chosen vault.
   *
   * @param id Pending save id
   * @param vaultId Vault for a new item; ignored for updates
   */
  async savePending(id: string, vaultId: string | undefined): Promise<void> {
    const session = await this.#session.require();
    const all = await loadPending(Date.now(), PENDING_TTL_MS);
    const entry = all.find((candidate) => candidate.id === id);

    if (entry === undefined) {
      throw new Error("This save prompt has expired.");
    }

    const existing = this.#existingFor(session, entry);

    if (existing !== undefined) {
      const { overview, details } = session.getItem(existing.id);

      await session.updateItem(existing.id, overview, {
        ...details,
        password: entry.password,
        passwordHistory: [
          ...(details.password === undefined
            ? []
            : [
                {
                  password: details.password,
                  replacedAt: new Date().toISOString(),
                },
              ]),
          ...details.passwordHistory,
        ].slice(0, 20),
      });
    } else {
      if (vaultId === undefined) {
        throw new Error("Choose a vault to save to.");
      }

      const origin = new URL(entry.url).origin;

      await session.createItem(
        vaultId,
        {
          type: "login",
          title: new URL(entry.url).hostname,
          urls: [origin],
          tags: [],
        },
        {
          password: entry.password,
          fields: [],
          passwordHistory: [],
          ...(entry.username === undefined ? {} : { username: entry.username }),
        },
      );
    }

    await this.dismissPending(id);
  }

  /**
   * ### prune
   *
   * Drops expired pending saves, which hold plaintext passwords, even when nobody reads them.
   */
  async prune(): Promise<void> {
    await loadPending(Date.now(), PENDING_TTL_MS);
  }

  /**
   * ### hasPending
   *
   * Whether a tab has an unexpired pending save.
   *
   * @param tabId Tab to check
   * @returns Whether to show the save badge
   */
  async hasPending(tabId: number): Promise<boolean> {
    return (await loadPending(Date.now(), PENDING_TTL_MS)).some(
      (entry) => entry.tabId === tabId,
    );
  }

  /**
   * ### dismissPending
   *
   * Drops a pending save.
   *
   * @param id Pending save id
   */
  async dismissPending(id: string): Promise<void> {
    const remaining = (await loadPending(Date.now(), PENDING_TTL_MS)).filter(
      (entry) => entry.id !== id,
    );

    await setSessionValue("pending", remaining);
  }

  /**
   * ### #existingFor
   *
   * The item a pending save would update: same scheme, same host and same user name. A login
   * submitted over http never updates an item saved for https, which autofill would refuse to
   * fill there anyway.
   *
   * @param session Unlocked session
   * @param entry Pending save
   * @returns The matching item summary, if any
   */
  #existingFor(session: Session, entry: PendingSave): ItemSummary | undefined {
    const page = siteKeyOf(entry.url);

    if (page === undefined) {
      return undefined;
    }

    // Updates target the exact site; a sibling subdomain must not overwrite another login
    return session
      .listItems()
      .filter((item) =>
        item.overview.urls.some((url) => {
          const saved = siteKeyOf(url);

          return saved?.scheme === page.scheme && saved.host === page.host;
        }),
      )
      .find(
        (item) => session.getItem(item.id).details.username === entry.username,
      );
  }
}
