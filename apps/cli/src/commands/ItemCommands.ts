import { spawn } from "node:child_process";
import { constants } from "node:os";
import { readFile } from "node:fs/promises";

import {
  detectImportFormat,
  parseImport,
  shareLinkUrl,
} from "@keymember/client";
import type { ImportFormat, ShareField } from "@keymember/client";
import { generatePassword } from "@keymember/core";

import type { CommandDeps } from "./CommandDeps.js";
import { parseEnvMapping, readField } from "../itemFields.js";
import { resolveItem, resolveVault } from "../lookups.js";

/**
 * ### ItemCommands
 *
 * Commands that read and write items: listing, adding, reading, sharing by link, deleting,
 * importing another password manager's export and running a command with items as
 * environment variables.
 */
export class ItemCommands {
  readonly #deps: CommandDeps;

  /**
   * ### constructor
   *
   * @param deps Terminal and session access
   */
  constructor(deps: CommandDeps) {
    this.#deps = deps;
  }

  /**
   * ### list
   *
   * Lists items, optionally in one vault.
   *
   * @param vaultRef Vault name or id to limit the listing to
   */
  async list(vaultRef?: string): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      await session.sync();

      const vaultId =
        vaultRef === undefined ? undefined : resolveVault(session, vaultRef);

      for (const item of session.listItems(vaultId)) {
        this.#deps.io.print(
          `${item.id}\t${item.overview.type}\t${item.overview.title}\t${item.overview.urls.join(",")}`,
        );
      }
    });
  }

  /**
   * ### add
   *
   * Adds a login item, asking for the password unless one is generated.
   *
   * @param vaultRef Vault name or id
   * @param options Item fields and whether to generate the password
   */
  async add(
    vaultRef: string,
    options: {
      title: string;
      urls: ReadonlyArray<string>;
      username?: string;
      generate: boolean;
      notes?: string;
    },
  ): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      await session.sync();

      const vaultId = resolveVault(session, vaultRef);
      const password = options.generate
        ? generatePassword()
        : await this.#deps.io.askSecret("Item password: ");
      const itemId = await session.createItem(
        vaultId,
        { type: "login", title: options.title, urls: options.urls, tags: [] },
        {
          password,
          fields: [],
          passwordHistory: [],
          ...(options.username === undefined
            ? {}
            : { username: options.username }),
          ...(options.notes === undefined ? {} : { notes: options.notes }),
        },
      );

      this.#deps.io.print(itemId);
    });
  }

  /**
   * ### get
   *
   * Prints one field of an item, or the whole item as JSON.
   *
   * @param itemRef Item title or id
   * @param field Field to print; omit for the whole item
   */
  async get(itemRef: string, field?: string): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      await session.sync();

      const item = session.getItem(resolveItem(session, itemRef).id);

      this.#deps.io.print(
        field === undefined
          ? JSON.stringify(item, null, 2)
          : readField(item, field),
      );
    });
  }

  /**
   * ### share
   *
   * Makes a share link for an item and prints it. Asks for a passphrase when `withPassphrase` is set.
   *
   * @param itemRef Item title or id
   * @param options Fields to include, lifetime in hours, number of views, and whether to set a passphrase
   */
  async share(
    itemRef: string,
    options: {
      fields: ReadonlyArray<ShareField>;
      hours: number;
      views: number;
      withPassphrase: boolean;
    },
  ): Promise<void> {
    await this.#deps.sessions.withSession(async (session, config) => {
      await session.sync();

      const item = resolveItem(session, itemRef);
      const passphrase = options.withPassphrase
        ? await this.#deps.io.askSecret("Passphrase for the recipient: ")
        : undefined;
      const link = await session.createShareLink(item.id, {
        fields: options.fields,
        expiresInMs: options.hours * 60 * 60 * 1000,
        maxViews: options.views,
        passphrase,
      });

      this.#deps.io.print(shareLinkUrl(config.serverUrl, link));
      this.#deps.io.print(
        `Opens ${String(options.views)} time(s) within ${String(options.hours)} hour(s)${
          link.needsPassphrase ? "; send the passphrase another way" : ""
        }`,
      );
    });
  }

  /**
   * ### delete
   *
   * Moves an item to the trash.
   *
   * @param itemRef Item title or id
   */
  async delete(itemRef: string): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      await session.sync();
      await session.deleteItem(resolveItem(session, itemRef).id);
      this.#deps.io.print("Deleted");
    });
  }

  /**
   * ### importFile
   *
   * Imports another password manager's export into one vault. The file is parsed locally;
   * only encrypted items are uploaded.
   *
   * @param filePath Export file
   * @param vaultRef Vault name or id to import into
   * @param format Export format; guessed from the extension when omitted
   */
  async importFile(
    filePath: string,
    vaultRef: string,
    format?: ImportFormat,
  ): Promise<void> {
    const contents = await readFile(filePath);
    const resolved = format ?? detectImportFormat(filePath, contents);

    if (resolved === undefined) {
      throw new Error(
        "Cannot tell the format from the file name; pass --format",
      );
    }

    const { items, skipped } = parseImport(resolved, contents);

    await this.#deps.sessions.withSession(async (session) => {
      await session.sync();

      const vaultId = resolveVault(session, vaultRef);

      for (const item of items) {
        await session.createItem(vaultId, item.overview, item.details);
      }

      this.#deps.io.print(`Imported ${String(items.length)} item(s)`);

      for (const reason of skipped) {
        this.#deps.io.print(`skipped: ${reason}`);
      }

      this.#deps.io.print(
        "Delete the export file now: it holds every password in plain text.",
      );
    });
  }

  /**
   * ### run
   *
   * Runs a command with secrets injected as environment variables, so they never land in
   * shell history or `.env` files. The vault is locked again before the command starts.
   *
   * @param mappings `NAME=item.field` mappings
   * @param command Command and arguments to run
   * @returns The command's exit code
   */
  async run(
    mappings: ReadonlyArray<string>,
    command: ReadonlyArray<string>,
  ): Promise<number> {
    const [executable, ...args] = command;

    if (executable === undefined) {
      throw new Error("Nothing to run; put the command after --");
    }

    const env: Record<string, string> = {};

    await this.#deps.sessions.withSession(async (session) => {
      await session.sync();

      for (const mapping of mappings) {
        const { name, item, field } = parseEnvMapping(mapping);

        env[name] = readField(
          session.getItem(resolveItem(session, item).id),
          field,
        );
      }
    });

    return new Promise((resolve, reject) => {
      const child = spawn(executable, args, {
        stdio: "inherit",
        env: { ...process.env, ...env },
      });

      child.on("error", reject);
      child.on("exit", (code, signal) => {
        // Like a shell: a child killed by a signal exits with 128 plus the signal's number
        resolve(
          code ?? (signal === null ? 1 : 128 + constants.signals[signal]),
        );
      });
    });
  }
}
