import type { Session } from "@keymember/client";

import type { SshKeyRow } from "../../shared/ipc.js";
import type { ConfirmSigning } from "../platform.js";
import {
  fingerprintOf,
  generateEd25519,
  loadSshKey,
  publicKeyLine,
} from "./keys.js";
import type { SshKey } from "./keys.js";
import type { AgentBackend, AgentIdentity } from "./SshAgent.js";

/**
 * ### KeyringSession
 *
 * The part of an unlocked session the keyring reads and writes SSH key items through.
 */
export type KeyringSession = Pick<
  Session,
  "createItem" | "getItem" | "listItems" | "listVaults" | "sync"
>;

/**
 * ### VaultKeyring
 *
 * The vault's SSH keys: lists and adds `ssh-key` items, and backs the SSH agent. Keys are
 * offered only while a session is attached, and each signature needs the user's approval,
 * once or until the vault locks. Detaching (on lock) drops both the keys and the approvals.
 */
export class VaultKeyring implements AgentBackend {
  readonly #confirmSigning: ConfirmSigning;
  readonly #allowed = new Set<string>();
  #session: KeyringSession | undefined;

  /**
   * ### constructor
   *
   * @param confirmSigning Asks the user before a key signs
   */
  constructor(confirmSigning: ConfirmSigning) {
    this.#confirmSigning = confirmSigning;
  }

  /**
   * ### attach
   *
   * Starts serving the keys of a newly unlocked session.
   *
   * @param session Unlocked session
   */
  attach(session: KeyringSession): void {
    this.#session = session;
    this.#allowed.clear();
  }

  /**
   * ### detach
   *
   * Stops serving keys and forgets every "allow until locked" answer.
   */
  detach(): void {
    this.#session = undefined;
    this.#allowed.clear();
  }

  /**
   * ### list
   *
   * SSH keys in the vault, public parts only.
   *
   * @returns Rows for the window
   */
  async list(): Promise<Array<SshKeyRow>> {
    const session = this.#require();

    await session.sync();

    const vaults = new Map(
      session.listVaults().map((vault) => [vault.id, vault.name]),
    );

    return session.listItems().flatMap((item) => {
      const key = session.getItem(item.id).details.sshKey;

      return key === undefined
        ? []
        : [
            {
              id: item.id,
              title: item.overview.title,
              vaultName: vaults.get(item.vaultId) ?? "",
              fingerprint: key.fingerprint,
              publicKey: key.publicKey,
            },
          ];
    });
  }

  /**
   * ### add
   *
   * Generates an Ed25519 key, or imports an unencrypted private key, into a new item.
   *
   * @param input Vault, title, and the private key to import (generates one when absent)
   * @returns The new item id
   */
  async add(input: {
    vaultId: string;
    title: string;
    privateKey?: string | undefined;
  }): Promise<string> {
    const session = this.#require();
    let sshKey: { privateKey: string; publicKey: string; fingerprint: string };

    if (input.privateKey === undefined || input.privateKey.trim() === "") {
      sshKey = generateEd25519(input.title);
    } else {
      const key = loadSshKey(input.privateKey);

      sshKey = {
        privateKey: input.privateKey,
        publicKey: publicKeyLine(
          key,
          key.comment === "" ? input.title : key.comment,
        ),
        fingerprint: fingerprintOf(key.publicBlob),
      };
    }

    return session.createItem(
      input.vaultId,
      { type: "ssh-key", title: input.title, urls: [], tags: [] },
      { fields: [], passwordHistory: [], sshKey },
    );
  }

  /**
   * ### identities
   *
   * Keys the SSH agent offers: every SSH key item, while unlocked.
   *
   * @returns Identities
   */
  identities(): Promise<ReadonlyArray<AgentIdentity>> {
    return Promise.resolve(
      this.#keys().map(({ title, key }) => ({
        publicBlob: key.publicBlob,
        comment: title,
      })),
    );
  }

  /**
   * ### sign
   *
   * Signs for an SSH client after the user allowed this key (once, or until the vault locks).
   *
   * @param publicBlob Key
   * @param data Data to sign
   * @param flags Request flags
   * @returns Signature, or `undefined` when refused or unknown
   */
  async sign(
    publicBlob: Uint8Array,
    data: Uint8Array,
    flags: number,
  ): Promise<Uint8Array | undefined> {
    const fingerprint = fingerprintOf(publicBlob);
    const entry = this.#keys().find(
      ({ key }) => fingerprintOf(key.publicBlob) === fingerprint,
    );

    if (entry === undefined) {
      return undefined;
    }

    if (!this.#allowed.has(fingerprint)) {
      const session = this.#session;
      const answer = await this.#confirmSigning({
        title: entry.title,
        fingerprint,
      });

      // The vault may have locked, or unlocked as someone else, while the user was deciding
      if (answer === "deny" || this.#session !== session) {
        return undefined;
      }

      if (answer === "session") {
        this.#allowed.add(fingerprint);
      }
    }

    return entry.key.sign(data, flags);
  }

  /**
   * ### #keys
   *
   * Loads the SSH keys of the attached session, skipping any that cannot be read.
   *
   * @returns Keys with their item titles
   */
  #keys(): Array<{ title: string; key: SshKey }> {
    const session = this.#session;

    if (session === undefined) {
      return [];
    }

    return session.listItems().flatMap((item) => {
      const stored = session.getItem(item.id).details.sshKey;

      if (stored === undefined) {
        return [];
      }

      try {
        return [
          { title: item.overview.title, key: loadSshKey(stored.privateKey) },
        ];
      } catch {
        // A key that cannot be loaded is simply not offered
        return [];
      }
    });
  }

  /**
   * ### #require
   *
   * The attached session, or an error when locked.
   *
   * @returns The session
   */
  #require(): KeyringSession {
    if (this.#session === undefined) {
      throw new Error("keymember is locked");
    }

    return this.#session;
  }
}
