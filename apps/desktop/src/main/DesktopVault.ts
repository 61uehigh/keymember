import {
  certifyInvitedInBackground,
  currentTotpCode,
  fetchTransport,
  hasValidTotp,
  logInDevice,
  loginEnded,
  matchesQuery,
  Session,
} from "@keymember/client";
import type { DeviceTrust } from "@keymember/client";

import type { DesktopState, ItemRow, UnlockResult } from "../shared/ipc.js";
import type { BiometricUnlock } from "./BiometricUnlock.js";
import type { ClipboardGuard } from "./ClipboardGuard.js";
import type { DeviceConfigStore } from "./DeviceConfigStore.js";
import type { AgentBackend } from "./ssh/SshAgent.js";
import type { VaultKeyring } from "./ssh/VaultKeyring.js";

/**
 * ### SYNC_MAX_AGE_MS
 *
 * How old the cached vault may get before a request syncs again: 30 seconds, as in the browser
 * extension, so typing a search does not sync on every keystroke.
 */
const SYNC_MAX_AGE_MS = 30_000;

/**
 * ### LOCKED_MESSAGE
 *
 * What the window shows when a request reaches a locked vault.
 */
const LOCKED_MESSAGE = "keymember is locked. Unlock again to continue.";

/**
 * ### DesktopVaultParts
 *
 * The collaborators a {@link DesktopVault} coordinates, each owning one concern. Each is typed
 * by only the members the vault uses, so a test can hand in any stand-in.
 */
export interface DesktopVaultParts {
  /** What this computer remembers: server, device id, pinned owners, sealed Secret Key */
  readonly config: Pick<
    DeviceConfigStore,
    "current" | "hasSecretKey" | "rememberLogin" | "secretKey" | "switchServer"
  >;
  /** Which organisation keys this computer trusts, and how it comes to trust more */
  readonly trust: Pick<DeviceTrust, "afterUnlock" | "apply" | "pinOwner">;
  /** Touch ID unlock from a sealed session snapshot */
  readonly biometric: Pick<
    BiometricUnlock,
    "available" | "forget" | "isEnabled" | "open" | "seal"
  >;
  /** Copies secrets and takes them off the clipboard again */
  readonly clipboard: Pick<ClipboardGuard, "clearIfUnchanged" | "copy">;
  /** The vault's SSH keys, served to the SSH agent while unlocked */
  readonly keyring: DesktopKeyring;
  /** Opens the identity provider's sign-in page */
  readonly openExternal: (url: string) => void;
}

/**
 * ### DesktopKeyring
 *
 * What the vault and the app need from the SSH keyring: following the session, the window's
 * SSH tab, and the agent.
 */
export type DesktopKeyring = Pick<
  VaultKeyring,
  "add" | "attach" | "detach" | "list"
> &
  AgentBackend;

/**
 * ### DesktopVault
 *
 * The desktop app's vault: owns the one session in the main process and its lifecycle
 * (unlock, lock, pinning the owner) and answers the window's narrow requests. Secrets go to
 * the clipboard from here and never to the window. Storage, Touch ID, the clipboard and SSH
 * keys are delegated to the parts it is given.
 */
export class DesktopVault {
  readonly #parts: DesktopVaultParts;
  readonly #lockListeners = new Set<() => void>();
  #session: Session | undefined;
  #lastSync = 0;
  // A lock in progress; a second lock() waits for it instead of returning early
  #locking: Promise<void> | undefined;
  // Touch ID reseals run one after another, so an older snapshot never overwrites a newer one
  #sealing: Promise<void> = Promise.resolve();

  /**
   * ### constructor
   *
   * Use `createDesktopVault`, which builds the parts from the platform; tests may pass their own.
   *
   * @param parts Collaborators
   */
  constructor(parts: DesktopVaultParts) {
    this.#parts = parts;
  }

  /**
   * ### keyring
   *
   * The vault's SSH keys, for the SSH agent and the window's SSH tab.
   */
  get keyring(): DesktopKeyring {
    return this.#parts.keyring;
  }

  /**
   * ### state
   *
   * What the window shows.
   *
   * @returns The state
   */
  async state(): Promise<DesktopState> {
    const { config, biometric } = this.#parts;
    const device = await config.current();

    return {
      ...(device.serverUrl === undefined
        ? {}
        : { serverUrl: device.serverUrl }),
      ...(device.email === undefined ? {} : { email: device.email }),
      knownDevice: await config.hasSecretKey(),
      pinned: device.roots.size > 0,
      biometricAvailable: biometric.available,
      biometricEnabled: await biometric.isEnabled(),
      ...(this.#session === undefined
        ? {}
        : {
            user: {
              name: this.#session.user.name,
              email: this.#session.user.email,
            },
          }),
    };
  }

  /**
   * ### configure
   *
   * Sets the server address. Changing servers forgets the account on this computer: the
   * pinned owner keys, Secret Key and Touch ID snapshot all belong to the old organization.
   *
   * @param serverUrl keymember server URL
   */
  async configure(serverUrl: string): Promise<void> {
    const url = new URL(serverUrl);

    if (
      url.protocol !== "https:" &&
      url.hostname !== "localhost" &&
      url.hostname !== "127.0.0.1"
    ) {
      throw new Error("The server URL must start with https.");
    }

    if ((await this.#parts.config.current()).serverUrl === url.origin) {
      return;
    }

    // Without the snapshot, locking also ends the login on the old server
    await this.#parts.biometric.forget();
    await this.lock();
    await this.#parts.config.switchServer(url.origin);
  }

  /**
   * ### unlock
   *
   * Logs in with password and Secret Key (and the identity provider, when the organisation
   * requires it).
   *
   * @param input Credentials
   * @returns Whether it worked, and why not
   */
  async unlock(input: {
    email: string;
    password: string;
    secretKey?: string | undefined;
    totp?: string | undefined;
  }): Promise<UnlockResult> {
    const { config, openExternal } = this.#parts;
    const device = await config.current();
    const login = await logInDevice(
      {
        serverUrl: device.serverUrl,
        deviceId: device.deviceId,
        deviceName: "keymember desktop",
        storedSecretKey:
          input.secretKey === undefined ? await config.secretKey() : undefined,
      },
      input,
      openExternal,
    );

    if (!login.ok) {
      return login;
    }

    await config.rememberLogin(login.email, login.secretKey);

    const trustsOrganisation = await this.#parts.trust.afterUnlock(
      login.session,
    );

    await this.#adopt(login.session, Date.now());
    certifyInvitedInBackground(login.session, {
      trustsOrganisation,
      onError: (error) => {
        console.warn("keymember: certifying invited members failed", error);
      },
    });

    return { ok: true, recoveryCancelled: login.session.recoveryCancelled };
  }

  /**
   * ### unlockWithBiometric
   *
   * Unlocks with Touch ID from the sealed session snapshot. Falls back to the password when the
   * snapshot is too old, cannot be opened, or the server ended that login.
   *
   * @returns Whether it worked
   */
  async unlockWithBiometric(): Promise<UnlockResult> {
    const { config, biometric } = this.#parts;
    const { serverUrl } = await config.current();

    if (serverUrl === undefined) {
      return {
        ok: false,
        code: "unavailable",
        message: "Touch ID isn't available.",
      };
    }

    const opened = await biometric.open();

    if (!opened.ok) {
      return opened;
    }

    let session: Session;

    try {
      session = Session.fromSnapshot(
        fetchTransport(serverUrl),
        opened.snapshot,
      );
    } catch {
      // A snapshot this version cannot read is useless from now on
      return this.#forgetBiometric();
    }

    try {
      await this.#parts.trust.apply(session);
      // Proves the login is still alive (and refreshes tokens) before calling it unlocked
      await session.sync();
      await this.#adopt(session, opened.passwordAt);

      return { ok: true, recoveryCancelled: false };
    } catch (error) {
      if (loginEnded(error)) {
        // The server ended that login; its snapshot can never unlock again
        return this.#forgetBiometric();
      }

      // Offline or the server is restarting: keep Touch ID for the next try
      return {
        ok: false,
        code: "offline",
        message:
          "Can't connect to the server. Check your network and try again.",
      };
    }
  }

  /**
   * ### setBiometric
   *
   * Turns Touch ID unlock on (sealing the current session) or off.
   *
   * @param enabled Whether to enable
   */
  async setBiometric(enabled: boolean): Promise<void> {
    if (!enabled) {
      await this.#parts.biometric.forget();

      return;
    }

    await this.#queueSeal(this.#require(), Date.now());
  }

  /**
   * ### lock
   *
   * Drops the keys from memory. With Touch ID on, the server login is kept for the sealed
   * snapshot; otherwise it is ended too.
   */
  lock(): Promise<void> {
    this.#locking ??= this.#lockNow().finally(() => {
      this.#locking = undefined;
    });

    return this.#locking;
  }

  /**
   * ### onLocked
   *
   * Calls `listener` whenever an unlocked vault locks, for whatever reason: the user, the
   * computer locking or sleeping, idle time, or the server ending the login.
   *
   * @param listener Called after locking
   */
  onLocked(listener: () => void): void {
    this.#lockListeners.add(listener);
  }

  /**
   * ### settle
   *
   * Waits for work that must finish before the app quits: a pending Touch ID reseal and
   * clearing a copied secret.
   */
  async settle(): Promise<void> {
    await this.#sealing;
    await this.#parts.clipboard.clearIfUnchanged();
  }

  /**
   * ### ownerCandidates
   *
   * Owners whose key can be pinned after comparing fingerprints.
   *
   * @returns Candidates
   */
  async ownerCandidates(): Promise<
    Array<{ userId: string; email: string; fingerprint: string }>
  > {
    const candidates = await this.#guarded((session) =>
      session.ownerCandidates(),
    );

    return candidates.map(({ userId, email, fingerprint }) => ({
      userId,
      email,
      fingerprint,
    }));
  }

  /**
   * ### pinOwner
   *
   * Pins the owner key whose fingerprint the user compared.
   *
   * @param userId Owner
   * @param fingerprint Fingerprint the user compared
   */
  async pinOwner(userId: string, fingerprint: string): Promise<void> {
    await this.#guarded(async (session) => {
      await this.#parts.trust.pinOwner(session, userId, fingerprint);
      // Grants from others count only now that the owner is trusted
      await session.sync();
      this.#lastSync = Date.now();
    });
  }

  /**
   * ### search
   *
   * Items whose title or URL contains the query.
   *
   * @param query Search text
   * @returns Matching rows, never a secret
   */
  async search(query: string): Promise<Array<ItemRow>> {
    const session = await this.#synced();

    const vaults = new Map(
      session.listVaults().map((vault) => [vault.id, vault.name]),
    );

    return session
      .listItems()
      .filter((item) => matchesQuery(item, query))
      .slice(0, 100)
      .map((item) => {
        const { details } = session.getItem(item.id);

        return {
          id: item.id,
          title: item.overview.title,
          type: item.overview.type,
          vaultName: vaults.get(item.vaultId) ?? "",
          ...(details.username === undefined
            ? {}
            : { username: details.username }),
          hasPassword: details.password !== undefined,
          hasTotp: hasValidTotp(details),
        };
      });
  }

  /**
   * ### copy
   *
   * Copies an item's field to the clipboard, which is cleared 30 seconds later if unchanged.
   *
   * @param itemId Item
   * @param field Field to copy
   */
  copy(
    itemId: string,
    field: "username" | "password" | "totp" | "publicKey",
  ): void {
    const { details } = this.#require().getItem(itemId);
    const value =
      field === "totp"
        ? currentTotpCode(details)
        : field === "publicKey"
          ? details.sshKey?.publicKey
          : details[field];

    if (value === undefined) {
      throw new Error("This item doesn't have that field.");
    }

    this.#parts.clipboard.copy(value);
  }

  /**
   * ### clearClipboardIfUnchanged
   *
   * Empties the clipboard if it still holds the last copied secret.
   */
  clearClipboardIfUnchanged(): Promise<void> {
    return this.#parts.clipboard.clearIfUnchanged();
  }

  /**
   * ### addSshKey
   *
   * Adds an SSH key item to a vault, locking first if the server ended the login.
   *
   * @param input Vault, title and an optional private key to import
   * @returns The new item's id
   */
  addSshKey(input: {
    vaultId: string;
    title: string;
    privateKey?: string | undefined;
  }): Promise<string> {
    return this.#guarded(() => this.#parts.keyring.add(input));
  }

  /**
   * ### writableVaults
   *
   * Vaults the user may add items to.
   *
   * @returns Vault ids and names
   */
  writableVaults(): Array<{ id: string; name: string }> {
    return this.#require()
      .listVaults()
      .filter((vault) => vault.permission !== "view")
      .map((vault) => ({ id: vault.id, name: vault.name }));
  }

  /**
   * ### #adopt
   *
   * Makes a session current, hands it to the keyring, and keeps the Touch ID snapshot's
   * tokens up to date.
   *
   * @param session Unlocked session
   * @param passwordAt When the password was last entered
   */
  async #adopt(session: Session, passwordAt: number): Promise<void> {
    const { biometric, keyring, trust } = this.#parts;

    await trust.apply(session);
    this.#session = session;
    keyring.attach(session);
    // The server refused the refresh token: lock rather than keep showing a dead login
    session.onEnded(() => {
      if (this.#session === session) {
        void this.lock();
      }
    });
    session.onTokensChanged(() => {
      // Only the session in use keeps the snapshot current; a locked one must not reseal it
      if (this.#session === session) {
        void this.#queueSeal(session, passwordAt, true);
      }
    });

    if (await biometric.isEnabled()) {
      await this.#queueSeal(session, passwordAt);
    }

    await session.sync();
    this.#lastSync = Date.now();
  }

  /**
   * ### #lockNow
   *
   * Does the locking for {@link DesktopVault.lock}, and tells the listeners once it is done.
   */
  async #lockNow(): Promise<void> {
    const session = this.#session;

    this.#session = undefined;
    this.#lastSync = 0;
    this.#parts.keyring.detach();
    await this.#parts.clipboard.clearIfUnchanged();

    if (session !== undefined && !(await this.#parts.biometric.isEnabled())) {
      // Best effort: the keys already left memory, and an unreachable server ends the login itself
      await session.logOut().catch(() => undefined);
    }

    if (session !== undefined) {
      for (const listener of this.#lockListeners) {
        listener();
      }
    }
  }

  /**
   * ### #queueSeal
   *
   * Reseals the Touch ID snapshot after any reseal already running.
   *
   * @param session Session to snapshot
   * @param passwordAt When the password was last entered
   * @param onlyIfEnabled Whether to skip it when Touch ID unlock is off
   * @returns When this reseal is written
   */
  #queueSeal(
    session: Session,
    passwordAt: number,
    onlyIfEnabled = false,
  ): Promise<void> {
    const { biometric } = this.#parts;
    const next = this.#sealing.then(async () => {
      if (!onlyIfEnabled || (await biometric.isEnabled())) {
        await biometric.seal(session, passwordAt);
      }
    });

    // A failed reseal leaves the previous snapshot; the next token change tries again
    this.#sealing = next.catch((error: unknown) => {
      console.warn("keymember: resealing the Touch ID snapshot failed", error);
    });

    return next;
  }

  /**
   * ### #forgetBiometric
   *
   * Deletes a Touch ID snapshot that can never unlock again, and says to use the password.
   *
   * @returns The failure to show
   */
  async #forgetBiometric(): Promise<UnlockResult> {
    await this.#parts.biometric.forget();

    return {
      ok: false,
      code: "password_required",
      message: "Unlock with your password.",
    };
  }

  /**
   * ### #synced
   *
   * The session with a cache at most {@link SYNC_MAX_AGE_MS} old.
   *
   * @returns The session
   */
  async #synced(): Promise<Session> {
    return this.#guarded(async (session) => {
      if (Date.now() - this.#lastSync > SYNC_MAX_AGE_MS) {
        await session.sync();
        this.#lastSync = Date.now();
      }

      return session;
    });
  }

  /**
   * ### #guarded
   *
   * Runs work against the session and locks when the server says the login has ended, so the
   * window does not keep showing a vault the server no longer serves.
   *
   * @param work Work that talks to the server
   * @returns Whatever the work returns
   */
  async #guarded<T>(work: (session: Session) => Promise<T>): Promise<T> {
    try {
      return await work(this.#require());
    } catch (error) {
      if (loginEnded(error)) {
        await this.lock();
        throw new Error("Your session has ended. Unlock again to continue.", {
          cause: error,
        });
      }

      throw error;
    }
  }

  /**
   * ### #require
   *
   * The unlocked session, or an error when locked.
   *
   * @returns The session
   */
  #require(): Session {
    if (this.#session === undefined) {
      throw new Error(LOCKED_MESSAGE);
    }

    return this.#session;
  }
}
