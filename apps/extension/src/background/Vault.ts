import {
  certifyInvitedInBackground,
  DeviceTrust,
  fetchTransport,
  logInDevice,
  loginEnded,
  Session,
} from "@keymember/client";
import type { UnlockResult } from "@keymember/client";

import type { ExtensionState } from "../shared/messages.js";
import { extensionDeviceRoots } from "./deviceRoots.js";
import {
  clearUnlockedState,
  loadDevice,
  saveDevice,
  sessionValue,
  setSessionValue,
} from "./storage.js";

const SYNC_MAX_AGE_MS = 30_000;

/**
 * ### FillTarget
 *
 * A frame a fill is aimed at, with the URL the browser reports for it.
 */
export interface FillTarget {
  /**
   * ### tabId
   *
   * Tab of the frame.
   */
  readonly tabId: number;

  /**
   * ### frameId
   *
   * Frame within the tab; 0 is the top frame.
   */
  readonly frameId: number;

  /**
   * ### url
   *
   * Frame URL as reported by the browser, never by the page.
   */
  readonly url: string;
}

/**
 * ### UnlockedSession
 *
 * How the background's other parts reach the unlocked session.
 */
export interface UnlockedSession {
  /**
   * ### current
   *
   * The session as it is, restored after a service worker restart.
   *
   * @returns The session, or `undefined` while locked
   */
  current(): Promise<Session | undefined>;

  /**
   * ### synced
   *
   * The session with a recently synced cache.
   *
   * @returns The session, or `undefined` while locked
   */
  synced(): Promise<Session | undefined>;

  /**
   * ### require
   *
   * The synced session, or an error telling the user to unlock.
   *
   * @returns The session
   */
  require(): Promise<Session>;

  /**
   * ### touch
   *
   * Records user activity for the idle auto-lock.
   */
  touch(): Promise<void>;
}

/**
 * ### Vault
 *
 * The background's single owner of the unlocked session and its lifecycle: unlocking,
 * pinning the owner, locking (on request, when idle, or when the server ends the login) and
 * surviving service worker restarts. Filling, save prompts and passkeys are separate parts
 * that reach the session through {@link UnlockedSession}; popup, menu and content scripts only
 * ever receive what they display or the exact values of one fill.
 */
export class Vault implements UnlockedSession {
  readonly #trust: DeviceTrust;
  readonly #lockListeners: Array<() => Promise<void>> = [];
  #session: Session | undefined;
  #restoring: Promise<Session | undefined> | undefined;
  #lastSync = 0;

  /**
   * ### constructor
   *
   * @param trust How this device trusts the organisation's keys
   */
  constructor(trust = new DeviceTrust(extensionDeviceRoots)) {
    this.#trust = trust;
  }

  /**
   * ### state
   *
   * Lock state and device settings for the popup.
   *
   * @returns Current state
   */
  async state(): Promise<ExtensionState> {
    const device = await loadDevice();
    const session = await this.current();

    return {
      knownDevice: device.secretKey !== undefined,
      pinned: Object.keys(device.roots).length > 0,
      ...(device.serverUrl === undefined
        ? {}
        : { serverUrl: device.serverUrl }),
      ...(device.email === undefined ? {} : { email: device.email }),
      ...(session === undefined
        ? {}
        : { user: { name: session.user.name, email: session.user.email } }),
    };
  }

  /**
   * ### configure
   *
   * Points the extension at a server. Changing servers forgets the account on this device.
   *
   * @param serverUrl Server origin; must be https unless it is localhost
   */
  async configure(serverUrl: string): Promise<void> {
    const origin = new URL(serverUrl).origin;

    // Validates the scheme the same way every request will
    fetchTransport(origin);

    const device = await loadDevice();

    await this.lock();
    await saveDevice(
      device.serverUrl === origin
        ? device
        : { deviceId: device.deviceId, serverUrl: origin, roots: {} },
    );
  }

  /**
   * ### unlock
   *
   * Logs in and keeps the session in memory-only storage. The Secret Key is remembered for
   * next time once a login with it succeeds.
   *
   * @param input Credentials from the popup
   * @returns Success, or a coded failure such as `totp_required`
   */
  async unlock(input: {
    email: string;
    password: string;
    secretKey?: string | undefined;
    totp?: string | undefined;
  }): Promise<UnlockResult> {
    const device = await loadDevice();
    const login = await logInDevice(
      {
        serverUrl: device.serverUrl,
        deviceId: device.deviceId,
        deviceName: "Browser extension",
        storedSecretKey: device.secretKey,
      },
      input,
      // The popup closes when the tab opens; the worker keeps waiting and unlocks on its own
      async (url) => {
        await chrome.tabs.create({ url, active: true });
      },
    );

    if (!login.ok) {
      return login;
    }

    await saveDevice({
      ...device,
      email: login.email,
      secretKey: login.secretKey,
    });
    const trustsOrganisation = await this.#trust.afterUnlock(login.session);

    await this.#adopt(login.session);
    certifyInvitedInBackground(login.session, {
      trustsOrganisation,
      // The service worker has no screen; the admin console shows these failures to the admin
      onError: (error) => {
        console.warn(
          "Certifying members who joined by invite link failed",
          error,
        );
      },
    });

    return { ok: true, recoveryCancelled: login.session.recoveryCancelled };
  }

  /**
   * ### ownerCandidates
   *
   * Owner keys reported by the server, for the user to compare before pinning.
   *
   * @returns Owners with fingerprints
   */
  async ownerCandidates(): Promise<
    Array<{ userId: string; email: string; fingerprint: string }>
  > {
    const session = await this.require();

    return (await session.ownerCandidates()).map(
      ({ userId, email, fingerprint }) => ({ userId, email, fingerprint }),
    );
  }

  /**
   * ### pinOwner
   *
   * Pins the owner key the user confirmed. The key is fetched again here, and pinned only when
   * its fingerprint is the one the user compared, so a server that serves a different key
   * between showing and pinning gets nothing pinned.
   *
   * @param userId Owner the user confirmed
   * @param fingerprint Fingerprint the user compared with the owner
   */
  async pinOwner(userId: string, fingerprint: string): Promise<void> {
    await this.#trust.pinOwner(await this.require(), userId, fingerprint);
    // Vaults shared by others become visible only after a sync with the new roots
    this.#lastSync = 0;
  }

  /**
   * ### onLock
   *
   * Registers work to run whenever the vault locks, however it locks (the popup, idle time, the
   * screen locking, the server ending the login).
   *
   * @param listener Work to run before the session's storage is cleared
   */
  onLock(listener: () => Promise<void>): void {
    this.#lockListeners.push(listener);
  }

  /**
   * ### lock
   *
   * Logs out on the server (best effort) and drops every key and pending credential.
   */
  async lock(): Promise<void> {
    const session = await this.current();

    // From here the session's token listener no longer writes snapshots (see #watchTokens)
    this.#session = undefined;

    for (const listener of this.#lockListeners) {
      // One failing listener must not keep the keys in storage
      await listener().catch(() => undefined);
    }

    await clearUnlockedState();

    if (session !== undefined) {
      // Best effort: the keys are gone locally either way, and the server ends the login on expiry
      await session.logOut().catch(() => undefined);
      // A refresh during logout must not leave anything behind
      await clearUnlockedState();
    }
  }

  /**
   * ### forgetDevice
   *
   * Locks and removes the Secret Key and pinned keys from this browser.
   */
  async forgetDevice(): Promise<void> {
    const device = await loadDevice();

    await this.lock();
    await saveDevice({
      deviceId: device.deviceId,
      roots: {},
      ...(device.serverUrl === undefined
        ? {}
        : { serverUrl: device.serverUrl }),
    });
  }

  /**
   * ### touch
   *
   * Records user activity for the idle auto-lock.
   */
  async touch(): Promise<void> {
    await setSessionValue("lastActivity", Date.now());
  }

  /**
   * ### lockIfIdle
   *
   * Locks when the user has not used the extension for longer than the limit.
   *
   * @param idleLimitMs Allowed inactivity
   */
  async lockIfIdle(idleLimitMs: number): Promise<void> {
    const last = await sessionValue("lastActivity");

    if (typeof last === "number" && Date.now() - last > idleLimitMs) {
      await this.lock();
    }
  }

  /**
   * ### unlockCount
   *
   * How many times the password has been entered since the browser started; it changes on
   * every unlock, so a passkey ceremony can tell whether the user verified during it.
   *
   * @returns The count, or `undefined` while locked
   */
  async unlockCount(): Promise<number | undefined> {
    const count = await sessionValue("unlockCount");

    return (await this.current()) !== undefined && typeof count === "number"
      ? count
      : undefined;
  }

  /**
   * ### current
   *
   * The unlocked session, restoring it from memory-only storage after the service worker restarted.
   *
   * @returns The session, or `undefined` while locked
   */
  async current(): Promise<Session | undefined> {
    if (this.#session !== undefined) {
      return this.#session;
    }

    // Messages arriving together after a restart share one restored session: two would each
    // hold the same single-use refresh token
    this.#restoring ??= this.#restore().finally(() => {
      this.#restoring = undefined;
    });

    return this.#restoring;
  }

  /**
   * ### #restore
   *
   * Rebuilds the session from its memory-only snapshot.
   *
   * @returns The session, or `undefined` while locked
   */
  async #restore(): Promise<Session | undefined> {
    const snapshot = await sessionValue("session");
    const device = await loadDevice();

    if (snapshot === undefined || device.serverUrl === undefined) {
      return undefined;
    }

    try {
      const session = Session.fromSnapshot(
        fetchTransport(device.serverUrl),
        snapshot,
      );

      this.#watchTokens(session);
      await this.#trust.apply(session);
      this.#session = session;
      this.#lastSync = 0;

      return session;
    } catch {
      // A malformed snapshot cannot be repaired; treat the extension as locked
      await setSessionValue("session", undefined);

      return undefined;
    }
  }

  /**
   * ### require
   *
   * The unlocked session, or an error telling the user to unlock.
   *
   * @returns The session
   */
  async require(): Promise<Session> {
    const session = await this.synced();

    if (session === undefined) {
      throw new Error(
        "keymember is locked. Click the extension icon to unlock.",
      );
    }

    return session;
  }

  /**
   * ### synced
   *
   * The session with a cache no older than {@link SYNC_MAX_AGE_MS}.
   *
   * @returns The session, or `undefined` while locked
   */
  async synced(): Promise<Session | undefined> {
    const session = await this.current();

    if (
      session !== undefined &&
      Date.now() - this.#lastSync > SYNC_MAX_AGE_MS
    ) {
      try {
        await session.sync();
        this.#lastSync = Date.now();
      } catch (error) {
        // Only a login the server ended locks; a refusal such as "not certified yet" does not
        if (loginEnded(error)) {
          await this.lock();

          return undefined;
        }

        throw error;
      }
    }

    return session;
  }

  /**
   * ### #adopt
   *
   * Makes a freshly logged-in session current and snapshots it.
   *
   * @param session New session
   */
  async #adopt(session: Session): Promise<void> {
    await this.#trust.apply(session);
    this.#session = session;
    this.#lastSync = 0;
    this.#watchTokens(session);
    await setSessionValue("session", session.toSnapshot());
    await setSessionValue("unlockedAt", Date.now());
    await setSessionValue(
      "unlockCount",
      (Number(await sessionValue("unlockCount")) || 0) + 1,
    );
    await this.touch();
  }

  /**
   * ### #watchTokens
   *
   * Keeps the stored snapshot's tokens current; an old refresh token is single-use.
   *
   * @param session Session to watch
   */
  #watchTokens(session: Session): void {
    session.onTokensChanged(() => {
      // A locked session may still refresh while logging out; its keys must not be stored again
      if (this.#session === session) {
        void setSessionValue("session", session.toSnapshot());
      }
    });
  }
}
