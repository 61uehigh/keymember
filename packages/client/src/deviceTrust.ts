import { confirmOwnerKey } from "./deviceLogin.js";
import type { Session } from "./Session.js";
import type { InvitedCertification } from "./Session.type.js";

/**
 * ### DeviceRoots
 *
 * Where one device keeps the organisation keys it trusts. Each app stores them its own way
 * (browser storage, a config file); {@link DeviceTrust} only reads and adds to them.
 */
export interface DeviceRoots {
  /**
   * ### current
   *
   * The keys this device trusts now.
   *
   * @returns Pinned signing keys by user id
   */
  current(): Promise<ReadonlyMap<string, Uint8Array>>;

  /**
   * ### pin
   *
   * Adds keys to the ones this device trusts.
   *
   * @param roots Signing keys by user id
   */
  pin(roots: ReadonlyMap<string, Uint8Array>): Promise<void>;
}

/**
 * ### TrustedSession
 *
 * What {@link DeviceTrust} needs from a session.
 */
export type TrustedSession = Pick<
  Session,
  "ownerCandidates" | "saveTrustedRoots" | "setRoots" | "storedTrustedRoots"
>;

/**
 * ### DeviceTrust
 *
 * How a device comes to trust the organisation's keys, the same in every app: from an invite
 * link, from the roots the account saved on another device, or from a fingerprint the user
 * compared. Whichever way, the session trusts exactly what the device has pinned, and roots the
 * user pinned are saved for the account's other devices.
 */
export class DeviceTrust {
  readonly #roots: DeviceRoots;

  /**
   * ### constructor
   *
   * @param roots The device's pinned keys
   */
  constructor(roots: DeviceRoots) {
    this.#roots = roots;
  }

  /**
   * ### afterUnlock
   *
   * Call right after logging in. A device that trusts nothing yet adopts the roots the account
   * saved, if their signature checks out; then the session trusts the device's roots.
   *
   * @param session Freshly logged-in session
   * @returns Whether the device trusts any organisation key; without one, ask the user to compare
   * the owner's fingerprint ({@link DeviceTrust.pinOwner})
   */
  async afterUnlock(session: TrustedSession): Promise<boolean> {
    if ((await this.#roots.current()).size === 0) {
      const saved = await session.storedTrustedRoots();

      if (saved !== undefined) {
        await this.#roots.pin(saved);
      }
    }

    return (await this.apply(session)).size > 0;
  }

  /**
   * ### apply
   *
   * Makes a session trust exactly the roots this device has pinned, for a session restored
   * from a snapshot or adopted again.
   *
   * @param session Session to configure
   * @returns The roots it now trusts
   */
  async apply(
    session: Pick<TrustedSession, "setRoots">,
  ): Promise<ReadonlyMap<string, Uint8Array>> {
    const roots = await this.#roots.current();

    session.setRoots(roots);

    return roots;
  }

  /**
   * ### pinOwner
   *
   * Pins the owner's key after the user compared its fingerprint, and saves the roots for the
   * account's other devices. The key is fetched again here, so a server that serves a different
   * key between showing and pinning gets nothing pinned.
   *
   * @param session Unlocked session
   * @param userId Owner the user confirmed
   * @param fingerprint Fingerprint the user compared
   */
  async pinOwner(
    session: TrustedSession,
    userId: string,
    fingerprint: string,
  ): Promise<void> {
    const key = await confirmOwnerKey(session, userId, fingerprint);

    await this.#adopt(session, new Map([[userId, key]]));
  }

  /**
   * ### adoptRoots
   *
   * Pins roots that need no fingerprint check, and saves them for the account's other devices:
   * the ones an invite link carried (it came from an admin over email or chat, not from the
   * server), or the owner's own key right after creating the organisation.
   *
   * @param session Unlocked session
   * @param roots Roots to trust
   */
  async adoptRoots(
    session: TrustedSession,
    roots: ReadonlyMap<string, Uint8Array>,
  ): Promise<void> {
    await this.#adopt(session, roots);
  }

  /**
   * ### #adopt
   *
   * Pins roots on the device, makes the session trust them and saves them for other devices.
   *
   * @param session Unlocked session
   * @param roots Roots to add
   */
  async #adopt(
    session: TrustedSession,
    roots: ReadonlyMap<string, Uint8Array>,
  ): Promise<void> {
    await this.#roots.pin(roots);
    await this.apply(session);
    await session.saveTrustedRoots();
  }
}

/**
 * ### certifyInvitedInBackground
 *
 * For an admin's session, certifies the members who joined through the admin's invite links,
 * without waiting or failing the caller. Members' sessions, and devices that trust no
 * organisation key yet (where every invite would fail verification), are left alone.
 *
 * @param session Unlocked session
 * @param options Whether the device trusts the organisation's keys ({@link DeviceTrust.afterUnlock}
 * says), and where to report the outcome and errors
 */
export function certifyInvitedInBackground(
  session: Pick<Session, "orgAdmin" | "user">,
  options: {
    readonly trustsOrganisation: boolean;
    readonly onResult?: (result: InvitedCertification) => void;
    readonly onError?: (error: unknown) => void;
  },
): void {
  if (session.user.role === "member" || !options.trustsOrganisation) {
    return;
  }

  void session
    .orgAdmin()
    .certifyInvited()
    .then(
      (result) => {
        options.onResult?.(result);
      },
      (error: unknown) => {
        // Reported, not thrown: this runs on its own, and the next unlock or timer tries again
        options.onError?.(error);
      },
    );
}
