import type { StoredPasskey } from "@keymember/core";

import type { Autofill } from "./Autofill.js";
import type { UnlockedSession } from "./Vault.js";

/**
 * ### PasskeyStore
 *
 * Passkeys kept in vault items: which ones a site may use, which items a new one can join,
 * reading one for signing, and saving a new one.
 */
export class PasskeyStore {
  readonly #session: UnlockedSession;
  readonly #autofill: Pick<Autofill, "rowsFor">;

  /**
   * ### constructor
   *
   * @param session The unlocked session, when there is one
   * @param autofill Matches items to the requesting site
   */
  constructor(session: UnlockedSession, autofill: Pick<Autofill, "rowsFor">) {
    this.#session = session;
    this.#autofill = autofill;
  }

  /**
   * ### passkeyCandidates
   *
   * Stored passkeys for a relying party, limited to the allowed credential ids when the site gave any.
   *
   * @param rpId Relying party id
   * @param allowIds Allowed credential ids (base64url); empty means any discoverable credential
   * @returns Choices for the consent window, without private keys
   */
  async passkeyCandidates(
    rpId: string,
    allowIds: ReadonlyArray<string>,
  ): Promise<
    Array<{
      itemId: string;
      title: string;
      userName: string;
      credentialId: string;
    }>
  > {
    const session = await this.#session.synced();

    if (session === undefined) {
      return [];
    }

    return session.listItems().flatMap((item) => {
      const { details } = session.getItem(item.id);

      return (details.passkeys ?? [])
        .filter(
          (passkey) =>
            passkey.rpId === rpId &&
            (allowIds.length === 0 || allowIds.includes(passkey.credentialId)),
        )
        .map((passkey) => ({
          itemId: item.id,
          title: item.overview.title,
          userName: passkey.userName,
          credentialId: passkey.credentialId,
        }));
    });
  }

  /**
   * ### passkeyTargets
   *
   * Login items for the requesting site, which a new passkey can be added to.
   *
   * @param origin Origin of the requesting page
   * @returns Items with their user names
   */
  async passkeyTargets(
    origin: string,
  ): Promise<Array<{ itemId: string; title: string; username?: string }>> {
    return (await this.#autofill.rowsFor(origin))
      .filter((row) => !row.insecure)
      .map((row) => ({
        itemId: row.id,
        title: row.title,
        ...(row.username === undefined ? {} : { username: row.username }),
      }));
  }

  /**
   * ### writableVaults
   *
   * Vaults the user may add items to.
   *
   * @returns Vault ids and names
   */
  async writableVaults(): Promise<Array<{ id: string; name: string }>> {
    const session = await this.#session.synced();

    return (session?.listVaults() ?? [])
      .filter((vault) => vault.permission !== "view")
      .map((vault) => ({ id: vault.id, name: vault.name }));
  }

  /**
   * ### findPasskey
   *
   * Reads one stored passkey, private key included, for signing in the background.
   *
   * @param itemId Item holding the passkey
   * @param credentialId Credential id (base64url)
   * @returns The passkey, or `undefined` when it does not exist
   */
  async findPasskey(
    itemId: string,
    credentialId: string,
  ): Promise<StoredPasskey | undefined> {
    const session = await this.#session.require();

    return session
      .getItem(itemId)
      .details.passkeys?.find(
        (passkey) => passkey.credentialId === credentialId,
      );
  }

  /**
   * ### storePasskey
   *
   * Saves a new passkey, either on an existing item or as a new login item.
   *
   * @param passkey Passkey to store
   * @param origin Origin of the page that registered it
   * @param target Existing item, or vault for a new item
   */
  async storePasskey(
    passkey: StoredPasskey,
    origin: string,
    target: { itemId?: string; vaultId?: string },
  ): Promise<void> {
    const session = await this.#session.require();

    if (target.itemId !== undefined) {
      const { overview, details } = session.getItem(target.itemId);

      await session.updateItem(target.itemId, overview, {
        ...details,
        passkeys: [...(details.passkeys ?? []), passkey],
      });

      return;
    }

    if (target.vaultId === undefined) {
      throw new Error("Choose a vault to save the passkey to.");
    }

    await session.createItem(
      target.vaultId,
      { type: "login", title: passkey.rpId, urls: [origin], tags: ["passkey"] },
      {
        username: passkey.userName,
        fields: [],
        passwordHistory: [],
        passkeys: [passkey],
      },
    );
  }
}
