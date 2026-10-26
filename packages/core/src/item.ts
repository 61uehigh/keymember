import { isRecord, readBytes } from "./cbor.js";
import type { CborValue } from "./cbor.js";
import { openValue, sealValue } from "./envelope.js";
import { MalformedDataError } from "./errors.js";
import { generateSymmetricKey, symmetricKeyFromBytes } from "./SymmetricKey.js";
import type { SymmetricKey } from "./SymmetricKey.js";

/**
 * ### ItemType
 *
 * Kinds of item a vault can hold. The type is encrypted inside the overview, so the
 * server cannot tell a login from a secure note.
 */
export type ItemType = "login" | "secure-note" | "api-credential" | "ssh-key";

/**
 * ### ItemOverview
 *
 * Fields needed to list, search and URL-match items. Decrypted for every item when the
 * vault opens, so it must stay small and never hold a secret.
 */
export interface ItemOverview {
  /**
   * ### type
   *
   * Kind of item.
   */
  readonly type: ItemType;

  /**
   * ### title
   *
   * Display title.
   */
  readonly title: string;

  /**
   * ### urls
   *
   * Sites the item fills on; empty for items that are not web logins.
   */
  readonly urls: ReadonlyArray<string>;

  /**
   * ### tags
   *
   * Free-form labels for search and grouping.
   */
  readonly tags: ReadonlyArray<string>;
}

/**
 * ### CustomField
 *
 * A user-defined field, for example a PIN or a recovery code.
 */
export interface CustomField {
  /**
   * ### label
   *
   * Field label as shown to the user.
   */
  readonly label: string;

  /**
   * ### value
   *
   * Field value.
   */
  readonly value: string;

  /**
   * ### concealed
   *
   * Whether the value is hidden by default in the UI, like a password.
   */
  readonly concealed: boolean;
}

/**
 * ### PasswordHistoryEntry
 *
 * A previous password kept so a mistaken change can be undone.
 */
export interface PasswordHistoryEntry {
  /**
   * ### password
   *
   * The replaced password.
   */
  readonly password: string;

  /**
   * ### replacedAt
   *
   * When the password was replaced, as an ISO 8601 timestamp.
   */
  readonly replacedAt: string;
}

/**
 * ### StoredPasskey
 *
 * A WebAuthn credential (passkey) kept inside an item's encrypted details. Binary values are
 * base64url text so the item stays plain JSON-compatible CBOR.
 */
export interface StoredPasskey {
  /**
   * ### credentialId
   *
   * Credential id the relying party stores, base64url.
   */
  readonly credentialId: string;

  /**
   * ### rpId
   *
   * Relying party id (a domain) the credential is scoped to.
   */
  readonly rpId: string;

  /**
   * ### userHandle
   *
   * Relying party's user id, base64url. Returned on sign-in for discoverable credentials.
   */
  readonly userHandle: string;

  /**
   * ### userName
   *
   * Account name the relying party supplied, shown when picking a passkey.
   */
  readonly userName: string;

  /**
   * ### userDisplayName
   *
   * Display name the relying party supplied.
   */
  readonly userDisplayName: string;

  /**
   * ### privateKey
   *
   * P-256 private scalar (32 bytes), base64url. Exists only inside the encrypted item.
   */
  readonly privateKey: string;

  /**
   * ### createdAt
   *
   * Creation time, ISO 8601.
   */
  readonly createdAt: string;
}

/**
 * ### ItemDetails
 *
 * Secret fields, decrypted only when a single item is opened or filled.
 * Absent fields are omitted rather than stored as empty strings.
 */
export interface ItemDetails {
  /**
   * ### username
   *
   * Login user name or email.
   */
  readonly username?: string;

  /**
   * ### password
   *
   * Current password or secret value.
   */
  readonly password?: string;

  /**
   * ### totp
   *
   * TOTP secret as an `otpauth://` URI or base32 seed.
   */
  readonly totp?: string;

  /**
   * ### notes
   *
   * Free-form notes.
   */
  readonly notes?: string;

  /**
   * ### fields
   *
   * User-defined fields in display order.
   */
  readonly fields: ReadonlyArray<CustomField>;

  /**
   * ### passwordHistory
   *
   * Previous passwords, newest first.
   */
  readonly passwordHistory: ReadonlyArray<PasswordHistoryEntry>;

  /**
   * ### passkeys
   *
   * Passkeys stored on the item. Absent on items written before passkey support.
   */
  readonly passkeys?: ReadonlyArray<StoredPasskey>;

  /**
   * ### sshKey
   *
   * The key of an `ssh-key` item. The desktop app's SSH agent signs with it; it never leaves
   * the item in plaintext otherwise.
   */
  readonly sshKey?: StoredSshKey;
}

/**
 * ### StoredSshKey
 *
 * An SSH key kept in an item.
 */
export interface StoredSshKey {
  /**
   * ### privateKey
   *
   * Unencrypted private key text: OpenSSH (`BEGIN OPENSSH PRIVATE KEY`) or PEM (PKCS#8,
   * PKCS#1 or SEC1). The item's encryption is what protects it.
   */
  readonly privateKey: string;

  /**
   * ### publicKey
   *
   * Public key in `authorized_keys` form, e.g. `ssh-ed25519 AAAA… comment`.
   */
  readonly publicKey: string;

  /**
   * ### fingerprint
   *
   * `SHA256:…` fingerprint, as `ssh-keygen -l` prints it.
   */
  readonly fingerprint: string;
}

/**
 * ### EncryptedItem
 *
 * An item as stored on the server.
 */
export interface EncryptedItem {
  /**
   * ### id
   *
   * Identifier of the item.
   */
  readonly id: string;

  /**
   * ### vaultId
   *
   * Vault the item belongs to.
   */
  readonly vaultId: string;

  /**
   * ### encryptedItemKey
   *
   * The per-item key sealed under the vault key. Moving an item to another vault
   * re-seals only this field.
   */
  readonly encryptedItemKey: Uint8Array;

  /**
   * ### encryptedOverview
   *
   * {@link ItemOverview} sealed under the item key.
   */
  readonly encryptedOverview: Uint8Array;

  /**
   * ### encryptedDetails
   *
   * {@link ItemDetails} sealed under the item key.
   */
  readonly encryptedDetails: Uint8Array;
}

/**
 * ### toCborValue
 *
 * Drops object keys whose value is `undefined`, which CBOR cannot encode, so optional fields
 * are omitted. Bytes stay bytes; an `undefined` array element becomes `null`, as it did when
 * this went through JSON, so earlier items encode the same way.
 *
 * @param value Item overview or details
 * @returns The same value, encodable as CBOR
 */
function toCborValue(value: unknown): CborValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    value instanceof Uint8Array
  ) {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("Item fields must hold finite numbers");
    }

    return value;
  }

  if (Array.isArray(value)) {
    return value.map((element: unknown) =>
      element === undefined ? null : toCborValue(element),
    );
  }

  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, field]) => field !== undefined)
        .map(([key, field]) => [key, toCborValue(field)]),
    );
  }

  throw new TypeError(`Item fields cannot hold a ${typeof value}`);
}

/**
 * ### sealItemKey
 *
 * Seals a per-item key under a vault key, pinned to the vault and item.
 *
 * @param vaultKey Key of the vault holding the item
 * @param vaultId Identifier of the vault
 * @param itemId Identifier of the item
 * @param itemKey Per-item key to seal
 * @returns The sealed item key
 */
export function sealItemKey(
  vaultKey: SymmetricKey,
  vaultId: string,
  itemId: string,
  itemKey: SymmetricKey,
): Uint8Array {
  return sealValue(
    vaultKey,
    { id: itemKey.id, key: itemKey.bytes },
    { kind: "item.key", scope: [vaultId, itemId] },
  );
}

/**
 * ### openItemKey
 *
 * Opens the per-item key of an encrypted item.
 *
 * @param vaultKey Key of the vault holding the item
 * @param item Encrypted item
 * @returns The per-item key
 */
export function openItemKey(
  vaultKey: SymmetricKey,
  item: EncryptedItem,
): SymmetricKey {
  const value = openValue(vaultKey, item.encryptedItemKey, {
    kind: "item.key",
    scope: [item.vaultId, item.id],
  });

  if (!isRecord(value)) {
    throw new MalformedDataError("Item key payload is not a map");
  }

  return symmetricKeyFromBytes(readBytes(value, "id"), readBytes(value, "key"));
}

/**
 * ### encryptItem
 *
 * Encrypts an item for storage. A new per-item key is generated unless the caller passes the
 * existing one, which an edit should do so the item key stays stable across revisions.
 *
 * @param vaultKey Key of the vault holding the item
 * @param ids Identifiers of the vault and item
 * @param overview Listing fields
 * @param details Secret fields
 * @param itemKey Existing per-item key to reuse on edit; omit when creating
 * @returns The encrypted item ready to upload
 */
export function encryptItem(
  vaultKey: SymmetricKey,
  ids: { vaultId: string; itemId: string },
  overview: ItemOverview,
  details: ItemDetails,
  itemKey: SymmetricKey = generateSymmetricKey(),
): EncryptedItem {
  return {
    id: ids.itemId,
    vaultId: ids.vaultId,
    encryptedItemKey: sealItemKey(vaultKey, ids.vaultId, ids.itemId, itemKey),
    encryptedOverview: sealValue(itemKey, toCborValue(overview), {
      kind: "item.overview",
      scope: [ids.itemId],
    }),
    encryptedDetails: sealValue(itemKey, toCborValue(details), {
      kind: "item.details",
      scope: [ids.itemId],
    }),
  };
}

/**
 * ### decryptItemOverview
 *
 * Decrypts only the listing fields of an item.
 * The payload is authenticated but its shape is trusted as written by a keymember client.
 *
 * @param itemKey Per-item key from {@link openItemKey}
 * @param item Encrypted item
 * @returns The item overview
 */
export function decryptItemOverview(
  itemKey: SymmetricKey,
  item: EncryptedItem,
): ItemOverview {
  const value = openValue(itemKey, item.encryptedOverview, {
    kind: "item.overview",
    scope: [item.id],
  });

  if (
    !isRecord(value) ||
    typeof value.title !== "string" ||
    typeof value.type !== "string"
  ) {
    throw new MalformedDataError("Item overview has the wrong shape");
  }

  // The envelope authenticated this payload as written by a keymember client holding the item key
  return value as unknown as ItemOverview;
}

/**
 * ### decryptItemDetails
 *
 * Decrypts the secret fields of an item.
 * The payload is authenticated but its shape is trusted as written by a keymember client.
 *
 * @param itemKey Per-item key from {@link openItemKey}
 * @param item Encrypted item
 * @returns The item details
 */
export function decryptItemDetails(
  itemKey: SymmetricKey,
  item: EncryptedItem,
): ItemDetails {
  const value = openValue(itemKey, item.encryptedDetails, {
    kind: "item.details",
    scope: [item.id],
  });

  if (
    !isRecord(value) ||
    !Array.isArray(value.fields) ||
    !Array.isArray(value.passwordHistory)
  ) {
    throw new MalformedDataError("Item details have the wrong shape");
  }

  // The envelope authenticated this payload as written by a keymember client holding the item key
  return value as unknown as ItemDetails;
}
