import { isRecord, readString } from "./cbor.js";
import { openValue, sealValue } from "./envelope.js";
import { MalformedDataError } from "./errors.js";
import { unwrapKey, wrapKey } from "./keyWrap.js";
import type { EncryptionKeyPair } from "./keyWrap.js";
import { generateSymmetricKey } from "./SymmetricKey.js";
import type { SymmetricKey } from "./SymmetricKey.js";

/**
 * ### VaultKeyRecipient
 *
 * A principal a vault key is wrapped to: a user, a group, or the recovery group.
 */
export interface VaultKeyRecipient {
  /**
   * ### principalId
   *
   * Identifier of the user or group receiving the key.
   */
  readonly principalId: string;

  /**
   * ### encryptionPublicKey
   *
   * X25519 public key of the principal. Callers must have verified it through a
   * member certificate (users) or group certificate before wrapping to it.
   */
  readonly encryptionPublicKey: Uint8Array;
}

/**
 * ### generateVaultKey
 *
 * Generates the key for a new vault or for the next key generation after a rotation.
 *
 * @returns A fresh vault key
 */
export function generateVaultKey(): SymmetricKey {
  return generateSymmetricKey();
}

/**
 * ### wrapVaultKey
 *
 * Wraps a vault key for one principal, pinned to the vault, the key generation and the principal.
 *
 * @param vaultKey Vault key to share
 * @param vaultId Identifier of the vault
 * @param keyGeneration Generation of the vault key, incremented on every rotation
 * @param recipient Principal receiving access
 * @returns The serialised wrapped key to upload as the principal's vault access
 */
export async function wrapVaultKey(
  vaultKey: SymmetricKey,
  vaultId: string,
  keyGeneration: number,
  recipient: VaultKeyRecipient,
): Promise<Uint8Array> {
  return wrapKey(vaultKey, recipient.encryptionPublicKey, {
    purpose: "vault-key",
    scope: [vaultId, keyGeneration, recipient.principalId],
  });
}

/**
 * ### unwrapVaultKey
 *
 * Unwraps a vault key received as a vault access entry.
 * Throws {@link DecryptionError} when the entry was wrapped for another vault, generation or principal.
 *
 * @param wrapped Wrapped key from the vault access entry
 * @param vaultId Identifier of the vault
 * @param keyGeneration Generation recorded on the vault access entry
 * @param principalId Principal the entry claims to be for
 * @param keyPair The principal's X25519 key pair
 * @returns The vault key
 */
export async function unwrapVaultKey(
  wrapped: Uint8Array,
  vaultId: string,
  keyGeneration: number,
  principalId: string,
  keyPair: EncryptionKeyPair,
): Promise<SymmetricKey> {
  return unwrapKey(wrapped, keyPair, {
    purpose: "vault-key",
    scope: [vaultId, keyGeneration, principalId],
  });
}

/**
 * ### sealVaultName
 *
 * Encrypts a vault's display name under its vault key.
 *
 * @param vaultKey Key of the vault
 * @param vaultId Identifier of the vault
 * @param name Display name to encrypt
 * @returns The sealed name
 */
export function sealVaultName(
  vaultKey: SymmetricKey,
  vaultId: string,
  name: string,
): Uint8Array {
  return sealValue(
    vaultKey,
    { name },
    { kind: "vault.name", scope: [vaultId] },
  );
}

/**
 * ### openVaultName
 *
 * Decrypts a vault's display name.
 *
 * @param vaultKey Key of the vault
 * @param vaultId Identifier of the vault
 * @param sealedName Sealed name from the server
 * @returns The display name
 */
export function openVaultName(
  vaultKey: SymmetricKey,
  vaultId: string,
  sealedName: Uint8Array,
): string {
  const value = openValue(vaultKey, sealedName, {
    kind: "vault.name",
    scope: [vaultId],
  });

  if (!isRecord(value)) {
    throw new MalformedDataError("Vault name payload is not a map");
  }

  return readString(value, "name");
}
