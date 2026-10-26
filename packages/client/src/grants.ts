import {
  RECOVERY_PRINCIPAL_ID,
  signGroupMembership,
  signKeyGrant,
  wrapGroupPrivateKey,
  wrapVaultKey,
} from "@keymember/core";
import type { EncryptionKeyPair, SymmetricKey } from "@keymember/core";

import { encode } from "./schemas.js";
import type { PrincipalType } from "./Session.type.js";

/**
 * ### SignedGrant
 *
 * A vault key wrapped to one principal, with the granter's signature over exactly that wrap,
 * both encoded for the API.
 */
export interface SignedGrant {
  readonly wrappedKey: string;
  readonly grantSignature: string;
}

/**
 * ### grantVaultKey
 *
 * Wraps a vault key to a principal and signs the grant. Every place that hands out a vault
 * key goes through here, so the signed statement always matches what sync verifies.
 *
 * @param signingKey Granter's signing private key
 * @param vaultKey Vault key to hand out
 * @param grant Vault, key generation and the principal with its encryption public key
 * @returns The wrapped key and its grant signature
 */
export async function grantVaultKey(
  signingKey: Uint8Array,
  vaultKey: SymmetricKey,
  grant: {
    vaultId: string;
    keyGeneration: number;
    principalType: PrincipalType;
    principalId: string;
    encryptionPublicKey: Uint8Array;
  },
): Promise<SignedGrant> {
  const wrappedKey = await wrapVaultKey(
    vaultKey,
    grant.vaultId,
    grant.keyGeneration,
    {
      principalId: grant.principalId,
      encryptionPublicKey: grant.encryptionPublicKey,
    },
  );

  return {
    wrappedKey: encode(wrappedKey),
    grantSignature: encode(
      signKeyGrant(signingKey, {
        vaultId: grant.vaultId,
        keyGeneration: grant.keyGeneration,
        principalType: grant.principalType,
        principalId: grant.principalId,
        wrappedKey,
      }),
    ),
  };
}

/**
 * ### SignedMemberCopy
 *
 * A group private key wrapped to one member, with the handing admin's membership signature,
 * both encoded for the API.
 */
export interface SignedMemberCopy {
  readonly userId: string;
  readonly wrappedPrivateKey: string;
  readonly membershipSignature: string;
}

/**
 * ### groupKeyCopy
 *
 * Wraps a group's private key to a member and signs the membership. Every place that hands a
 * member a group key goes through here, so group rotation can tell members an admin added from
 * members the server added.
 *
 * @param signingKey Admin's signing private key
 * @param groupKey Group key pair
 * @param membership Group, key version and the member with their encryption public key
 * @returns The member's copy and its signature
 */
export async function groupKeyCopy(
  signingKey: Uint8Array,
  groupKey: EncryptionKeyPair,
  membership: {
    groupId: string;
    keysetVersion: number;
    userId: string;
    encryptionPublicKey: Uint8Array;
  },
): Promise<SignedMemberCopy> {
  const wrappedPrivateKey = await wrapGroupPrivateKey(
    groupKey,
    membership.groupId,
    membership.keysetVersion,
    membership.userId,
    membership.encryptionPublicKey,
  );

  return {
    userId: membership.userId,
    wrappedPrivateKey: encode(wrappedPrivateKey),
    membershipSignature: encode(
      signGroupMembership(signingKey, {
        groupId: membership.groupId,
        keysetVersion: membership.keysetVersion,
        userId: membership.userId,
        wrappedPrivateKey,
      }),
    ),
  };
}

/**
 * ### recoveryCopy
 *
 * The vault key wrapped to the organisation's recovery key, when it has one.
 *
 * @param vaultKey Vault key
 * @param vaultId Vault id
 * @param keyGeneration Vault key generation
 * @param recoveryPublicKey Verified recovery public key, if the organisation has one
 * @returns The request field to spread into a vault create or rotate body
 */
export async function recoveryCopy(
  vaultKey: SymmetricKey,
  vaultId: string,
  keyGeneration: number,
  recoveryPublicKey: Uint8Array | undefined,
): Promise<{ recoveryWrappedKey?: string }> {
  if (recoveryPublicKey === undefined) {
    return {};
  }

  return {
    recoveryWrappedKey: encode(
      await wrapVaultKey(vaultKey, vaultId, keyGeneration, {
        principalId: RECOVERY_PRINCIPAL_ID,
        encryptionPublicKey: recoveryPublicKey,
      }),
    ),
  };
}
