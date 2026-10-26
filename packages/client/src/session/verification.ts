import {
  constantTimeEqual,
  verifyGroupCertificate,
  verifyKeyGrant,
} from "@keymember/core";
import type { GroupCertificate } from "@keymember/core";

/**
 * ### certifiedGroup
 *
 * Whether a served group's certificate names this organisation and group, matches the served
 * key and version, and is signed by a trusted admin.
 *
 * @param group Group as served
 * @param orgId Organisation id
 * @param issuers Trusted admin signing keys
 * @returns Whether the group key can be trusted
 */
export function certifiedGroup(
  group: {
    id: string;
    keysetVersion: number;
    encryptionPublicKey: Uint8Array;
    certificate: GroupCertificate;
    certificateSignature: Uint8Array;
  },
  orgId: string,
  issuers: ReadonlyMap<string, Uint8Array>,
): boolean {
  const { certificate } = group;

  return (
    certificate.orgId === orgId &&
    certificate.groupId === group.id &&
    certificate.keysetVersion === group.keysetVersion &&
    constantTimeEqual(
      certificate.encryptionPublicKey,
      group.encryptionPublicKey,
    ) &&
    verifyGroupCertificate(certificate, group.certificateSignature, issuers)
  );
}

/**
 * ### grantVerifies
 *
 * Whether a served vault-key grant was signed by someone allowed to hand out vault keys.
 * Anyone can wrap a key to a public key, so an unsigned or foreign-signed grant could carry a
 * key the server knows.
 *
 * @param vaultId Vault the grant is for
 * @param path Access entry as served
 * @param granters Trusted granter signing keys by user id
 * @returns Whether the grant is authentic
 */
export function grantVerifies(
  vaultId: string,
  path: {
    principalType: "user" | "group";
    principalId: string;
    wrappedKey: Uint8Array;
    keyGeneration: number;
    grantedBy: string | null;
    grantSignature: Uint8Array | null;
  },
  granters: ReadonlyMap<string, Uint8Array>,
): boolean {
  const key =
    path.grantedBy === null ? undefined : granters.get(path.grantedBy);

  return (
    key !== undefined &&
    path.grantSignature !== null &&
    verifyKeyGrant(
      key,
      {
        vaultId,
        keyGeneration: path.keyGeneration,
        principalType: path.principalType,
        principalId: path.principalId,
        wrappedKey: path.wrappedKey,
      },
      path.grantSignature,
    )
  );
}
