import {
  constantTimeEqual,
  generateEncryptionKeyPair,
  RECOVERY_PRINCIPAL_ID,
  signGroupCertificate,
  unwrapGroupPrivateKey,
  unwrapVaultKey,
  verifyGroupMembership,
  wrapGroupPrivateKey,
} from "@keymember/core";
import type { EncryptionKeyPair, GroupCertificate } from "@keymember/core";
import { z } from "zod";

import { grantVaultKey, groupKeyCopy } from "./grants.js";
import { b64, encode, parseResponse } from "./schemas.js";
import type {
  GroupView,
  RecipientKeys,
  GroupAdminDeps,
} from "./Session.type.js";

const groupKeysSchema = z.object({
  groupId: z.string(),
  keysetVersion: z.number().int(),
  encryptionPublicKey: b64,
  recoveryWrappedKey: b64.nullable(),
  memberWrappedKey: b64.nullable(),
  // Every member's copy of the current key with the handing admin's signature; servers from
  // before membership signatures do not send it
  members: z
    .array(
      z.object({
        userId: z.string(),
        wrappedPrivateKey: b64,
        grantedBy: z.string().nullable(),
        membershipSignature: b64.nullable(),
      }),
    )
    .optional(),
  access: z.array(
    z.object({
      vaultId: z.string(),
      wrappedKey: b64,
      keyGeneration: z.number().int(),
      permission: z.enum(["view", "edit", "manage"]),
    }),
  ),
});

/**
 * ### GroupAdmin
 *
 * Admin side of groups. A group has its own key pair; vault keys are wrapped to the group, and
 * the group's private key is wrapped to each member and to the recovery key. Adding a member
 * hands them the current group key. Removing one rotates the group key and re-wraps the vault
 * keys the group carries, so the removed member's copy opens nothing the group gets from now
 * on; the vault keys they already saw stay valid until a manager rotates those vaults.
 */
export class GroupAdmin {
  readonly #session: GroupAdminDeps;

  /**
   * ### constructor
   *
   * Created by {@link Session.groupAdmin}.
   *
   * @param session Internals of the admin's session
   */
  constructor(session: GroupAdminDeps) {
    this.#session = session;
  }

  /**
   * ### create
   *
   * Creates a group with the given members, each verified against the roots.
   *
   * @param name Group name, signed into the certificate
   * @param memberIds Members holding the group key from the start
   * @returns The new group id
   */
  async create(
    name: string,
    memberIds: ReadonlyArray<string>,
  ): Promise<string> {
    const groupId = crypto.randomUUID();
    const keys = await this.#session.recipientKeys(memberIds);
    const groupKey = generateEncryptionKeyPair();

    await this.#session.request({
      method: "POST",
      path: "/api/org/groups",
      body: await this.#keyMaterial(groupId, name, 1, groupKey, keys),
    });

    return groupId;
  }

  /**
   * ### addMember
   *
   * Hands a member a copy of the group's current key.
   *
   * @param groupId Group
   * @param userId Member to add
   */
  async addMember(groupId: string, userId: string): Promise<void> {
    const { group, groupKey } = await this.#currentKey(groupId);
    const keys = await this.#session.recipientKeys([userId]);
    const publicKey = keys.members.get(userId);

    if (publicKey === undefined) {
      throw new Error(`No key for ${userId}`);
    }

    const copy = await groupKeyCopy(
      this.#session.keyset.signing.privateKey,
      groupKey,
      {
        groupId,
        keysetVersion: group.keysetVersion,
        userId,
        encryptionPublicKey: publicKey,
      },
    );

    await this.#session.request({
      method: "PUT",
      path: `/api/org/groups/${groupId}/members/${userId}`,
      body: {
        keysetVersion: group.keysetVersion,
        wrappedPrivateKey: copy.wrappedPrivateKey,
        membershipSignature: copy.membershipSignature,
      },
    });
    await this.#session.sync();
  }

  /**
   * ### removeMember
   *
   * Removes a member by rotating the group key to everyone else.
   *
   * @param groupId Group
   * @param userId Member to remove
   */
  async removeMember(groupId: string, userId: string): Promise<void> {
    const group = await this.#group(groupId);

    await this.rotate(
      groupId,
      group.memberIds.filter((memberId) => memberId !== userId),
    );
  }

  /**
   * ### rotate
   *
   * Replaces the group key, re-wraps every vault key the group carries to the new key, and
   * hands the new key to `memberIds` (by default, the current members). Members left out lose
   * the group.
   *
   * Only members whose current copy carries a valid signature from a trusted admin get the new
   * key: a server that slips someone into the member list does not get them a fresh key from
   * this admin. When the server sends no membership signatures, everyone listed is kept.
   *
   * @param groupId Group
   * @param memberIds Members holding the new key
   * @param options `keepUnverified` also keeps members whose copy does not verify, after the
   * caller confirmed them
   */
  async rotate(
    groupId: string,
    memberIds?: ReadonlyArray<string>,
    options: { readonly keepUnverified?: boolean } = {},
  ): Promise<void> {
    const { group, groupKey, access, verifiedMemberIds } =
      await this.#currentKey(groupId);
    const wanted = memberIds ?? group.memberIds;
    const keys = await this.#session.recipientKeys(
      options.keepUnverified === true || verifiedMemberIds === undefined
        ? wanted
        : wanted.filter((userId) => verifiedMemberIds.has(userId)),
    );
    const nextVersion = group.keysetVersion + 1;
    const nextKey = generateEncryptionKeyPair();
    const rewrapped = [];

    for (const entry of access) {
      const vaultKey = await unwrapVaultKey(
        entry.wrappedKey,
        entry.vaultId,
        entry.keyGeneration,
        groupId,
        groupKey,
      );

      rewrapped.push({
        vaultId: entry.vaultId,
        keyGeneration: entry.keyGeneration,
        ...(await grantVaultKey(
          this.#session.keyset.signing.privateKey,
          vaultKey,
          {
            vaultId: entry.vaultId,
            keyGeneration: entry.keyGeneration,
            principalType: "group",
            principalId: groupId,
            encryptionPublicKey: nextKey.publicKey,
          },
        )),
      });
    }

    await this.#session.request({
      method: "POST",
      path: `/api/org/groups/${groupId}/rotate`,
      body: {
        ...(await this.#keyMaterial(
          groupId,
          group.certificate.name,
          nextVersion,
          nextKey,
          keys,
        )),
        access: rewrapped,
      },
    });
    await this.#session.sync();
  }

  /**
   * ### delete
   *
   * Deletes a group and every vault access it carried.
   *
   * @param groupId Group
   */
  async delete(groupId: string): Promise<void> {
    await this.#session.request({
      method: "DELETE",
      path: `/api/org/groups/${groupId}`,
    });
    await this.#session.sync();
  }

  /**
   * ### #group
   *
   * Finds a group whose certificate verifies against the roots.
   *
   * @param groupId Group
   * @returns The verified group
   */
  async #group(
    groupId: string,
  ): Promise<GroupView & { certificate: GroupCertificate }> {
    const group = (await this.#session.groups()).find(
      (candidate) => candidate.id === groupId,
    );

    if (group?.certificate === undefined) {
      throw new Error(
        `Group ${groupId} doesn't exist or its certificate can't be verified.`,
      );
    }

    return { ...group, certificate: group.certificate };
  }

  /**
   * ### #currentKey
   *
   * Opens the group's current private key from the admin's own member copy, or else from the
   * recovery key's copy, and checks it against the certified public key.
   *
   * @param groupId Group
   * @returns The verified group, its key pair, and the vault keys wrapped to it
   */
  async #currentKey(groupId: string): Promise<{
    group: GroupView & { certificate: GroupCertificate };
    groupKey: EncryptionKeyPair;
    access: z.infer<typeof groupKeysSchema>["access"];
    verifiedMemberIds: ReadonlySet<string> | undefined;
  }> {
    const group = await this.#group(groupId);
    const material = parseResponse(
      groupKeysSchema,
      await this.#session.request({
        method: "GET",
        path: `/api/org/groups/${groupId}/keys`,
      }),
    );
    const { certificate } = group;

    // The key material must belong to the certificate just verified, not a newer unverified one
    if (
      material.keysetVersion !== certificate.keysetVersion ||
      !constantTimeEqual(
        material.encryptionPublicKey,
        certificate.encryptionPublicKey,
      )
    ) {
      throw new Error("The group key changed in the meantime. Try again.");
    }

    let groupKey: EncryptionKeyPair;

    if (material.memberWrappedKey !== null) {
      groupKey = await unwrapGroupPrivateKey(
        material.memberWrappedKey,
        groupId,
        certificate.keysetVersion,
        this.#session.user.id,
        this.#session.keyset.encryption,
        certificate.encryptionPublicKey,
      );
    } else if (material.recoveryWrappedKey !== null) {
      groupKey = await unwrapGroupPrivateKey(
        material.recoveryWrappedKey,
        groupId,
        certificate.keysetVersion,
        RECOVERY_PRINCIPAL_ID,
        await this.#session.recoveryKeyPair(),
        certificate.encryptionPublicKey,
      );
    } else {
      throw new Error(
        "You aren't in this group and don't have the organization recovery key to open it.",
      );
    }

    return {
      group,
      groupKey,
      access: material.access,
      verifiedMemberIds:
        material.members === undefined
          ? undefined
          : await this.#verifiedMembers(
              groupId,
              certificate.keysetVersion,
              material.members,
            ),
    };
  }

  /**
   * ### #verifiedMembers
   *
   * Members whose copy of the current group key carries a valid membership signature from an
   * admin trusted from this device's roots.
   *
   * @param groupId Group
   * @param keysetVersion Current group key version
   * @param members Copies and signatures as the server listed them
   * @returns The verified members' user ids
   */
  async #verifiedMembers(
    groupId: string,
    keysetVersion: number,
    members: NonNullable<z.infer<typeof groupKeysSchema>["members"]>,
  ): Promise<ReadonlySet<string>> {
    const { issuers } = this.#session.trust(await this.#session.fetchOrg());

    return new Set(
      members
        .filter((member) => {
          const signerKey =
            member.grantedBy === null
              ? undefined
              : issuers.get(member.grantedBy);

          return (
            signerKey !== undefined &&
            member.membershipSignature !== null &&
            verifyGroupMembership(
              signerKey,
              {
                groupId,
                keysetVersion,
                userId: member.userId,
                wrappedPrivateKey: member.wrappedPrivateKey,
              },
              member.membershipSignature,
            )
          );
        })
        .map((member) => member.userId),
    );
  }

  /**
   * ### #keyMaterial
   *
   * Signs a group certificate and wraps the group key to each member and the recovery key.
   *
   * @param groupId Group
   * @param name Group name
   * @param keysetVersion Version of `groupKey`
   * @param groupKey Group key pair
   * @param keys Verified member and recovery keys
   * @returns Request body fields shared by create and rotate
   */
  async #keyMaterial(
    groupId: string,
    name: string,
    keysetVersion: number,
    groupKey: EncryptionKeyPair,
    keys: RecipientKeys,
  ): Promise<Record<string, unknown>> {
    const certificate: GroupCertificate = {
      orgId: keys.orgId,
      groupId,
      name,
      encryptionPublicKey: groupKey.publicKey,
      keysetVersion,
      issuerId: this.#session.user.id,
      issuedAt: Math.floor(Date.now() / 1000),
    };
    const members = [];

    for (const [userId, encryptionPublicKey] of keys.members) {
      members.push(
        await groupKeyCopy(this.#session.keyset.signing.privateKey, groupKey, {
          groupId,
          keysetVersion,
          userId,
          encryptionPublicKey,
        }),
      );
    }

    return {
      certificate: {
        ...certificate,
        encryptionPublicKey: encode(certificate.encryptionPublicKey),
      },
      signature: encode(
        signGroupCertificate(
          this.#session.keyset.signing.privateKey,
          certificate,
        ),
      ),
      members,
      ...(keys.recovery === undefined
        ? {}
        : {
            recoveryWrappedKey: encode(
              await wrapGroupPrivateKey(
                groupKey,
                groupId,
                keysetVersion,
                RECOVERY_PRINCIPAL_ID,
                keys.recovery,
              ),
            ),
          }),
    };
  }
}
