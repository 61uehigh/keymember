import {
  publicKeyFingerprint,
  trustedIssuers,
  unwrapRecoveryPrivateKey,
  verifyDirectory,
  verifyRecoveryKey,
} from "@keymember/core";
import type {
  AccountKeyset,
  EncryptionKeyPair,
  MemberCertificate,
} from "@keymember/core";

import {
  groupsResponseSchema,
  orgResponseSchema,
  parseResponse,
} from "../schemas.js";
import type {
  DirectoryMember,
  GroupView,
  OrgResponse,
  RecipientKeys,
  SessionUser,
} from "../Session.type.js";
import type { AuthorizedRequest } from "./AuthorizedApi.js";
import { certifiedGroup } from "./verification.js";

/**
 * ### TrustContext
 *
 * Decides whose keys this session believes. Everything starts at the pinned roots (normally
 * the owner's signing key): member certificates chain from them, group certificates and the
 * recovery key must be signed by admins they vouch for, and nothing is shared with a key that
 * does not check out. Until roots are set, only the user's own keys are trusted.
 */
export class TrustContext {
  readonly #request: AuthorizedRequest;
  readonly #user: SessionUser;
  readonly #keyset: AccountKeyset;
  #roots: ReadonlyMap<string, Uint8Array> = new Map();

  /**
   * ### constructor
   *
   * @param request Authenticated requests to the server
   * @param user The logged-in user
   * @param keyset The user's unlocked keyset
   */
  constructor(
    request: AuthorizedRequest,
    user: SessionUser,
    keyset: AccountKeyset,
  ) {
    this.#request = request;
    this.#user = user;
    this.#keyset = keyset;
  }

  /**
   * ### setRoots
   *
   * Pins the issuer keys this session trusts.
   *
   * @param roots Pinned issuer keys by user id
   */
  setRoots(roots: ReadonlyMap<string, Uint8Array>): void {
    this.#roots = new Map(roots);
  }

  /**
   * ### roots
   *
   * The pinned issuer keys.
   *
   * @returns Pinned issuer keys by user id
   */
  roots(): ReadonlyMap<string, Uint8Array> {
    return this.#roots;
  }

  /**
   * ### fetchOrg
   *
   * Fetches the organisation document: directory, policies and recovery key.
   *
   * @returns The validated, still unverified organisation document
   */
  async fetchOrg(): Promise<OrgResponse> {
    return parseResponse(
      orgResponseSchema,
      await this.#request({ method: "GET", path: "/api/org" }),
    );
  }

  /**
   * ### trust
   *
   * Verifies an organisation document's member certificates from the roots.
   *
   * @param org Organisation document
   * @returns Verified certificates by user id, and the keys trusted to issue statements
   */
  trust(org: OrgResponse): {
    certified: Map<string, MemberCertificate>;
    issuers: Map<string, Uint8Array>;
  } {
    const certified = this.#verifyOrg(org, this.#roots);

    return { certified, issuers: trustedIssuers(certified, this.#roots) };
  }

  /**
   * ### granters
   *
   * Whoever may hand out vault keys to this user: the user, and members certified from the
   * roots.
   *
   * @param certified Verified member certificates
   * @returns Signing keys by user id
   */
  granters(
    certified: ReadonlyMap<string, MemberCertificate>,
  ): Map<string, Uint8Array> {
    return new Map<string, Uint8Array>([
      ...[...certified].map(
        ([userId, certificate]) =>
          [userId, certificate.signingPublicKey] as const,
      ),
      [this.#user.id, this.#keyset.signing.publicKey],
    ]);
  }

  /**
   * ### verifiedRecoveryPublicKey
   *
   * Returns the organisation's recovery public key when a pinned root signed it,
   * `undefined` when the organisation has none, and throws when the signature does not check out.
   *
   * @param org Organisation document
   * @returns The verified recovery public key, if any
   */
  verifiedRecoveryPublicKey(org: OrgResponse): Uint8Array | undefined {
    if (org.recoveryKey === null) {
      return undefined;
    }

    // Only the owner creates the recovery key, so only a pinned root may vouch for it
    const signer = this.#roots.get(org.recoveryKey.signerId);

    if (
      signer === undefined ||
      !verifyRecoveryKey(
        signer,
        { orgId: org.org.id, publicKey: org.recoveryKey.publicKey },
        org.recoveryKey.signature,
      )
    ) {
      throw new Error(
        "The organization recovery key isn't signed by a trusted admin, so it isn't used.",
      );
    }

    return org.recoveryKey.publicKey;
  }

  /**
   * ### recoveryKeyPair
   *
   * Unwraps this admin's copy of the recovery key after verifying the published public key.
   *
   * @returns The recovery key pair
   */
  async recoveryKeyPair(): Promise<EncryptionKeyPair> {
    const org = await this.fetchOrg();
    const publicKey = this.verifiedRecoveryPublicKey(org);
    const wrapped = org.recoveryKey?.wrappedPrivateKey ?? null;

    if (publicKey === undefined || wrapped === null) {
      throw new Error(
        "This account has no copy of the organization recovery key. An admin who holds it has to do this.",
      );
    }

    return unwrapRecoveryPrivateKey(
      wrapped,
      org.org.id,
      this.#user.id,
      this.#keyset.encryption,
      publicKey,
    );
  }

  /**
   * ### groups
   *
   * Fetches the groups and marks which group keys a trusted admin vouched for. A certificate
   * must name this organisation and group and match the served key and version.
   *
   * @param org Organisation document; fetched when omitted
   * @returns Every live group, with `certificate` set only when it verified
   */
  async groups(org?: OrgResponse): Promise<Array<GroupView>> {
    const document = org ?? (await this.fetchOrg());
    const response = parseResponse(
      groupsResponseSchema,
      await this.#request({ method: "GET", path: "/api/org/groups" }),
    );
    const { issuers } = this.trust(document);

    return response.groups.map((group) => {
      const { certificate } = group;
      const verified = certifiedGroup(group, document.org.id, issuers);

      return {
        id: group.id,
        name: verified ? certificate.name : group.name,
        keysetVersion: group.keysetVersion,
        memberIds: group.members
          .filter((member) => member.keysetVersion === group.keysetVersion)
          .map((member) => member.userId),
        certificate: verified ? certificate : undefined,
      };
    });
  }

  /**
   * ### directory
   *
   * Fetches the member directory and marks which members' keys the roots vouch for.
   *
   * @returns Every member, verified or not
   */
  async directory(): Promise<Array<DirectoryMember>> {
    return this.#directory(this.#roots);
  }

  /**
   * ### ownerCandidates
   *
   * Lists the owners the server reports, with fingerprints, so a client can pin one on first use.
   * The fingerprint must be compared out of band before pinning; this call proves nothing by itself.
   *
   * @returns Owner user ids with their signing keys and fingerprints
   */
  async ownerCandidates(): Promise<
    Array<{
      userId: string;
      email: string;
      signingPublicKey: Uint8Array;
      fingerprint: string;
    }>
  > {
    return (await this.#directory(new Map()))
      .filter((member) => member.role === "owner")
      .map((member) => ({
        userId: member.userId,
        email: member.email,
        signingPublicKey: member.publishedKeys.signing,
        fingerprint: member.fingerprint,
      }));
  }

  /**
   * ### recipientKeys
   *
   * Resolves the certified encryption keys of the given members and groups plus the verified
   * recovery key, refusing anyone without a certificate chain from the roots.
   *
   * @param userIds Members about to receive a key
   * @param groupIds Groups about to receive a key
   * @returns Verified keys of every recipient
   */
  async recipientKeys(
    userIds: ReadonlyArray<string>,
    groupIds: ReadonlyArray<string> = [],
  ): Promise<RecipientKeys> {
    const org = await this.fetchOrg();
    const { certified } = this.trust(org);
    const statuses = new Map(
      org.members.map((member) => [member.userId, member.status]),
    );
    const members = new Map<string, Uint8Array>();
    const groups = new Map<
      string,
      { publicKey: Uint8Array; keysetVersion: number }
    >();

    for (const userId of userIds) {
      if (userId === this.#user.id) {
        members.set(userId, this.#keyset.encryption.publicKey);
        continue;
      }

      const certificate = certified.get(userId);

      if (certificate === undefined || statuses.get(userId) !== "confirmed") {
        throw new Error(`Not sharing: ${userId}'s key isn't verified.`);
      }

      members.set(userId, certificate.encryptionPublicKey);
    }

    if (groupIds.length > 0) {
      const verifiedGroups = new Map(
        (await this.groups(org)).map((group) => [group.id, group.certificate]),
      );

      for (const groupId of groupIds) {
        const certificate = verifiedGroups.get(groupId);

        if (certificate === undefined) {
          throw new Error(
            `Not sharing: group ${groupId} isn't certified by a trusted admin.`,
          );
        }

        groups.set(groupId, {
          publicKey: certificate.encryptionPublicKey,
          keysetVersion: certificate.keysetVersion,
        });
      }
    }

    return {
      members,
      groups,
      recovery: this.verifiedRecoveryPublicKey(org),
      orgId: org.org.id,
    };
  }

  /**
   * ### #directory
   *
   * The member directory judged from the given roots.
   *
   * @param roots Pinned issuer keys; empty before any owner is pinned
   * @returns Every member, verified or not
   */
  async #directory(
    roots: ReadonlyMap<string, Uint8Array>,
  ): Promise<Array<DirectoryMember>> {
    const org = await this.fetchOrg();
    const verified = this.#verifyOrg(org, roots);

    return org.members.map((member) => ({
      userId: member.userId,
      email: member.email,
      name: member.name,
      role: member.role,
      status: member.status,
      fingerprint: publicKeyFingerprint(member.publicBundle),
      certificate: verified.get(member.userId),
      publishedKeys: {
        encryption: member.publicBundle.encryptionPublicKey,
        signing: member.publicBundle.signingPublicKey,
        version: member.publicBundle.keysetVersion,
      },
    }));
  }

  /**
   * ### #verifyOrg
   *
   * Verifies the directory of an organisation document against some roots.
   *
   * @param org Organisation document
   * @param roots Pinned issuer keys
   * @returns Verified certificates keyed by user id
   */
  #verifyOrg(
    org: OrgResponse,
    roots: ReadonlyMap<string, Uint8Array>,
  ): Map<string, MemberCertificate> {
    return verifyDirectory(
      org.members.map((member) => ({
        certificate: member.certificate ?? undefined,
        signature: member.certificateSignature ?? undefined,
        keysetVersion: member.publicBundle.keysetVersion,
        userId: member.userId,
      })),
      roots,
      org.org.id,
    );
  }
}
