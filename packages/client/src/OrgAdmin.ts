import {
  generateEncryptionKeyPair,
  inviteLinkSecret,
  publicKeyFingerprint,
  randomBytes,
  signMemberCertificate,
  signMemberInvite,
  signRecoveryKey,
  toBase64Url,
  verifyInviteProof,
  verifyMemberInvite,
  wrapRecoveryPrivateKey,
} from "@keymember/core";
import type {
  MemberCertificate,
  MemberInvite,
  MemberRole,
} from "@keymember/core";
import { z } from "zod";

import type { InviteLink } from "./inviteLinks.js";
import { encode, parseResponse } from "./schemas.js";
import type { Session } from "./Session.js";
import type {
  InvitedCertification,
  OffboardingReport,
  OrgResponse,
  OrgAdminDeps,
} from "./Session.type.js";

/**
 * ### INVITE_LINK_MAX_AGE_SECONDS
 *
 * How old an invite may be for its link to vouch for the member's keys: the 7 days an invite
 * stays usable plus 7 days for the admin to open keymember. Older links are treated as possibly
 * leaked (old chat or mail history), and the member is compared by fingerprint instead.
 */
export const INVITE_LINK_MAX_AGE_SECONDS = 14 * 24 * 60 * 60;

/**
 * ### OrgAdmin
 *
 * Admin side of the organisation: who joins (invites, certificates), what the organisation
 * requires (policies), and who leaves (suspension, offboarding), plus the audit log.
 */
export class OrgAdmin {
  readonly #session: Pick<
    Session,
    | "fingerprint"
    | "groupAdmin"
    | "groups"
    | "listVaults"
    | "rotateVaultKey"
    | "sync"
  >;
  readonly #internals: OrgAdminDeps;

  /**
   * ### constructor
   *
   * Created by {@link Session.orgAdmin}.
   *
   * @param session The admin's session, for the vault and group work offboarding does
   * @param internals Internals of the same session
   */
  constructor(
    session: Pick<
      Session,
      | "fingerprint"
      | "groupAdmin"
      | "groups"
      | "listVaults"
      | "rotateVaultKey"
      | "sync"
    >,
    internals: OrgAdminDeps,
  ) {
    this.#session = session;
    this.#internals = internals;
  }

  /**
   * ### setRequireTotp
   *
   * Turns the "two-factor login required" policy on or off. Admins only.
   *
   * @param requireTotp Whether members must enrol two-factor login
   */
  async setRequireTotp(requireTotp: boolean): Promise<void> {
    await this.#internals.request({
      method: "PUT",
      path: "/api/org/policies",
      body: { requireTotp },
    });
  }

  /**
   * ### setRequireSso
   *
   * Turns the "sign in with the identity provider" policy on or off. Admins only. Switching it
   * on requires this login to have passed the provider ({@link Session.linkSso}); logins that
   * did not are refused from then on and must sign in again.
   *
   * @param requireSso Whether every login must pass the identity provider
   */
  async setRequireSso(requireSso: boolean): Promise<void> {
    await this.#internals.request({
      method: "PUT",
      path: "/api/org/policies",
      body: { requireSso },
    });
  }

  /**
   * ### certify
   *
   * Signs and uploads a certificate for a member's currently published keys. Certifying an
   * admin also hands them a copy of the recovery key. Compare `expectedFingerprint` with the
   * member out of band first; certification fails when the published keys do not match it.
   *
   * @param userId Member to certify
   * @param expectedFingerprint Fingerprint the member read out to the admin
   */
  async certify(userId: string, expectedFingerprint: string): Promise<void> {
    const org = await this.#internals.fetchOrg();
    const member = org.members.find((candidate) => candidate.userId === userId);

    if (member === undefined) {
      throw new Error(`Member ${userId} not found.`);
    }

    await this.#certifyMember(org, member, expectedFingerprint);
  }

  /**
   * ### #certifyMember
   *
   * Certifies one member of an organisation document already fetched.
   *
   * @param org Organisation document
   * @param member Member to certify
   * @param expectedFingerprint Fingerprint the published keys must have
   */
  async #certifyMember(
    org: OrgResponse,
    member: OrgResponse["members"][number],
    expectedFingerprint: string,
  ): Promise<void> {
    const { userId } = member;
    const fingerprint = publicKeyFingerprint(member.publicBundle);

    if (fingerprint !== expectedFingerprint) {
      throw new Error(
        // Never echo the published value: an admin could copy it instead of comparing with the member
        `The fingerprint for ${member.email} doesn't match. Compare it with the member again; if it differs, their key may have been swapped.`,
      );
    }

    const attested = this.#attestedMembership(org, member);
    const certificate: MemberCertificate = {
      orgId: org.org.id,
      userId,
      email: attested.email,
      encryptionPublicKey: member.publicBundle.encryptionPublicKey,
      signingPublicKey: member.publicBundle.signingPublicKey,
      keysetVersion: member.publicBundle.keysetVersion,
      role: attested.role,
      issuerId: this.#internals.user.id,
      issuedAt: Math.floor(Date.now() / 1000),
    };
    const needsRecoveryCopy =
      attested.role !== "member" &&
      org.recoveryKey !== null &&
      userId !== this.#internals.user.id;
    const recoveryKeyWrap = needsRecoveryCopy
      ? await wrapRecoveryPrivateKey(
          await this.#internals.recoveryKeyPair(),
          org.org.id,
          userId,
          certificate.encryptionPublicKey,
        )
      : undefined;

    await this.#internals.request({
      method: "POST",
      path: `/api/org/members/${userId}/confirm`,
      body: {
        certificate: {
          ...certificate,
          encryptionPublicKey: encode(certificate.encryptionPublicKey),
          signingPublicKey: encode(certificate.signingPublicKey),
        },
        signature: encode(
          signMemberCertificate(
            this.#internals.keyset.signing.privateKey,
            certificate,
          ),
        ),
        ...(recoveryKeyWrap === undefined
          ? {}
          : { recoveryKeyWrap: encode(recoveryKeyWrap) }),
      },
    });
  }

  /**
   * ### #attestedMembership
   *
   * The email and role to certify, taken from an invite a trusted admin signed rather than from
   * the server, which could otherwise slip an admin role (and a recovery-key copy) past the
   * certifying admin. Only the owner's own bootstrap certificate has no invite.
   *
   * @param org Organisation document
   * @param member Member about to be certified
   * @returns Email and role to sign
   */
  #attestedMembership(
    org: OrgResponse,
    member: OrgResponse["members"][number],
  ): { email: string; role: MemberRole } {
    if (member.userId === this.#internals.user.id) {
      // Self-certification is the owner's one-time bootstrap; the server allows nothing else
      return { email: member.email, role: "owner" };
    }

    const { issuers } = this.#internals.trust(org);
    const { invite } = member;

    if (invite === null) {
      throw new Error(
        `${member.email} has no signed invite. Invite them again.`,
      );
    }

    if (
      invite.statement.orgId !== org.org.id ||
      invite.statement.email !== member.email ||
      !verifyMemberInvite(
        signedInvite(invite.statement),
        invite.signature,
        issuers,
      )
    ) {
      throw new Error(
        `The invite for ${member.email} wasn't signed by a trusted admin. Invite them again.`,
      );
    }

    return { email: invite.statement.email, role: invite.statement.role };
  }

  /**
   * ### initializeOrganization
   *
   * Owner-only, once, right after bootstrap: certifies the owner's own keys (making them the
   * organisation's trust root) and creates the recovery key, signed by the owner.
   */
  async initializeOrganization(): Promise<void> {
    await this.certify(this.#internals.user.id, this.#session.fingerprint);

    const org = await this.#internals.fetchOrg();

    if (org.recoveryKey !== null) {
      return;
    }

    const recoveryKey = generateEncryptionKeyPair();

    await this.#internals.request({
      method: "POST",
      path: "/api/org/recovery-key",
      body: {
        publicKey: encode(recoveryKey.publicKey),
        signature: encode(
          signRecoveryKey(this.#internals.keyset.signing.privateKey, {
            orgId: org.org.id,
            publicKey: recoveryKey.publicKey,
          }),
        ),
        wrappedPrivateKey: encode(
          await wrapRecoveryPrivateKey(
            recoveryKey,
            org.org.id,
            this.#internals.user.id,
            this.#internals.keyset.encryption.publicKey,
          ),
        ),
      },
    });
  }

  /**
   * ### invite
   *
   * Creates a one-time invite and the link to send. The link carries a secret and the roots
   * this admin trusts in its fragment, so send it by email or chat rather than through
   * keymember; whoever holds it can join as the invitee until it is used or expires.
   *
   * @param email Invitee's email
   * @param role Role granted on sign-up
   * @returns The invite token, its expiry, and the link contents for {@link inviteLinkUrl}
   */
  async invite(
    email: string,
    role: "admin" | "member",
  ): Promise<{ inviteToken: string; expiresAt: string; link: InviteLink }> {
    const org = await this.#internals.fetchOrg();
    const roots = this.#internals.roots();

    if (roots.size === 0) {
      throw new Error(
        "This device doesn't trust the organization's keys yet, so it can't create invite links. Verify the owner's key first.",
      );
    }

    const statement: MemberInvite = {
      orgId: org.org.id,
      email: email.toLowerCase(),
      role,
      issuerId: this.#internals.user.id,
      issuedAt: Math.floor(Date.now() / 1000),
      nonce: toBase64Url(randomBytes(16)),
    };
    const signingKey = this.#internals.keyset.signing.privateKey;
    const created = parseResponse(
      z.object({ inviteToken: z.string(), expiresAt: z.string() }),
      await this.#internals.request({
        method: "POST",
        path: "/api/org/invites",
        body: {
          email: statement.email,
          role,
          statement,
          signature: encode(signMemberInvite(signingKey, statement)),
        },
      }),
    );

    return {
      ...created,
      link: {
        token: created.inviteToken,
        email: statement.email,
        secret: inviteLinkSecret(signingKey, statement),
        roots,
      },
    };
  }

  /**
   * ### certifyInvited
   *
   * Certifies the members who joined through a link this admin sent and proved, with the
   * link's secret, that the keys the server lists are theirs. The link vouches only for a plain
   * member on their first keys, within {@link INVITE_LINK_MAX_AGE_SECONDS} of the invite, and
   * only when one account used it; anyone else is left for {@link OrgAdmin.certify} after a
   * fingerprint comparison. One member failing does not stop the others.
   *
   * @returns Who was certified, who needs a fingerprint comparison, and what failed
   */
  async certifyInvited(): Promise<InvitedCertification> {
    const org = await this.#internals.fetchOrg();
    const now = Math.floor(Date.now() / 1000);
    const nonceUses = new Map<string, number>();

    for (const member of org.members) {
      const nonce = member.invite?.statement.nonce;

      if (nonce !== undefined) {
        nonceUses.set(nonce, (nonceUses.get(nonce) ?? 0) + 1);
      }
    }

    const certified: Array<string> = [];
    const needsFingerprint: Array<string> = [];
    const failed: Array<{ email: string; reason: string }> = [];

    for (const member of org.members) {
      const { invite } = member;
      const proof = invite?.proof ?? undefined;
      const nonce = invite?.statement.nonce;

      if (
        member.status !== "accepted" ||
        invite === null ||
        proof === undefined ||
        nonce === undefined ||
        invite.statement.issuerId !== this.#internals.user.id
      ) {
        continue;
      }

      const secret = inviteLinkSecret(
        this.#internals.keyset.signing.privateKey,
        signedInvite(invite.statement),
      );

      if (!verifyInviteProof(secret, member.publicBundle, proof)) {
        continue;
      }

      if (
        invite.statement.role !== "member" ||
        now - invite.statement.issuedAt > INVITE_LINK_MAX_AGE_SECONDS ||
        (nonceUses.get(nonce) ?? 0) > 1 ||
        member.certificate !== null ||
        member.publicBundle.keysetVersion !== 1
      ) {
        needsFingerprint.push(member.email);
        continue;
      }

      try {
        // certifyMember still checks that a trusted admin signed the invite's email and role
        await this.#certifyMember(
          org,
          member,
          publicKeyFingerprint(member.publicBundle),
        );
        certified.push(member.email);
      } catch (error) {
        failed.push({
          email: member.email,
          reason: error instanceof Error ? error.message : String(error),
        });
      }
    }

    return { certified, needsFingerprint, failed };
  }

  /**
   * ### suspendMember
   *
   * Suspends a member: ends their sessions and removes their vault and group access. The
   * vaults they could open are flagged for key rotation. {@link OrgAdmin.offboard} also does
   * the rotations this admin can do.
   *
   * @param userId Member to suspend
   * @returns The vaults (with their remaining managers) and groups the member could open
   */
  async suspendMember(userId: string): Promise<{
    vaults: Array<{ vaultId: string; managerIds: Array<string> }>;
    groups: Array<string>;
  }> {
    return parseResponse(
      z.object({
        vaults: z.array(
          z.object({ vaultId: z.string(), managerIds: z.array(z.string()) }),
        ),
        groups: z.array(z.string()),
      }),
      await this.#internals.request({
        method: "POST",
        path: `/api/org/members/${userId}/suspend`,
      }),
    );
  }

  /**
   * ### offboard
   *
   * Removes a member who left: suspends them, rotates the key of every group they were in, and
   * rotates every vault they could open that this admin manages. The rest are reported with
   * their managers, and stay flagged until a manager rotates them.
   *
   * @param userId Member who left
   * @returns What was rotated and what is left for other managers
   */
  async offboard(userId: string): Promise<OffboardingReport> {
    const exposure = await this.suspendMember(userId);
    const groupAdmin = this.#session.groupAdmin();

    const groups = await this.#session.groups();

    // The leaver is named explicitly: the server's membership lists are not trusted to drop them
    for (const groupId of exposure.groups) {
      const group = groups.find((candidate) => candidate.id === groupId);

      await groupAdmin.rotate(
        groupId,
        (group?.memberIds ?? []).filter((memberId) => memberId !== userId),
      );
    }

    await this.#session.sync();

    const managed = new Set(
      this.#session
        .listVaults()
        .filter((vault) => vault.permission === "manage")
        .map((vault) => vault.id),
    );
    const vaultsRotated = [];
    const vaultsPending = [];

    for (const vault of exposure.vaults) {
      if (managed.has(vault.vaultId)) {
        await this.#session.rotateVaultKey(vault.vaultId, [userId]);
        vaultsRotated.push(vault.vaultId);
      } else {
        vaultsPending.push(vault);
      }
    }

    return { groupsRotated: exposure.groups, vaultsRotated, vaultsPending };
  }

  /**
   * ### auditLog
   *
   * Reads the newest audit events. Admins only.
   *
   * @param limit Maximum number of events, newest first. Defaults to `100`.
   * @returns Audit events, newest first
   */
  async auditLog(limit = 100): Promise<
    Array<{
      id: number;
      actorId: string | null;
      action: string;
      targetId: string | null;
      at: string;
    }>
  > {
    return parseResponse(
      z.object({
        events: z.array(
          z.object({
            id: z.number(),
            actorId: z.string().nullable(),
            action: z.string(),
            targetId: z.string().nullable(),
            at: z.string(),
          }),
        ),
      }),
      await this.#internals.request({
        method: "GET",
        path: `/api/audit?limit=${String(limit)}`,
      }),
    ).events;
  }
}

/**
 * ### signedInvite
 *
 * An invite statement as it was signed: older invites have no nonce field at all, which differs
 * from a field holding `undefined`.
 *
 * @param statement Statement as served
 * @returns The statement to verify or derive from
 */
function signedInvite(
  statement: NonNullable<OrgResponse["members"][number]["invite"]>["statement"],
): MemberInvite {
  const { nonce, ...fields } = statement;

  return nonce === undefined ? fields : { ...fields, nonce };
}
