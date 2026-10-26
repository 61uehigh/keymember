import { randomBytes, toBase64Url, verifyMemberInvite } from "@keymember/core";
import type { MemberInvite } from "@keymember/core";

import type { Caller } from "../../domain/Caller.js";
import { DomainError } from "../../domain/DomainError.js";
import type { ServiceContext } from "../ServiceContext.js";
import { hashToken } from "../tokens.js";

/**
 * ### INVITE_TTL_MS
 *
 * How long an invite stays usable: 7 days.
 */
const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * ### NewInvite
 *
 * An invite as the admin's app made it: who, in which role, and the admin's signed statement of
 * both, which certification later relies on instead of the server.
 */
export interface NewInvite {
  readonly email: string;
  readonly role: "admin" | "member";
  readonly statement: MemberInvite;
  readonly signature: Uint8Array;
}

/**
 * ### IssuedInvite
 *
 * The invite token to hand to the invitee, and when it stops working.
 */
export interface IssuedInvite {
  readonly token: string;
  readonly expiresAt: Date;
}

/**
 * ### Invitations
 *
 * Admins inviting people into the organisation.
 */
export class Invitations {
  readonly #context: ServiceContext;

  /**
   * ### constructor
   *
   * @param context Storage and clock
   */
  constructor(context: ServiceContext) {
    this.#context = context;
  }

  /**
   * ### invite
   *
   * Stores an invite whose signed statement matches it and comes from the caller.
   *
   * @param caller Inviting admin
   * @param invite The invite
   * @returns The token and its expiry
   */
  async invite(caller: Caller, invite: NewInvite): Promise<IssuedInvite> {
    const { store } = this.#context;
    const issuerKey = await store
      .repositories()
      .users.signingPublicKey(caller.userId);
    const { statement } = invite;

    if (
      issuerKey === undefined ||
      statement.orgId !== caller.orgId ||
      statement.email !== invite.email ||
      statement.role !== invite.role ||
      statement.issuerId !== caller.userId ||
      !verifyMemberInvite(
        statement,
        invite.signature,
        new Map([[caller.userId, issuerKey]]),
      )
    ) {
      throw new DomainError(
        "invalid",
        "bad_request",
        "Invite statement does not match the invite or is not signed by the caller",
      );
    }

    const token = toBase64Url(randomBytes(32));
    const expiresAt = new Date(this.#context.now().getTime() + INVITE_TTL_MS);

    await store.transaction(async ({ audit, invites }) => {
      await invites.insert({
        tokenHash: hashToken(token),
        orgId: caller.orgId,
        email: invite.email,
        role: invite.role,
        createdBy: caller.userId,
        expiresAt,
        statement: { ...statement },
        signature: invite.signature,
      });
      await audit.record({
        orgId: caller.orgId,
        actorId: caller.userId,
        action: "org.invite_created",
        detail: { email: invite.email, role: invite.role },
        ip: caller.ip,
      });
    });

    return { token, expiresAt };
  }
}
