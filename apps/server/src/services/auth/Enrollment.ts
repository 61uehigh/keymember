import { randomUUID } from "node:crypto";

import {
  assertKdfParams,
  constantTimeEqual,
  KdfParametersRejectedError,
  verifyPublicBundle,
} from "@keymember/core";
import type { KdfParams } from "@keymember/core";

import { DomainError } from "../../domain/DomainError.js";
import type { MembershipRole } from "../../domain/membership.js";
import type { Repositories } from "../../repositories/Repositories.js";
import type { ServiceContext } from "../ServiceContext.js";
import { hashToken } from "../tokens.js";

/**
 * ### NewUser
 *
 * A new account as its client built it: public keys, the encrypted keyset and how the password
 * is stretched. The server never sees the password or the Secret Key.
 */
export interface NewUser {
  readonly userId: string;
  readonly email: string;
  readonly name: string;
  readonly accountId: string;
  readonly salt: Uint8Array;
  readonly kdf: KdfParams;
  readonly loginPublicKey: Uint8Array;
  readonly keyset: {
    readonly encryptedAccountKey: Uint8Array;
    readonly encryptedPrivateKeys: Uint8Array;
    readonly encryptionPublicKey: Uint8Array;
    readonly signingPublicKey: Uint8Array;
    readonly keysetVersion: number;
    readonly selfSignature: Uint8Array;
  };
}

/**
 * ### Invitation
 *
 * The invite a sign-up redeems.
 */
export interface Invitation {
  /**
   * ### token
   *
   * Token from the invite.
   */
  readonly token: string;

  /**
   * ### proof
   *
   * Proof from the invite link's secret that the keys are the invitee's; absent when the
   * invitee typed the token in, in which case the admin compares fingerprints.
   */
  readonly proof: Uint8Array | undefined;
}

/**
 * ### Enrollment
 *
 * Accounts joining the server: the owner creating the organisation, and invitees signing up.
 * A new membership is usable only after an admin certifies it.
 */
export class Enrollment {
  readonly #context: ServiceContext;
  readonly #bootstrapToken: string | undefined;

  /**
   * ### constructor
   *
   * @param context Storage and clock
   * @param bootstrapToken Token the first owner must present; `undefined` lets anyone bootstrap
   */
  constructor(context: ServiceContext, bootstrapToken: string | undefined) {
    this.#context = context;
    this.#bootstrapToken = bootstrapToken;
  }

  /**
   * ### bootstrap
   *
   * Creates the server's only organisation with the user as owner.
   *
   * @param orgName Organisation name
   * @param user The owner's account
   * @param token Bootstrap token the owner presented
   * @param ip Where the request came from, for the audit log
   * @returns The new organisation's id
   */
  async bootstrap(
    orgName: string,
    user: NewUser,
    token: string | undefined,
    ip: string,
  ): Promise<string> {
    this.#checkBootstrapToken(token);

    const orgId = randomUUID();

    await this.#context.store.transaction(async (repositories) => {
      // Serialises concurrent bootstrap attempts so only one organisation can ever be created
      if (await repositories.organizations.lockForBootstrap()) {
        throw new DomainError(
          "conflict",
          "conflict",
          "This server already has an organisation",
        );
      }

      await repositories.organizations.insert(orgId, orgName);
      await insertUser(repositories, user, orgId, "owner");
      await repositories.audit.record({
        orgId,
        actorId: user.userId,
        action: "org.bootstrapped",
        ip,
      });
    });

    return orgId;
  }

  /**
   * ### signUp
   *
   * Redeems an invite for the email it was made out to.
   *
   * @param user The invitee's account
   * @param invitation The invite and its link proof
   * @param ip Where the request came from, for the audit log
   */
  async signUp(
    user: NewUser,
    invitation: Invitation,
    ip: string,
  ): Promise<void> {
    const now = this.#context.now();
    const tokenHash = hashToken(invitation.token);

    await this.#context.store.transaction(async (repositories) => {
      const invite = await repositories.invites.lockValid(tokenHash, now);

      if (invite?.email !== user.email) {
        throw new DomainError(
          "forbidden",
          "forbidden",
          "Invite is invalid, expired, used, or for another email",
        );
      }

      await insertUser(repositories, user, invite.orgId, invite.role);
      await repositories.invites.markUsed(tokenHash, now, invitation.proof);
      await repositories.audit.record({
        orgId: invite.orgId,
        actorId: user.userId,
        action: "user.signed_up",
        ip,
      });
    });
  }

  /**
   * ### #checkBootstrapToken
   *
   * Refuses a bootstrap without the server's token, so whoever reaches a fresh server first
   * cannot claim it.
   *
   * @param token Token presented
   */
  #checkBootstrapToken(token: string | undefined): void {
    if (this.#bootstrapToken === undefined) {
      return;
    }

    if (
      token === undefined ||
      // Hashing first gives both sides the same length, so the comparison leaks nothing
      !constantTimeEqual(hashToken(token), hashToken(this.#bootstrapToken))
    ) {
      throw new DomainError(
        "forbidden",
        "bootstrap_token_invalid",
        "The bootstrap token is missing or wrong; find it in the server log or KEYMEMBER_BOOTSTRAP_TOKEN",
      );
    }
  }
}

/**
 * ### insertUser
 *
 * Validates a new account's KDF parameters and self-signature, then inserts the user and an
 * `accepted` membership.
 *
 * @param repositories Storage bound to the sign-up's transaction
 * @param user The new account
 * @param orgId Organisation the user joins
 * @param role Role granted by the invite or bootstrap
 */
async function insertUser(
  repositories: Pick<Repositories, "memberships" | "users">,
  user: NewUser,
  orgId: string,
  role: MembershipRole,
): Promise<void> {
  try {
    assertKdfParams(user.kdf);
  } catch (error) {
    if (error instanceof KdfParametersRejectedError) {
      throw new DomainError("invalid", "bad_request", error.message);
    }

    throw error;
  }

  const bundle = {
    userId: user.userId,
    encryptionPublicKey: user.keyset.encryptionPublicKey,
    signingPublicKey: user.keyset.signingPublicKey,
    keysetVersion: user.keyset.keysetVersion,
  };

  if (!verifyPublicBundle(bundle, user.keyset.selfSignature)) {
    throw new DomainError(
      "invalid",
      "bad_request",
      "Self-signature does not match the public keys",
    );
  }

  if (
    await repositories.users.isRegistered({
      id: user.userId,
      email: user.email,
      accountId: user.accountId,
    })
  ) {
    throw new DomainError(
      "conflict",
      "conflict",
      "User id, email or account id is already registered",
    );
  }

  await repositories.users.insert({
    id: user.userId,
    email: user.email,
    name: user.name,
    accountId: user.accountId,
    salt: user.salt,
    kdf: user.kdf,
    loginPublicKey: user.loginPublicKey,
    keyset: user.keyset,
  });
  await repositories.memberships.insert(orgId, user.userId, role);
}
