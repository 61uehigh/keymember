import {
  assertKdfParams,
  KdfParametersRejectedError,
  verifyPublicBundle,
} from "@keymember/core";

import { DomainError } from "../../domain/DomainError.js";
import type { RecoveryRecord } from "../../repositories/RecoveryRepository.js";
import type { NewUser } from "../../repositories/UserRepository.js";
import { hashToken } from "../tokens.js";
import type { ServiceContext } from "../ServiceContext.js";

/**
 * ### RecoveryEnrolment
 *
 * The member's side: with the token an admin handed over, replaces their credentials and keys.
 * Admins never learn the member's password, Secret Key or personal keys.
 */
export class RecoveryEnrolment {
  readonly #context: ServiceContext;

  /**
   * ### constructor
   *
   * @param context Where data is kept, and the clock
   */
  constructor(context: ServiceContext) {
    this.#context = context;
  }

  /**
   * ### approvedByToken
   *
   * Resolves an unexpired recovery token to its approved recovery, for the member re-enrolling.
   *
   * @param token Token handed to the member
   * @returns The recovery with the member's current keyset version and the organisation name
   */
  async approvedByToken(
    token: string,
  ): Promise<RecoveryRecord & { keysetVersion: number; orgName: string }> {
    const recovery = await this.#context.store
      .repositories()
      .recoveries.approvedByToken(hashToken(token), this.#context.now());

    if (recovery === undefined) {
      throw new DomainError(
        "forbidden",
        "forbidden",
        "Recovery token is invalid, expired or already used",
      );
    }

    return recovery;
  }

  /**
   * ### rekey
   *
   * The member's side: replaces their credentials and keys. Their old vault and group access
   * goes, since it was wrapped to keys that no longer exist; it comes back when an admin
   * certifies the new keys and completes the recovery.
   *
   * @param token Recovery token
   * @param rekey New account id, KDF inputs, login key and key set, one version newer
   * @param ip Where the request came from, for the audit log
   */
  async rekey(
    token: string,
    rekey: Omit<NewUser, "email" | "id" | "name">,
    ip: string,
  ): Promise<void> {
    const recovery = await this.approvedByToken(token);

    try {
      assertKdfParams(rekey.kdf);
    } catch (error) {
      if (error instanceof KdfParametersRejectedError) {
        throw new DomainError("invalid", "bad_request", error.message);
      }

      throw error;
    }

    const bundle = {
      userId: recovery.userId,
      encryptionPublicKey: rekey.keyset.encryptionPublicKey,
      signingPublicKey: rekey.keyset.signingPublicKey,
      keysetVersion: rekey.keyset.keysetVersion,
    };

    if (
      rekey.keyset.keysetVersion !== recovery.keysetVersion + 1 ||
      !verifyPublicBundle(bundle, rekey.keyset.selfSignature)
    ) {
      throw new DomainError(
        "invalid",
        "bad_request",
        "New keyset must be self-signed and one version newer",
      );
    }

    await this.#context.store.transaction(async (repos) => {
      await repos.changeFeed.lock();

      const now = this.#context.now();

      if (
        await repos.users.accountIdTakenByOther(
          rekey.accountId,
          recovery.userId,
        )
      ) {
        throw new DomainError(
          "conflict",
          "conflict",
          "Account id already in use; generate a new Secret Key",
        );
      }

      await repos.users.rekey(recovery.userId, rekey);
      // The new keys must be certified again before anyone shares with them
      await repos.memberships.resetForRekey(recovery.userId);
      // Old wraps target keys that no longer exist; access comes back when the recovery completes
      await repos.vaults.removeUserGrants(recovery.userId);
      await repos.groups.removeFromAll(recovery.userId);
      await repos.organizations.removeRecoveryKeyCopies(recovery.userId);
      await repos.sessions.revokeAll(recovery.userId, now);

      // The user may have cancelled it by logging in, or the token was used concurrently
      if (!(await repos.recoveries.markRekeyed(recovery.id, now))) {
        throw new DomainError(
          "forbidden",
          "forbidden",
          "The recovery is no longer open",
        );
      }

      await repos.audit.record({
        orgId: recovery.orgId,
        actorId: recovery.userId,
        action: "recovery.rekeyed",
        targetId: recovery.userId,
        detail: { recoveryId: recovery.id },
        ip,
      });
    });
  }
}
