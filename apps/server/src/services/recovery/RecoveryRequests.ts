import {
  randomBytes,
  toBase64Url,
  verifyRecoveryRequest,
} from "@keymember/core";

import { DomainError } from "../../domain/DomainError.js";
import type { RecoveryRecord } from "../../repositories/RecoveryRepository.js";
import { hashToken } from "../tokens.js";
import { findRecovery, takeSnapshot } from "./shared.js";
import type { Caller } from "../../domain/Caller.js";
import type { ServiceContext } from "../ServiceContext.js";

/**
 * ### RECOVERY_TOKEN_TTL_MS
 *
 * How long the one-time token an approving admin hands the user stays valid: 3 days.
 */
const RECOVERY_TOKEN_TTL_MS = 3 * 24 * 60 * 60 * 1000;

/**
 * ### NEW_ADMIN_COOLING_OFF_MS
 *
 * How long both admins of a recovery must have been confirmed members before it is approved:
 * 7 days. One admin who invites a second identity cannot request and approve with it at once,
 * and the invite and confirmation sit in the audit log for others to notice meanwhile.
 */
const NEW_ADMIN_COOLING_OFF_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * ### RecoveryRequests
 *
 * The admins' side of starting a recovery: one admin requests it, a different admin approves
 * it and receives a one-time token for the member, and any admin can cancel it.
 */
export class RecoveryRequests {
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
   * ### list
   *
   * Recent recoveries of an organisation.
   *
   * @param orgId Organisation
   * @returns The recoveries, newest first
   */
  list(orgId: string): Promise<Array<RecoveryRecord>> {
    return this.#context.store.repositories().recoveries.list(orgId);
  }

  /**
   * ### request
   *
   * Opens a recovery for a confirmed member, recording the access they have now. The request
   * must carry the requesting admin's signature over the member and the version of the keys
   * being replaced, which the completing admin checks later.
   *
   * @param actor Requesting admin
   * @param request Recovery id, member, their current key version, and the signature over them
   */
  async request(
    actor: Caller,
    request: {
      recoveryId: string;
      userId: string;
      keysetVersion: number;
      signature: Uint8Array;
    },
  ): Promise<void> {
    const { recoveryId, userId, keysetVersion, signature } = request;
    const { memberships, users } = this.#context.store.repositories();
    const requesterKey = await users.signingPublicKey(actor.userId);

    if (
      requesterKey === undefined ||
      !verifyRecoveryRequest(
        {
          orgId: actor.orgId,
          recoveryId,
          userId,
          requestedBy: actor.userId,
          keysetVersion,
        },
        signature,
        new Map([[actor.userId, requesterKey]]),
      )
    ) {
      throw new DomainError(
        "invalid",
        "bad_request",
        "Recovery request is not signed by the caller",
      );
    }

    if (userId === actor.userId) {
      throw new DomainError(
        "invalid",
        "bad_request",
        "Admins cannot start their own recovery",
      );
    }

    const target = (await memberships.directory(actor.orgId)).find(
      (entry) => entry.userId === userId,
    );

    // A wrong version would make the completing admin refuse the recovery; reject it now instead
    if (target !== undefined && target.keysetVersion !== keysetVersion) {
      throw new DomainError(
        "invalid",
        "bad_request",
        "The request names keys the member no longer has",
      );
    }

    await this.#context.store.transaction(async (repos) => {
      const target = await repos.memberships.lockState(actor.orgId, userId);

      if (target === undefined) {
        throw new DomainError("not_found", "not_found", "No such member");
      }

      // Every device pins the owner's key as its trust root; re-keying the owner would break them all
      if (target.role === "owner") {
        throw new DomainError(
          "invalid",
          "bad_request",
          "The owner's account cannot be recovered by admins",
        );
      }

      if (target.status !== "confirmed") {
        throw new DomainError(
          "conflict",
          "conflict",
          `Member is ${target.status}`,
        );
      }

      if (await repos.recoveries.hasOpen(userId)) {
        throw new DomainError(
          "conflict",
          "conflict",
          "A recovery is already open for this member",
        );
      }

      await repos.recoveries.insert(
        {
          id: recoveryId,
          orgId: actor.orgId,
          userId,
          requestedBy: actor.userId,
          requestSignature: signature,
          snapshot: await takeSnapshot(repos, userId),
        },
        this.#context.now(),
      );
      await repos.audit.record({
        orgId: actor.orgId,
        actorId: actor.userId,
        action: "recovery.requested",
        targetId: userId,
        detail: { recoveryId },
        ip: actor.ip,
      });
    });
  }

  /**
   * ### approve
   *
   * Approves a recovery as a second admin: freezes the member, ends their sessions, refreshes
   * the access snapshot, and issues the one-time token for the member.
   *
   * @param actor Approving admin, who must not be the requester; both must have been confirmed
   * members for at least 7 days
   * @param recoveryId Recovery to approve
   * @returns The token to hand the member, and when it expires
   */
  async approve(
    actor: Caller,
    recoveryId: string,
  ): Promise<{ token: string; expiresAt: Date }> {
    const recovery = await findRecovery(
      this.#context.store,
      actor.orgId,
      recoveryId,
    );

    if (recovery.requestedBy === actor.userId) {
      throw new DomainError(
        "forbidden",
        "forbidden",
        "A different admin must approve the recovery",
      );
    }

    const { memberships } = this.#context.store.repositories();
    const [approver, requester] = await Promise.all([
      memberships.confirmation(actor.userId),
      memberships.confirmation(recovery.requestedBy),
    ]);
    const now = this.#context.now().getTime();
    const established = (confirmedAt: Date | undefined): boolean =>
      confirmedAt !== undefined &&
      now - confirmedAt.getTime() >= NEW_ADMIN_COOLING_OFF_MS;

    // Either admin could be the other's recent second identity: an admin can invite and, through an
    // invite link, have certified someone they control. Both must have been members for a while
    if (
      !established(approver.confirmedAt) ||
      !established(requester.confirmedAt)
    ) {
      throw new DomainError(
        "forbidden",
        "forbidden",
        "Both admins must have been confirmed members for 7 days before a recovery is approved",
      );
    }

    const token = toBase64Url(randomBytes(32));
    const expiresAt = new Date(
      this.#context.now().getTime() + RECOVERY_TOKEN_TTL_MS,
    );

    await this.#context.store.transaction(async (repos) => {
      if (
        !(await repos.recoveries.approve(
          recoveryId,
          actor.userId,
          { hash: hashToken(token), expiresAt },
          this.#context.now(),
        ))
      ) {
        throw new DomainError(
          "conflict",
          "conflict",
          `Recovery is ${recovery.status}, not pending`,
        );
      }

      // A suspended (offboarded) member must never come back through a recovery
      if (!(await repos.memberships.freeze(recovery.userId))) {
        throw new DomainError(
          "conflict",
          "conflict",
          "The member is no longer active; cancel this recovery",
        );
      }

      // Access removed while the request waited must not come back: restore what they have now
      await repos.recoveries.replaceSnapshot(
        recoveryId,
        await takeSnapshot(repos, recovery.userId),
      );
      await repos.sessions.revokeAll(recovery.userId, this.#context.now());
      await repos.audit.record({
        orgId: actor.orgId,
        actorId: actor.userId,
        action: "recovery.approved",
        targetId: recovery.userId,
        detail: { recoveryId },
        ip: actor.ip,
      });
    });

    return { token, expiresAt };
  }

  /**
   * ### cancel
   *
   * Cancels an open recovery and unfreezes the member.
   *
   * @param actor Cancelling admin
   * @param recoveryId Recovery to cancel
   */
  async cancel(actor: Caller, recoveryId: string): Promise<void> {
    const recovery = await findRecovery(
      this.#context.store,
      actor.orgId,
      recoveryId,
    );

    await this.#context.store.transaction(async (repos) => {
      if (!(await repos.recoveries.cancel(recoveryId, this.#context.now()))) {
        throw new DomainError(
          "conflict",
          "conflict",
          `Recovery is already ${recovery.status}`,
        );
      }

      await repos.memberships.unfreeze(recovery.userId);
      await repos.audit.record({
        orgId: actor.orgId,
        actorId: actor.userId,
        action: "recovery.cancelled",
        targetId: recovery.userId,
        detail: { recoveryId, by: "admin" },
        ip: actor.ip,
      });
    });
  }
}
