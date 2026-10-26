import { constantTimeEqual, verifyMemberCertificate } from "@keymember/core";
import type { MemberCertificate } from "@keymember/core";

import type { Caller } from "../../domain/Caller.js";
import { DomainError } from "../../domain/DomainError.js";
import { b64 } from "../../http/codec.js";
import type { ServiceContext } from "../ServiceContext.js";

/**
 * ### Certification
 *
 * An admin's signed statement that a member's published keys are theirs.
 */
export interface Certification {
  readonly certificate: MemberCertificate;
  readonly signature: Uint8Array;
  /** The recovery key wrapped to the member; required for admins once the key exists */
  readonly recoveryKeyWrap: Uint8Array | undefined;
}

/**
 * ### MemberCertification
 *
 * Admins certifying members' keys, which makes the membership usable. The owner certifies their
 * own keys once, right after bootstrap.
 */
export class MemberCertification {
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
   * ### certify
   *
   * Stores a certificate that matches the member's published keys and is signed by the caller.
   *
   * @param caller Certifying admin
   * @param userId Member being certified
   * @param certification The certificate, its signature and the recovery key copy
   */
  async certify(
    caller: Caller,
    userId: string,
    certification: Certification,
  ): Promise<void> {
    const { certificate, signature, recoveryKeyWrap } = certification;

    if (
      certificate.issuerId === userId &&
      (caller.role !== "owner" || caller.userId !== userId)
    ) {
      throw new DomainError(
        "forbidden",
        "forbidden",
        "Only the owner may self-certify, and only their own keys",
      );
    }

    if (certificate.issuerId !== caller.userId) {
      throw new DomainError(
        "forbidden",
        "forbidden",
        "Certificate issuer must be the caller",
      );
    }

    await this.#context.store.transaction(async (repos) => {
      const { audit, memberships, organizations, users } = repos;
      const target = await memberships.lockForCertification(userId);
      const issuerKey = await users.signingPublicKey(caller.userId);

      if (
        target === undefined ||
        issuerKey === undefined ||
        target.orgId !== caller.orgId
      ) {
        throw new DomainError("not_found", "not_found", "No such member");
      }

      if (target.status === "suspended" || target.status === "recovering") {
        throw new DomainError(
          "conflict",
          "conflict",
          `Member is ${target.status}; it cannot be certified now`,
        );
      }

      // Every admin must hold a copy of the recovery key, or recoveries could stall
      if (
        target.role !== "member" &&
        recoveryKeyWrap === undefined &&
        (await organizations.hasRecoveryKey(caller.orgId))
      ) {
        throw new DomainError(
          "invalid",
          "bad_request",
          "Certifying an admin requires wrapping the recovery key to them",
        );
      }

      const matchesStoredKeys =
        certificate.orgId === caller.orgId &&
        certificate.userId === userId &&
        certificate.email === target.email &&
        certificate.keysetVersion === target.keysetVersion &&
        certificate.role === target.role &&
        constantTimeEqual(
          certificate.encryptionPublicKey,
          target.encryptionPublicKey,
        ) &&
        constantTimeEqual(
          certificate.signingPublicKey,
          target.signingPublicKey,
        );

      // Clients verify certificates themselves; checking here only catches faulty clients early
      if (
        !matchesStoredKeys ||
        !verifyMemberCertificate(
          certificate,
          signature,
          new Map([[caller.userId, issuerKey]]),
        )
      ) {
        throw new DomainError(
          "invalid",
          "bad_request",
          "Certificate does not match the member's published keys",
        );
      }

      await memberships.certify(
        userId,
        {
          ...certificate,
          encryptionPublicKey: b64(certificate.encryptionPublicKey),
          signingPublicKey: b64(certificate.signingPublicKey),
        },
        signature,
        caller.userId,
        this.#context.now(),
      );

      if (recoveryKeyWrap !== undefined && target.role !== "member") {
        await organizations.putRecoveryKeyCopy(
          caller.orgId,
          userId,
          recoveryKeyWrap,
        );
      }

      await audit.record({
        orgId: caller.orgId,
        actorId: caller.userId,
        action: "org.member_confirmed",
        targetId: userId,
        ip: caller.ip,
      });
    });
  }
}
