import {
  RECOVERY_PRINCIPAL_ID,
  signRecoveryRequest,
  verifyRecoveryRequest,
  unwrapGroupPrivateKey,
  unwrapVaultKey,
} from "@keymember/core";
import { z } from "zod";

import { grantVaultKey, groupKeyCopy } from "./grants.js";
import { b64, encode, parseResponse } from "./schemas.js";
import type { RecoveryAdminDeps, VaultPermission } from "./Session.type.js";

/**
 * ### RecoveryStatus
 *
 * Lifecycle of an account recovery: `pending` → `approved` → `rekeyed` → `completed`,
 * or `cancelled` at any point before completion.
 */
export type RecoveryStatus =
  "pending" | "approved" | "rekeyed" | "completed" | "cancelled";

/**
 * ### RecoverySummary
 *
 * A recovery as listed for admins.
 */
export interface RecoverySummary {
  /**
   * ### id
   *
   * Recovery id.
   */
  readonly id: string;

  /**
   * ### userId
   *
   * Member being recovered.
   */
  readonly userId: string;

  /**
   * ### email
   *
   * Member's email.
   */
  readonly email: string;

  /**
   * ### status
   *
   * Current step.
   */
  readonly status: RecoveryStatus;

  /**
   * ### requestedBy
   *
   * Admin who requested it.
   */
  readonly requestedBy: string;

  /**
   * ### approvedBy
   *
   * Admin who approved it, once approved.
   */
  readonly approvedBy: string | null;

  /**
   * ### createdAt
   *
   * When it was requested, as an ISO 8601 timestamp.
   */
  readonly createdAt: string;

  /**
   * ### vaults
   *
   * Vault access the member had when the recovery was requested; exactly this is restored.
   */
  readonly vaults: ReadonlyArray<{
    vaultId: string;
    permission: VaultPermission;
  }>;

  /**
   * ### groups
   *
   * Groups the member belonged to when the recovery was requested; exactly these are restored.
   */
  readonly groups: ReadonlyArray<string>;
}

const recoverySchema = z.object({
  id: z.string(),
  userId: z.string(),
  email: z.string(),
  status: z.enum(["pending", "approved", "rekeyed", "completed", "cancelled"]),
  requestedBy: z.string(),
  approvedBy: z.string().nullable(),
  createdAt: z.string(),
  vaults: z.array(
    z.object({
      vaultId: z.string(),
      permission: z.enum(["view", "edit", "manage"]),
    }),
  ),
  groups: z.array(z.string()),
});

/**
 * ### RecoveryAdmin
 *
 * Admin side of account recovery. Two different admins must take part (request and approve);
 * the server enforces that. The admins never see the member's password, Secret Key or
 * personal keys: they only re-wrap vault keys the recovery key already held.
 */
export class RecoveryAdmin {
  readonly #session: RecoveryAdminDeps;

  /**
   * ### constructor
   *
   * Created by {@link Session.recovery}.
   *
   * @param session Internals of the admin's session
   */
  constructor(session: RecoveryAdminDeps) {
    this.#session = session;
  }

  /**
   * ### list
   *
   * Lists recent recoveries of the organisation, newest first.
   *
   * @returns Recovery summaries
   */
  async list(): Promise<Array<RecoverySummary>> {
    return parseResponse(
      z.object({ recoveries: z.array(recoverySchema) }),
      await this.#session.request({
        method: "GET",
        path: "/api/org/recoveries",
      }),
    ).recoveries;
  }

  /**
   * ### request
   *
   * Starts a recovery for a member who lost their password or Secret Key. Nothing happens
   * to the member's account until a second admin approves.
   *
   * @param userId Member to recover
   * @returns The recovery id
   */
  async request(userId: string): Promise<string> {
    const org = await this.#session.fetchOrg();
    const id = crypto.randomUUID();
    const current = this.#session.trust(org).certified.get(userId);

    if (current === undefined) {
      throw new Error(
        "This member's key isn't verified, so recovery can't be requested.",
      );
    }

    return parseResponse(
      z.object({ id: z.string() }),
      await this.#session.request({
        method: "POST",
        path: "/api/org/recoveries",
        body: {
          userId,
          id,
          keysetVersion: current.keysetVersion,
          // Names whose account this is for, and which keys it replaces; the completing admin
          // re-wraps keys only to that member's next keys
          signature: encode(
            signRecoveryRequest(this.#session.keyset.signing.privateKey, {
              orgId: org.org.id,
              recoveryId: id,
              userId,
              requestedBy: this.#session.user.id,
              keysetVersion: current.keysetVersion,
            }),
          ),
        },
      }),
    ).id;
  }

  /**
   * ### approve
   *
   * Approves another admin's request. Freezes the member's account and returns a one-time
   * token to hand to the member in person or over a trusted channel. Logging in with their old
   * credentials before using it cancels the recovery.
   *
   * @param recoveryId Recovery to approve
   * @returns The recovery token and its expiry
   */
  async approve(
    recoveryId: string,
  ): Promise<{ recoveryToken: string; expiresAt: string }> {
    return parseResponse(
      z.object({ recoveryToken: z.string(), expiresAt: z.string() }),
      await this.#session.request({
        method: "POST",
        path: `/api/org/recoveries/${recoveryId}/approve`,
      }),
    );
  }

  /**
   * ### cancel
   *
   * Cancels a recovery that has not completed and unfreezes the account if it was frozen.
   *
   * @param recoveryId Recovery to cancel
   */
  async cancel(recoveryId: string): Promise<void> {
    await this.#session.request({
      method: "POST",
      path: `/api/org/recoveries/${recoveryId}/cancel`,
    });
  }

  /**
   * ### complete
   *
   * Finishes a recovery after the member re-enrolled and an admin certified their new keys:
   * unwraps each former vault key and group key with the recovery key and wraps it to the
   * member's new, certified encryption key.
   *
   * @param recoveryId Recovery to complete
   * @returns Number of vaults and groups restored
   */
  async complete(
    recoveryId: string,
  ): Promise<{ vaults: number; groups: number }> {
    const response = parseResponse(
      z.object({
        userId: z.string(),
        requestedBy: z.string(),
        requestSignature: b64.nullable(),
        vaults: z.array(
          z.object({
            vaultId: z.string(),
            keyGeneration: z.number().int(),
            recoveryWrappedKey: b64,
          }),
        ),
        groups: z.array(
          z.object({
            groupId: z.string(),
            keysetVersion: z.number().int(),
            encryptionPublicKey: b64,
            recoveryWrappedKey: b64,
          }),
        ),
      }),
      await this.#session.request({
        method: "GET",
        path: `/api/org/recoveries/${recoveryId}/vault-keys`,
      }),
    );
    const org = await this.#session.fetchOrg();
    const { certified: verified, issuers } = this.#session.trust(org);
    const certificate = verified.get(response.userId);

    if (certificate === undefined) {
      throw new Error(
        "Verify the member's new key before completing the recovery.",
      );
    }

    // The server says whom to restore; only a trusted admin's signed request may decide that.
    // The request names the keys being replaced, so this verifies only for the next version:
    // keys are never re-wrapped to the old ones a server might keep serving
    if (
      response.requestSignature === null ||
      !verifyRecoveryRequest(
        {
          orgId: org.org.id,
          recoveryId,
          userId: response.userId,
          requestedBy: response.requestedBy,
          keysetVersion: certificate.keysetVersion - 1,
        },
        response.requestSignature,
        issuers,
      )
    ) {
      throw new Error(
        "This recovery wasn't requested by a trusted admin, or it points to someone else or to an old key.",
      );
    }

    const recoveryKey = await this.#session.recoveryKeyPair();
    const access = [];

    for (const vault of response.vaults) {
      const vaultKey = await unwrapVaultKey(
        vault.recoveryWrappedKey,
        vault.vaultId,
        vault.keyGeneration,
        RECOVERY_PRINCIPAL_ID,
        recoveryKey,
      );

      access.push({
        vaultId: vault.vaultId,
        keyGeneration: vault.keyGeneration,
        ...(await grantVaultKey(
          this.#session.keyset.signing.privateKey,
          vaultKey,
          {
            vaultId: vault.vaultId,
            keyGeneration: vault.keyGeneration,
            principalType: "user",
            principalId: response.userId,
            encryptionPublicKey: certificate.encryptionPublicKey,
          },
        )),
      });
    }

    const certifiedGroups = new Map(
      (await this.#session.groups()).map((group) => [
        group.id,
        group.certificate,
      ]),
    );
    const groups = [];

    for (const group of response.groups) {
      const groupCertificate = certifiedGroups.get(group.groupId);

      // Only a group key a trusted admin vouched for is handed back
      if (groupCertificate?.keysetVersion !== group.keysetVersion) {
        throw new Error(
          `Group ${group.groupId} has no verified certificate at that version`,
        );
      }

      const groupKey = await unwrapGroupPrivateKey(
        group.recoveryWrappedKey,
        group.groupId,
        group.keysetVersion,
        RECOVERY_PRINCIPAL_ID,
        recoveryKey,
        groupCertificate.encryptionPublicKey,
      );

      const copy = await groupKeyCopy(
        this.#session.keyset.signing.privateKey,
        groupKey,
        {
          groupId: group.groupId,
          keysetVersion: group.keysetVersion,
          userId: response.userId,
          encryptionPublicKey: certificate.encryptionPublicKey,
        },
      );

      groups.push({
        groupId: group.groupId,
        keysetVersion: group.keysetVersion,
        wrappedPrivateKey: copy.wrappedPrivateKey,
        membershipSignature: copy.membershipSignature,
      });
    }

    await this.#session.request({
      method: "POST",
      path: `/api/org/recoveries/${recoveryId}/complete`,
      body: { access, groups },
    });

    return { vaults: access.length, groups: groups.length };
  }
}
