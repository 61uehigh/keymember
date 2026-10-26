import { verifyRecoveryKey } from "@keymember/core";

import type { Caller } from "../../domain/Caller.js";
import { DomainError } from "../../domain/DomainError.js";
import type { ServiceContext } from "../ServiceContext.js";

/**
 * ### RecoveryKeySetup
 *
 * The organisation's recovery key: its public half signed by the owner, and the private half
 * wrapped to the owner.
 */
export interface RecoveryKeySetup {
  readonly publicKey: Uint8Array;
  readonly signature: Uint8Array;
  readonly wrappedPrivateKey: Uint8Array;
}

/**
 * ### Policies
 *
 * Login policies to change; absent ones stay as they are.
 */
export interface Policies {
  readonly requireTotp?: boolean | undefined;
  readonly requireSso?: boolean | undefined;
}

/**
 * ### OrgSettings
 *
 * Organisation-wide settings: the recovery key, set once by the owner, and login policies.
 */
export class OrgSettings {
  readonly #context: ServiceContext;
  readonly #ssoConfigured: boolean;

  /**
   * ### constructor
   *
   * @param context Storage and clock
   * @param ssoConfigured Whether the server has an identity provider
   */
  constructor(context: ServiceContext, ssoConfigured: boolean) {
    this.#context = context;
    this.#ssoConfigured = ssoConfigured;
  }

  /**
   * ### setRecoveryKey
   *
   * Stores the recovery key, once; replacing it would orphan every vault key wrapped to it.
   *
   * @param caller The owner
   * @param setup The key
   */
  async setRecoveryKey(caller: Caller, setup: RecoveryKeySetup): Promise<void> {
    if (caller.role !== "owner") {
      throw new DomainError(
        "forbidden",
        "forbidden",
        "Only the owner sets up the recovery key",
      );
    }

    await this.#context.store.transaction(
      async ({ audit, organizations, users }) => {
        const hasKey = await organizations.lockRecoveryKey(caller.orgId);
        const ownerKey = await users.signingPublicKey(caller.userId);

        if (hasKey !== false || ownerKey === undefined) {
          throw new DomainError(
            "conflict",
            "conflict",
            "The recovery key is already set",
          );
        }

        if (
          !verifyRecoveryKey(
            ownerKey,
            { orgId: caller.orgId, publicKey: setup.publicKey },
            setup.signature,
          )
        ) {
          throw new DomainError(
            "invalid",
            "bad_request",
            "Recovery key signature is invalid",
          );
        }

        await organizations.setRecoveryKey(caller.orgId, {
          publicKey: setup.publicKey,
          signature: setup.signature,
          signerId: caller.userId,
        });
        await organizations.putRecoveryKeyCopy(
          caller.orgId,
          caller.userId,
          setup.wrappedPrivateKey,
        );
        await audit.record({
          orgId: caller.orgId,
          actorId: caller.userId,
          action: "org.recovery_key_set",
          ip: caller.ip,
        });
      },
    );
  }

  /**
   * ### updatePolicies
   *
   * Changes login policies. Requiring SSO needs a working identity provider, which the admin
   * proves by having linked their own login to it.
   *
   * @param caller Admin
   * @param familyId The admin's login
   * @param policies Policies to change
   */
  async updatePolicies(
    caller: Caller,
    familyId: string,
    policies: Policies,
  ): Promise<void> {
    const { store } = this.#context;

    if (policies.requireSso === true) {
      if (!this.#ssoConfigured) {
        throw new DomainError(
          "conflict",
          "sso_unavailable",
          "Configure the server's identity provider before requiring SSO",
        );
      }

      // A misconfigured provider would lock everyone out; proving it works for this admin first prevents that
      if ((await store.repositories().sso.link(familyId)) === undefined) {
        throw new DomainError(
          "conflict",
          "sso_not_linked",
          "Sign in with the identity provider yourself before requiring it",
        );
      }
    }

    await store.transaction(async ({ audit, organizations }) => {
      await organizations.updatePolicies(caller.orgId, policies);
      await audit.record({
        orgId: caller.orgId,
        actorId: caller.userId,
        action: "org.policy_updated",
        detail: {
          ...(policies.requireTotp === undefined
            ? {}
            : { requireTotp: policies.requireTotp }),
          ...(policies.requireSso === undefined
            ? {}
            : { requireSso: policies.requireSso }),
        },
        ip: caller.ip,
      });
    });
  }
}
