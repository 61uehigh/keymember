import type { FastifyRequest } from "fastify";

import type { SymmetricKey } from "@keymember/core";

import type { ServiceContext } from "../services/ServiceContext.js";
import type { OidcClient } from "../services/OidcClient.js";
import type { AuthLimits } from "../services/auth/AuthLimits.js";
import { hashToken } from "../services/tokens.js";
import { clientIp } from "./clientIp.js";
import type { Caller } from "../domain/Caller.js";
import { DomainError } from "../domain/DomainError.js";
import type { MembershipRole, MembershipStatus } from "../domain/membership.js";

/**
 * ### AppContext
 *
 * Dependencies shared by every route, beyond what the services need. Built once by
 * {@link buildApp}.
 */
export interface AppContext extends ServiceContext {
  /**
   * ### serverSecret
   *
   * Server-only secret used to derive stable fake prelogin values for unknown emails.
   * Rotating it changes those fake values, which reveals nothing but breaks their stability.
   */
  readonly serverSecret: Uint8Array;

  /**
   * ### limits
   *
   * Rate limits on signing in and on replacing an authenticator.
   */
  readonly limits: AuthLimits;

  /**
   * ### sso
   *
   * The organisation's identity provider, when the server is configured with one.
   */
  readonly sso: OidcClient | undefined;

  /**
   * ### ssoTokenKey
   *
   * Server key that encrypts stored identity-provider refresh tokens, derived from the server secret.
   */
  readonly ssoTokenKey: SymmetricKey;
}

/**
 * ### Actor
 *
 * The authenticated caller of a request.
 */
export interface Actor {
  /**
   * ### userId
   *
   * Caller's user id.
   */
  readonly userId: string;

  /**
   * ### email
   *
   * Caller's email.
   */
  readonly email: string;

  /**
   * ### orgId
   *
   * Organisation the caller belongs to.
   */
  readonly orgId: string;

  /**
   * ### role
   *
   * Caller's role.
   */
  readonly role: MembershipRole;

  /**
   * ### status
   *
   * Caller's membership status.
   */
  readonly status: MembershipStatus;

  /**
   * ### familyId
   *
   * Session family of the presented token, used to revoke this login.
   */
  readonly familyId: string;
}

/**
 * ### ActorRequirement
 *
 * What a route demands of its caller.
 */
export interface ActorRequirement {
  /**
   * ### confirmed
   *
   * Whether the caller's keys must already be certified by an admin.
   *
   * @defaultValue `true` — only routes that bootstrap trust accept unconfirmed members
   */
  readonly confirmed?: boolean;

  /**
   * ### admin
   *
   * Whether the caller must be an owner or admin.
   *
   * @defaultValue `false`
   */
  readonly admin?: boolean;

  /**
   * ### allowWithoutTotp
   *
   * Whether the route stays usable while the organisation requires two-factor login and the
   * caller has not enrolled yet. Only routes needed to enrol (and to look around) set this.
   *
   * @defaultValue `false`
   */
  readonly allowWithoutTotp?: boolean;

  /**
   * ### allowWithoutSso
   *
   * Whether the route stays usable while the organisation requires SSO and the caller's login
   * has not passed it. Only routes that link SSO to the current login (and logout) set this.
   *
   * @defaultValue `false`
   */
  readonly allowWithoutSso?: boolean;
}

/**
 * ### requireActor
 *
 * Authenticates the bearer token of a request and checks the caller against a requirement.
 * Throws 401 for a missing, unknown, expired or revoked token and 403 when the caller
 * is suspended or lacks the required role or status.
 *
 * @param context Application context
 * @param request Incoming request
 * @param requirement What the route demands of its caller
 * @returns The authenticated caller
 */
export async function requireActor(
  context: AppContext,
  request: FastifyRequest,
  requirement: ActorRequirement = {},
): Promise<Actor> {
  const header = request.headers.authorization;
  const token =
    header?.startsWith("Bearer ") === true
      ? header.slice("Bearer ".length)
      : undefined;

  if (token === undefined) {
    throw new DomainError(
      "unauthenticated",
      "unauthorized",
      "Missing bearer token",
    );
  }

  const row = await context.store
    .repositories()
    .sessions.authenticate(hashToken(token), context.now());

  if (row === undefined) {
    throw new DomainError(
      "unauthenticated",
      "unauthorized",
      "Invalid or expired token",
    );
  }

  if (row.status === "suspended" || row.status === "recovering") {
    throw new DomainError(
      "forbidden",
      "membership_ended",
      `Membership is ${row.status}`,
    );
  }

  // Logins from before the policy was switched on stop working; the client signs in again
  if (row.ssoMissing && requirement.allowWithoutSso !== true) {
    throw new DomainError(
      "unauthenticated",
      "sso_required",
      "Your organisation requires signing in with its identity provider",
    );
  }

  if (row.totpMissing && requirement.allowWithoutTotp !== true) {
    throw new DomainError(
      "forbidden",
      "totp_enrollment_required",
      "Your organisation requires two-factor login; set it up first",
    );
  }

  if ((requirement.confirmed ?? true) && row.status !== "confirmed") {
    throw new DomainError(
      "forbidden",
      "not_confirmed",
      "Membership has not been confirmed by an admin yet",
    );
  }

  if (requirement.admin === true && row.role === "member") {
    throw new DomainError("forbidden", "forbidden", "Admin role required");
  }

  return {
    userId: row.userId,
    email: row.email,
    orgId: row.orgId,
    role: row.role,
    status: row.status,
    familyId: row.familyId,
  };
}

/**
 * ### callerOf
 *
 * The caller as services see them: who acts, for which organisation, from where.
 *
 * @param actor Authenticated caller
 * @param request Incoming request, for the audit IP
 * @returns The caller
 */
export function callerOf(actor: Actor, request: FastifyRequest): Caller {
  return {
    userId: actor.userId,
    orgId: actor.orgId,
    role: actor.role,
    ip: clientIp(request),
  };
}
