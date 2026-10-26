import { randomUUID } from "node:crypto";

import {
  openBytes,
  randomBytes,
  sealBytes,
  toBase64Url,
  utf8Decode,
  utf8Encode,
} from "@keymember/core";

import type { AppContext } from "../http/AppContext.js";
import { DomainError } from "../domain/DomainError.js";
import type { SsoRepository } from "../repositories/SsoRepository.js";
import { hashToken } from "./tokens.js";

/**
 * ### SSO_TICKET_TTL_MS
 *
 * How long a user has to finish signing in with the identity provider: 10 minutes.
 */
export const SSO_TICKET_TTL_MS = 10 * 60 * 1000;

/**
 * ### SSO_GRACE_MS
 *
 * How long keymember keeps refreshing a login while the identity provider cannot be reached:
 * 1 hour since the last successful check. A provider that answers "revoked" ends the login at once.
 */
export const SSO_GRACE_MS = 60 * 60 * 1000;

/**
 * ### SsoTicket
 *
 * A pending SSO check handed to the client. The id goes into the browser URL; the secret stays
 * with the client and is needed to collect the result, so whoever completes the provider login
 * in a browser cannot also take the session.
 */
export interface SsoTicket {
  readonly ssoRequired: true;
  readonly ticketId: string;
  readonly ticketSecret: string;
  readonly url: string;
  readonly expiresAt: string;
}

/**
 * ### sealRefreshToken
 *
 * Encrypts a provider refresh token under the server key, bound to the subject it belongs to.
 *
 * @param context Shared dependencies
 * @param refreshToken Provider refresh token
 * @param subject Provider subject the token was issued for
 * @returns The ciphertext to store
 */
export function sealRefreshToken(
  context: AppContext,
  refreshToken: string,
  subject: string,
): Uint8Array {
  return sealBytes(context.ssoTokenKey, utf8Encode(refreshToken), {
    kind: "server.sso_refresh_token",
    scope: [subject],
  });
}

/**
 * ### openRefreshToken
 *
 * Decrypts a refresh token sealed by {@link sealRefreshToken}.
 *
 * @param context Shared dependencies
 * @param ciphertext Stored ciphertext
 * @param subject Provider subject the token was issued for
 * @returns The provider refresh token
 */
export function openRefreshToken(
  context: AppContext,
  ciphertext: Uint8Array,
  subject: string,
): string {
  return utf8Decode(
    openBytes(context.ssoTokenKey, ciphertext, {
      kind: "server.sso_refresh_token",
      scope: [subject],
    }),
  );
}

/**
 * ### createSsoTicket
 *
 * Records a pending SSO check and returns the ticket for the client. Expired tickets are
 * pruned on the way.
 *
 * @param sso SSO storage
 * @param context Shared dependencies
 * @param ticket What the check is for: a login on a device, or linking an existing login
 * @returns The ticket
 */
export async function createSsoTicket(
  sso: Pick<SsoRepository, "insertTicket">,
  context: Pick<AppContext, "sso" | "now">,
  ticket:
    | {
        kind: "login";
        userId: string;
        deviceId: string;
        deviceName: string;
      }
    | { kind: "link"; userId: string; familyId: string },
): Promise<SsoTicket> {
  if (context.sso === undefined) {
    throw new DomainError(
      "unavailable",
      "sso_unavailable",
      "This server has no identity provider configured",
    );
  }

  const now = context.now();
  const id = randomUUID();
  const secret = toBase64Url(randomBytes(32));
  const expiresAt = new Date(now.getTime() + SSO_TICKET_TTL_MS);

  await sso.insertTicket(
    {
      id,
      secretHash: hashToken(secret),
      kind: ticket.kind,
      userId: ticket.userId,
      familyId: ticket.kind === "link" ? ticket.familyId : undefined,
      deviceId: ticket.kind === "login" ? ticket.deviceId : undefined,
      deviceName: ticket.kind === "login" ? ticket.deviceName : undefined,
      state: toBase64Url(randomBytes(32)),
      nonce: toBase64Url(randomBytes(32)),
      codeVerifier: toBase64Url(randomBytes(32)),
      expiresAt,
    },
    now,
  );

  return {
    ssoRequired: true,
    ticketId: id,
    ticketSecret: secret,
    url: `/api/auth/sso/start?ticket=${id}`,
    expiresAt: expiresAt.toISOString(),
  };
}

/**
 * ### checkSsoOnRefresh
 *
 * Decides whether a login may be refreshed as far as SSO is concerned. A login that passed SSO
 * is re-checked with the provider on every refresh: a refusal ends the whole login, an
 * unreachable provider is tolerated for {@link SSO_GRACE_MS}. A login that never passed SSO is
 * refused while the organisation requires it.
 *
 * @param context Shared dependencies
 * @param session The session being refreshed
 * @param ip Client IP for the audit log
 */
export async function checkSsoOnRefresh(
  context: AppContext,
  session: {
    familyId: string;
    userId: string;
    orgId: string;
    requireSso: boolean;
  },
  ip: string,
): Promise<void> {
  const link = await context.store.repositories().sso.link(session.familyId);
  const now = context.now();
  const revoke = async (reason: string): Promise<never> => {
    await context.store.transaction(async (repos) => {
      const { audit, sessions, sso } = repos;

      await sessions.revokeFamily(session.familyId, now);
      await sso.removeLink(session.familyId);
      await audit.record({
        orgId: session.orgId,
        actorId: session.userId,
        action: "auth.sso_revoked",
        detail: { reason },
        ip,
      });
    });

    throw new DomainError(
      "unauthenticated",
      reason === "policy" ? "sso_required" : "sso_revoked",
      reason === "policy"
        ? "Your organisation requires signing in with its identity provider"
        : "The identity provider no longer vouches for this account",
    );
  };

  if (link === undefined) {
    if (session.requireSso) {
      await revoke("policy");
    }

    return;
  }

  // A server whose provider was removed cannot check; the policy cannot be on without one
  if (context.sso === undefined) {
    return;
  }

  const outcome = await context.sso.checkAccount(
    openRefreshToken(context, link.encryptedRefreshToken, link.subject),
  );

  if (outcome.status === "revoked") {
    await revoke("provider");
  }

  if (outcome.status === "unavailable") {
    if (now.getTime() - link.checkedAt.getTime() > SSO_GRACE_MS) {
      throw new DomainError(
        "unavailable",
        "sso_unavailable",
        "The identity provider cannot be reached; try again later",
      );
    }

    return;
  }

  await context.store
    .repositories()
    .sso.recordCheck(
      session.familyId,
      now,
      outcome.status === "active" && outcome.refreshToken !== undefined
        ? sealRefreshToken(context, outcome.refreshToken, link.subject)
        : undefined,
    );
}
