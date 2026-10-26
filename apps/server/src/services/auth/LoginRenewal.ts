import { DomainError } from "../../domain/DomainError.js";
import type { AppContext } from "../../http/AppContext.js";
import { checkSsoOnRefresh, openRefreshToken } from "../sso.js";
import { hashToken, issueTokens } from "../tokens.js";
import type { IssuedTokens } from "../tokens.js";

/**
 * ### LoginRenewal
 *
 * Keeping a login going and ending it: swapping the refresh token for a new pair, and logout.
 * A refresh token presented twice means it was copied, and ends the whole login.
 */
export class LoginRenewal {
  readonly #context: AppContext;

  /**
   * ### constructor
   *
   * @param context Storage, clock and the identity provider that re-checks SSO logins
   */
  constructor(context: AppContext) {
    this.#context = context;
  }

  /**
   * ### refresh
   *
   * Swaps a refresh token for a new pair.
   *
   * @param refreshToken Token from the client
   * @param ip Where the request came from, for the audit log
   * @returns The new token pair
   */
  async refresh(refreshToken: string, ip: string): Promise<IssuedTokens> {
    const context = this.#context;
    const now = context.now();
    const refreshHash = hashToken(refreshToken);
    const current = await context.store
      .repositories()
      .sessions.refreshTarget(refreshHash);

    // Asks the identity provider outside the transaction; reuse detection below still runs as before
    if (current !== undefined) {
      await checkSsoOnRefresh(context, current, ip);
    }

    const result = await context.store.transaction(
      async ({ audit, sessions }) => {
        const session = await sessions.lockForRefresh(refreshHash);

        if (session === undefined) {
          throw new DomainError(
            "unauthenticated",
            "unauthorized",
            "Unknown refresh token",
          );
        }

        if (session.spent) {
          // A rotated token being presented again means it was copied: end every session in the family
          await sessions.revokeFamily(session.familyId, now);
          await audit.record({
            orgId: session.orgId,
            actorId: session.userId,
            action: "auth.refresh_reuse_detected",
            detail: { deviceName: session.deviceName },
            ip,
          });

          return { revoked: true as const };
        }

        if (session.refreshExpiresAt <= now) {
          throw new DomainError(
            "unauthenticated",
            "unauthorized",
            "Refresh token expired",
          );
        }

        await sessions.markRotated(refreshHash, now);

        return issueTokens(
          sessions,
          {
            userId: session.userId,
            deviceId: session.deviceId,
            deviceName: session.deviceName,
            familyId: session.familyId,
          },
          now,
        );
      },
    );

    // The revocation must commit, so the 401 is raised only after the transaction has finished
    if ("revoked" in result) {
      throw new DomainError(
        "unauthenticated",
        "unauthorized",
        "Refresh token reuse detected; all sessions of this login were revoked",
      );
    }

    return result;
  }

  /**
   * ### logout
   *
   * Ends a login and lets go of the identity provider's token kept for it.
   *
   * @param familyId The login
   */
  async logout(familyId: string): Promise<void> {
    const context = this.#context;
    const { sessions, sso } = context.store.repositories();

    await sessions.revokeFamily(familyId, context.now());

    // The provider refresh token was kept only to re-check this login; it has no use any more
    const link = await sso.removeLink(familyId);

    if (link !== undefined && context.sso !== undefined) {
      await context.sso.revoke(
        openRefreshToken(context, link.encryptedRefreshToken, link.subject),
      );
    }
  }
}
