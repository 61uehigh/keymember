import type { Repositories } from "../../repositories/Repositories.js";

export type { RecoveryStatus } from "../../repositories/RecoveryRepository.js";

/**
 * ### cancelOpenRecovery
 *
 * Cancels a `pending` or `approved` recovery of a user who just proved they still hold their
 * original credentials, and unfreezes the membership. A `rekeyed` recovery is not touched:
 * by then the original credentials no longer work.
 *
 * Runs inside the login's own transaction, after every check, so a login that fails late
 * cancels nothing.
 *
 * @param repositories Storage bound to the login's transaction
 * @param now Current time
 * @param userId User who logged in
 * @param orgId Organisation of the user
 * @param ip Client IP for the audit record
 * @returns Whether a recovery was cancelled
 */
export async function cancelOpenRecovery(
  repositories: Pick<Repositories, "audit" | "memberships" | "recoveries">,
  now: Date,
  userId: string,
  orgId: string,
  ip: string,
): Promise<boolean> {
  const cancelled = await repositories.recoveries.cancelOpen(userId, now);

  if (cancelled.length === 0) {
    return false;
  }

  await repositories.memberships.unfreeze(userId);

  for (const id of cancelled) {
    await repositories.audit.record({
      orgId,
      actorId: userId,
      action: "recovery.cancelled",
      targetId: id,
      detail: { by: "user_login" },
      ip,
    });
  }

  return true;
}
