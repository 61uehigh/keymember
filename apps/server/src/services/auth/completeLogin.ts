import { randomUUID } from "node:crypto";

import { b64 } from "../../http/codec.js";
import type { Repositories } from "../../repositories/Repositories.js";
import type { LoginAccount } from "../../repositories/UserRepository.js";
import { cancelOpenRecovery } from "../recovery/cancelOpenRecovery.js";
import type { ServiceContext } from "../ServiceContext.js";
import { issueTokens } from "../tokens.js";

/**
 * ### completeLogin
 *
 * Starts a new session family for a user who passed every login check, and returns what the
 * client needs to unlock: tokens, profile and the encrypted keyset.
 *
 * Signing in with the original credentials proves the user still has them, so any recovery
 * started on their behalf is cancelled here (guards against a rogue pair of admins). Every
 * login path ends here, inside its transaction and after all of its checks.
 *
 * @param repositories Storage bound to the login's transaction
 * @param context The clock
 * @param ip Where the login came from, for the audit log
 * @param user The user signing in
 * @param device Device the session belongs to
 * @param sso SSO result to attach to the new login, if it passed SSO
 * @returns The login response
 */
export async function completeLogin(
  repositories: Repositories,
  context: Pick<ServiceContext, "now">,
  ip: string,
  user: LoginAccount,
  device: { deviceId: string; deviceName: string },
  sso?: { subject: string; encryptedRefreshToken: Uint8Array },
): Promise<Record<string, unknown>> {
  const now = context.now();
  const recoveryCancelled = await cancelOpenRecovery(
    repositories,
    now,
    user.id,
    user.orgId,
    ip,
  );
  const familyId = randomUUID();
  const tokens = await issueTokens(
    repositories.sessions,
    { userId: user.id, ...device, familyId },
    now,
  );

  if (sso !== undefined) {
    await repositories.sso.putLink(familyId, user.id, {
      subject: sso.subject,
      encryptedRefreshToken: sso.encryptedRefreshToken,
      checkedAt: now,
    });
  }

  await repositories.audit.record({
    orgId: user.orgId,
    actorId: user.id,
    action: "auth.login",
    detail: { deviceName: device.deviceName, sso: sso !== undefined },
    ip: ip,
  });

  return {
    ...tokens,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      status: recoveryCancelled ? "confirmed" : user.status,
    },
    recoveryCancelled,
    keyset: {
      encryptedAccountKey: b64(user.keyset.encryptedAccountKey),
      encryptedPrivateKeys: b64(user.keyset.encryptedPrivateKeys),
      encryptionPublicKey: b64(user.keyset.encryptionPublicKey),
      signingPublicKey: b64(user.keyset.signingPublicKey),
      keysetVersion: user.keyset.keysetVersion,
      selfSignature: b64(user.keyset.selfSignature),
    },
  };
}
