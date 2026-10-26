import { randomUUID } from "node:crypto";

import {
  constantTimeEqual,
  deriveAuthVerifier,
  randomBytes,
  verifyLoginChallenge,
} from "@keymember/core";
import type { LoginPurpose } from "@keymember/core";

import type { LoginChallengeRepository } from "../repositories/LoginChallengeRepository.js";

/**
 * ### LOGIN_CHALLENGE_TTL_MS
 *
 * How long a login challenge from prelogin stays usable: 2 minutes.
 */
export const LOGIN_CHALLENGE_TTL_MS = 2 * 60 * 1000;

/**
 * ### issueLoginChallenge
 *
 * Stores a fresh single-use challenge for an email. Issued for unknown emails too, so prelogin
 * looks the same whether or not the account exists.
 *
 * @param challenges Login challenge storage
 * @param email Email the challenge is for
 * @param now Current time
 * @returns Challenge id and bytes
 */
export async function issueLoginChallenge(
  challenges: Pick<LoginChallengeRepository, "issue">,
  email: string,
  now: Date,
): Promise<{ challengeId: string; challenge: Uint8Array }> {
  const challengeId = randomUUID();
  const challenge = randomBytes(32);

  await challenges.issue(
    {
      id: challengeId,
      email,
      challenge,
      expiresAt: new Date(now.getTime() + LOGIN_CHALLENGE_TTL_MS),
    },
    now,
  );

  return { challengeId, challenge };
}

/**
 * ### LoginProof
 *
 * What a client presents to prove its credentials: a signature over a challenge, or, for an
 * account that has not switched to signed login yet, the legacy authentication key.
 */
export type LoginProof =
  | { readonly challengeId: string; readonly signature: Uint8Array }
  | { readonly authKey: Uint8Array };

/**
 * ### checkLoginProof
 *
 * Verifies a login proof against the stored credential. A challenge is consumed whether or not
 * the signature is valid, so each one can be tried once.
 *
 * @param challenges Login challenge storage
 * @param user Stored credential of the account
 * @param proof Proof from the client
 * @param context Email, device and purpose the signature must cover
 * @param now Current time
 * @returns Whether the proof is valid
 */
export async function checkLoginProof(
  challenges: Pick<LoginChallengeRepository, "consume">,
  user: {
    authPublicKey: Uint8Array | undefined;
    authVerifier: Uint8Array | undefined;
  },
  proof: LoginProof,
  context: { email: string; deviceId: string; purpose: LoginPurpose },
  now: Date,
): Promise<boolean> {
  if ("authKey" in proof) {
    // Legacy accounts only: once an account has a login key, its old secret no longer works
    return (
      user.authPublicKey === undefined &&
      user.authVerifier !== undefined &&
      constantTimeEqual(deriveAuthVerifier(proof.authKey), user.authVerifier)
    );
  }

  const challenge = await challenges.consume(
    proof.challengeId,
    context.email,
    now,
  );

  return (
    challenge !== undefined &&
    user.authPublicKey !== undefined &&
    verifyLoginChallenge(
      user.authPublicKey,
      {
        purpose: context.purpose,
        email: context.email,
        challengeId: proof.challengeId,
        challenge,
        deviceId: context.deviceId,
      },
      proof.signature,
    )
  );
}
