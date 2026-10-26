import { signLoginChallenge } from "@keymember/core";

import { encode } from "./schemas.js";

/**
 * ### challengeSignature
 *
 * Signs the server's login challenge for one purpose. Login and password change both prove
 * the password this way; only the purpose and device differ.
 *
 * @param seed Login signing seed derived from the password
 * @param prelogin Prelogin response with the challenge
 * @param purpose What the proof is for
 * @param email Account email
 * @param deviceId Device signing in, or empty when no device is involved
 * @returns The encoded signature
 */
export function challengeSignature(
  seed: Uint8Array,
  prelogin: { challengeId: string; challenge: Uint8Array },
  purpose: "login" | "change-password",
  email: string,
  deviceId: string,
): string {
  return encode(
    signLoginChallenge(seed, {
      purpose,
      email,
      challengeId: prelogin.challengeId,
      challenge: prelogin.challenge,
      deviceId,
    }),
  );
}
