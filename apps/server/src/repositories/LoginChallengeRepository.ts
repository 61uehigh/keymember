/**
 * ### LoginChallengeRepository
 *
 * Single-use challenges a client signs to prove it holds the login key.
 */
export interface LoginChallengeRepository {
  /**
   * ### issue
   *
   * Stores a new challenge for an email, first dropping expired ones.
   *
   * @param challenge Id, email, random bytes and expiry
   * @param now Current time
   */
  issue(
    challenge: {
      id: string;
      email: string;
      challenge: Uint8Array;
      expiresAt: Date;
    },
    now: Date,
  ): Promise<void>;

  /**
   * ### consume
   *
   * Uses up an unexpired challenge issued for this email.
   *
   * @param challengeId Challenge
   * @param email Email it must have been issued for
   * @param now Current time
   * @returns The challenge bytes, or `undefined` when unknown, used, expired or for another email
   */
  consume(
    challengeId: string,
    email: string,
    now: Date,
  ): Promise<Uint8Array | undefined>;
}
