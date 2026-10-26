import type { LoginChallengeRepository } from "../repositories/LoginChallengeRepository.js";
import { COLLECTIONS } from "./collections.js";
import type { Documents } from "./Documents.js";
import { bytes, date, optionalDate, text } from "./fields.js";
import { insertNew } from "./insertNew.js";

const LOGIN_CHALLENGES = COLLECTIONS.loginChallenges;

/**
 * ### CLEANUP_PAGE
 *
 * Most expired challenges removed while issuing one.
 */
const CLEANUP_PAGE = 20;

/**
 * ### FirestoreLoginChallengeRepository
 *
 * {@link LoginChallengeRepository} on Firestore. Challenges are keyed by id; issuing one prunes
 * the expired ones, which keeps the collection small enough to scan.
 */
export class FirestoreLoginChallengeRepository implements LoginChallengeRepository {
  readonly #docs: Documents;

  /**
   * ### constructor
   *
   * @param docs Documents to work in, inside a transaction or not
   */
  constructor(docs: Documents) {
    this.#docs = docs;
  }

  /**
   * ### issue
   *
   * @see {@link LoginChallengeRepository.issue}
   */
  async issue(
    challenge: {
      id: string;
      email: string;
      challenge: Uint8Array;
      expiresAt: Date;
    },
    now: Date,
  ): Promise<void> {
    // Only expired challenges are read, a page at a time, so each is read once when removed:
    // the cost per request stays constant however many live challenges there are
    for (const expired of await this.#docs.findBefore(
      LOGIN_CHALLENGES,
      "expiresAt",
      now,
      CLEANUP_PAGE,
    )) {
      await this.#docs.delete(LOGIN_CHALLENGES, expired.id);
    }

    await insertNew(this.#docs, LOGIN_CHALLENGES, challenge.id, {
      id: challenge.id,
      email: challenge.email,
      challenge: challenge.challenge,
      expiresAt: challenge.expiresAt,
      usedAt: null,
    });
  }

  /**
   * ### consume
   *
   * @see {@link LoginChallengeRepository.consume}
   */
  async consume(
    challengeId: string,
    email: string,
    now: Date,
  ): Promise<Uint8Array | undefined> {
    // One transaction, so two requests with the same challenge cannot both use it
    return this.#docs.atomic(async (docs) => {
      const challenge = await docs.get(LOGIN_CHALLENGES, challengeId);

      if (
        challenge === undefined ||
        text(challenge, "email") !== email ||
        optionalDate(challenge, "usedAt") !== undefined ||
        date(challenge, "expiresAt") <= now
      ) {
        return undefined;
      }

      await docs.update(LOGIN_CHALLENGES, challengeId, { usedAt: now });

      return bytes(challenge, "challenge");
    });
  }
}
