import type { Queryable } from "../../db/Database.js";
import type { LoginChallengeRepository } from "../LoginChallengeRepository.js";

/**
 * ### PgLoginChallengeRepository
 *
 * {@link LoginChallengeRepository} on PostgreSQL.
 */
export class PgLoginChallengeRepository implements LoginChallengeRepository {
  readonly #db: Queryable;

  /**
   * ### constructor
   *
   * @param db Connection or transaction to work in
   */
  constructor(db: Queryable) {
    this.#db = db;
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
    await this.#db.query("DELETE FROM login_challenges WHERE expires_at < $1", [
      now,
    ]);
    await this.#db.query(
      "INSERT INTO login_challenges (id, email, challenge, expires_at) VALUES ($1, $2, $3, $4)",
      [challenge.id, challenge.email, challenge.challenge, challenge.expiresAt],
    );
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
    const [row] = await this.#db.query<{ challenge: Uint8Array }>(
      `UPDATE login_challenges SET used_at = $3
        WHERE id = $1 AND email = $2 AND used_at IS NULL AND expires_at > $3
        RETURNING challenge`,
      [challengeId, email, now],
    );

    return row?.challenge;
  }
}
