import type { Caller } from "../../domain/Caller.js";
import { DomainError } from "../../domain/DomainError.js";
import type { RateLimiter } from "../RateLimiter.js";
import type { ServiceContext } from "../ServiceContext.js";
import { generateTotpSecret, verifyTotp } from "../totp.js";

/**
 * ### TwoFactorEnrollment
 *
 * A member setting up, or replacing, the authenticator they sign in with.
 *
 * Replacing an authenticator needs a code from the current one. Each such code is used up like
 * a login code, and a login that keeps guessing is ended: a stolen session token alone cannot
 * swap the second factor.
 */
export class TwoFactorEnrollment {
  readonly #context: ServiceContext;
  readonly #replaceLimiter: RateLimiter;

  /**
   * ### constructor
   *
   * @param context Storage and clock
   * @param replaceLimiter Wrong current codes per user
   */
  constructor(context: ServiceContext, replaceLimiter: RateLimiter) {
    this.#context = context;
    this.#replaceLimiter = replaceLimiter;
  }

  /**
   * ### start
   *
   * Stores a new secret waiting for its first code.
   *
   * @param caller The member
   * @returns The secret to show to the authenticator app
   */
  async start(caller: Caller): Promise<Uint8Array> {
    const secret = generateTotpSecret();

    await this.#context.store
      .repositories()
      .users.setPendingTotp(caller.userId, secret);

    return secret;
  }

  /**
   * ### confirm
   *
   * Makes the pending secret the active one once a code from it checks out, after a code from
   * the current authenticator when one is set.
   *
   * @param caller The member
   * @param familyId Their login, ended when it guesses too often
   * @param code Code from the new authenticator
   * @param currentCode Code from the current authenticator, if any
   */
  async confirm(
    caller: Caller,
    familyId: string,
    code: string,
    currentCode: string | undefined,
  ): Promise<void> {
    const now = this.#context.now();
    const { users } = this.#context.store.repositories();
    const totp = await users.totpState(caller.userId);

    if (totp?.secret !== undefined) {
      await this.#checkCurrent(
        caller,
        familyId,
        totp.secret,
        totp.lastStep,
        currentCode,
      );
    }

    if (totp?.pendingSecret === undefined) {
      throw new DomainError(
        "invalid",
        "bad_request",
        "Start two-factor setup first",
      );
    }

    const step = verifyTotp(totp.pendingSecret, code, now, undefined);

    if (step === undefined) {
      throw new DomainError(
        "invalid",
        "invalid_totp",
        "Code does not match; check the device clock",
      );
    }

    await this.#context.store.transaction(async ({ audit, users }) => {
      await users.confirmTotp(caller.userId, step);
      await audit.record({
        orgId: caller.orgId,
        actorId: caller.userId,
        action: "account.totp_enabled",
        ip: caller.ip,
      });
    });
  }

  /**
   * ### #checkCurrent
   *
   * Checks and uses up a code from the current authenticator. Too many wrong codes end the
   * login that sent them.
   *
   * @param caller The member
   * @param familyId Their login
   * @param secret Current secret
   * @param lastStep Step of the last code used
   * @param currentCode Code sent, if any
   */
  async #checkCurrent(
    caller: Caller,
    familyId: string,
    secret: Uint8Array,
    lastStep: number | undefined,
    currentCode: string | undefined,
  ): Promise<void> {
    const now = this.#context.now();
    const key = caller.userId;

    if (this.#replaceLimiter.isBlocked(key, now.getTime())) {
      throw new DomainError(
        "rate_limited",
        "rate_limited",
        "Too many wrong codes; try again later",
      );
    }

    const step =
      currentCode === undefined
        ? undefined
        : verifyTotp(secret, currentCode, now, lastStep);

    // Claimed atomically, like a login code, so one code cannot be replayed
    if (
      step !== undefined &&
      (await this.#context.store
        .repositories()
        .users.claimTotpStep(caller.userId, step))
    ) {
      this.#replaceLimiter.reset(key);

      return;
    }

    // A missing code is a mistake of the app, not a guess
    if (currentCode !== undefined) {
      this.#replaceLimiter.recordFailure(key, now.getTime());

      if (this.#replaceLimiter.isBlocked(key, now.getTime())) {
        await this.#context.store.transaction(async ({ audit, sessions }) => {
          await sessions.revokeFamily(familyId, now);
          await audit.record({
            orgId: caller.orgId,
            actorId: caller.userId,
            action: "account.totp_replace_locked",
            ip: caller.ip,
          });
        });
      }
    }

    throw new DomainError(
      "forbidden",
      "invalid_totp",
      "Enter a code from your current authenticator to replace it",
    );
  }
}
