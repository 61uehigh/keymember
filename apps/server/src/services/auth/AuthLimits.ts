import { RateLimiter } from "../RateLimiter.js";

/**
 * ### FIFTEEN_MINUTES
 *
 * Window of every authentication limit.
 */
const FIFTEEN_MINUTES = 15 * 60 * 1000;

/**
 * ### AuthLimits
 *
 * The rate limits on signing in and on replacing an authenticator. Each lives in the memory of
 * one server process: several instances each keep their own counts.
 */
export interface AuthLimits {
  /**
   * ### login
   *
   * Failed logins per email and client address, so a stranger guessing cannot lock the owner out.
   */
  readonly login: RateLimiter;

  /**
   * ### loginEmail
   *
   * Failed logins per email from anywhere. Devices the account already signed in from are not
   * held back by it, so a flood of guesses cannot lock its owner out.
   */
  readonly loginEmail: RateLimiter;

  /**
   * ### prelogin
   *
   * Prelogin requests per client address; each one stores a login challenge.
   */
  readonly prelogin: RateLimiter;

  /**
   * ### totpReplace
   *
   * Wrong codes from the current authenticator when replacing it, per user.
   */
  readonly totpReplace: RateLimiter;
}

/**
 * ### TOTP_REPLACE_ATTEMPTS
 *
 * Wrong current codes allowed before the login trying them is ended.
 */
export const TOTP_REPLACE_ATTEMPTS = 5;

/**
 * ### createAuthLimits
 *
 * Fresh limits with the server's thresholds.
 *
 * @returns The limits
 */
export function createAuthLimits(): AuthLimits {
  return {
    login: new RateLimiter(10, FIFTEEN_MINUTES),
    loginEmail: new RateLimiter(50, FIFTEEN_MINUTES),
    prelogin: new RateLimiter(300, FIFTEEN_MINUTES),
    totpReplace: new RateLimiter(TOTP_REPLACE_ATTEMPTS, FIFTEEN_MINUTES),
  };
}
