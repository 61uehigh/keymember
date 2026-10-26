import { DEFAULT_KDF_PARAMS, SALT_LENGTH, utf8Encode } from "@keymember/core";
import type { KdfParams } from "@keymember/core";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { DomainError } from "../../domain/DomainError.js";
import type { AppContext } from "../../http/AppContext.js";
import type { AuditEntry } from "../../repositories/AuditRepository.js";
import type { LoginAccount } from "../../repositories/UserRepository.js";
import { checkLoginProof, issueLoginChallenge } from "../loginChallenge.js";
import type { LoginProof } from "../loginChallenge.js";
import { createSsoTicket } from "../sso.js";
import type { SsoTicket } from "../sso.js";
import { verifyTotp } from "../totp.js";
import { completeLogin } from "./completeLogin.js";

/**
 * ### Prelogin
 *
 * What a client needs to stretch the password and sign a login: the account's KDF inputs and
 * a fresh challenge.
 */
export interface Prelogin {
  readonly salt: Uint8Array;
  readonly kdf: KdfParams;
  readonly challengeId: string;
  readonly challenge: Uint8Array;
  /** `legacy` for accounts that still log in with the old secret */
  readonly method: "legacy" | "signature";
}

/**
 * ### LoginAttempt
 *
 * A login as the client sent it.
 */
export interface LoginAttempt {
  readonly email: string;
  /** Signed challenge, or the legacy secret; absent proves nothing */
  readonly proof: LoginProof | undefined;
  /** Login key a legacy account switches to */
  readonly loginPublicKey: Uint8Array | undefined;
  readonly deviceId: string;
  readonly deviceName: string;
  readonly totp: string | undefined;
  /** Whether the user asked to confirm with the identity provider */
  readonly sso: boolean;
}

/**
 * ### UNKNOWN_ACCOUNT
 *
 * Credential checked for emails without an account: a login key nobody holds.
 */
const UNKNOWN_ACCOUNT = {
  authPublicKey: new Uint8Array(32).fill(1),
  authVerifier: undefined,
};

/**
 * ### PasswordLogin
 *
 * Signing in with password and Secret Key: prelogin, then the login itself, rate limited and
 * looking the same for unknown emails as for wrong passwords.
 */
export class PasswordLogin {
  readonly #context: Pick<
    AppContext,
    "store" | "now" | "serverSecret" | "sso" | "limits"
  >;
  readonly #report: (error: unknown) => void;

  /**
   * ### constructor
   *
   * @param context Storage, clock, server secret, identity provider and rate limits
   * @param report Where failures of background work (failed-login audit records) go
   */
  constructor(
    context: Pick<
      AppContext,
      "store" | "now" | "serverSecret" | "sso" | "limits"
    >,
    report: (error: unknown) => void,
  ) {
    this.#context = context;
    this.#report = report;
  }

  /**
   * ### prelogin
   *
   * The KDF inputs for an email and a challenge to sign. Unknown emails get stable made-up
   * values, so prelogin does not reveal which emails are registered (the enumeration weakness
   * 1Password lists as A.11).
   *
   * @param email Normalised email
   * @param ip Where the request came from
   * @returns The prelogin values
   */
  async prelogin(email: string, ip: string): Promise<Prelogin> {
    const now = this.#context.now();
    const limiter = this.#context.limits.prelogin;

    if (limiter.isBlocked(ip, now.getTime())) {
      throw tooManyAttempts();
    }

    limiter.recordFailure(ip, now.getTime());

    const repositories = this.#context.store.repositories();
    const user = await repositories.users.prelogin(email);
    const result = user ?? {
      ...this.#fakePrelogin(email),
      legacy: false,
    };
    const { challengeId, challenge } = await issueLoginChallenge(
      repositories.loginChallenges,
      email,
      now,
    );

    return {
      salt: result.salt,
      kdf: result.kdf,
      challengeId,
      challenge,
      // Unknown emails look like switched-over accounts; only not-yet-switched accounts say "legacy"
      method: result.legacy ? "legacy" : "signature",
    };
  }

  /**
   * ### login
   *
   * Checks the proof and the second factor, then starts a session, or hands over to the
   * identity provider when the account or the user asks for it.
   *
   * @param attempt The login
   * @param ip Where the request came from
   * @returns The login response, or an SSO ticket
   */
  async login(
    attempt: LoginAttempt,
    ip: string,
  ): Promise<Record<string, unknown> | SsoTicket> {
    const { limits, store } = this.#context;
    const now = this.#context.now();
    const at = now.getTime();
    // Per email and client, so a stranger cannot lock a user out; plus a looser cap per email
    const clientKey = `${attempt.email}:${ip}`;

    if (limits.login.isBlocked(clientKey, at)) {
      throw tooManyAttempts();
    }

    const repositories = store.repositories();
    const user = await repositories.users.loginAccount({
      email: attempt.email,
    });

    // Devices the account already used get past the per-email cap; unknown emails are looked
    // up the same way, so the answer takes as long either way
    if (
      limits.loginEmail.isBlocked(attempt.email, at) &&
      !(await repositories.sessions.knownDevice(
        user?.id ?? "",
        attempt.deviceId,
      ))
    ) {
      throw tooManyAttempts();
    }

    const recordFailure = (reason: string): void => {
      limits.login.recordFailure(clientKey, at);
      limits.loginEmail.recordFailure(attempt.email, at);

      if (user !== undefined) {
        this.#audit({
          orgId: user.orgId,
          actorId: user.id,
          action: "auth.login_failed",
          detail: { reason },
          ip,
        });
      }
    };

    // Unknown emails go through the same check against a key nobody holds, to keep timing alike
    const valid =
      attempt.proof !== undefined &&
      (await checkLoginProof(
        repositories.loginChallenges,
        user ?? UNKNOWN_ACCOUNT,
        attempt.proof,
        { email: attempt.email, deviceId: attempt.deviceId, purpose: "login" },
        now,
      ));

    if (user === undefined || attempt.proof === undefined || !valid) {
      recordFailure("credentials");

      throw new DomainError(
        "unauthenticated",
        "invalid_credentials",
        "Email, password or Secret Key is incorrect",
      );
    }

    await this.#checkSecondFactor(user, attempt.totp, now, () => {
      recordFailure("totp");
    });

    if (user.status === "suspended") {
      throw new DomainError(
        "forbidden",
        "membership_ended",
        "Membership is suspended",
      );
    }

    limits.login.reset(clientKey);

    // A legacy login proved the old secret; from now on this account logs in by signature only
    if ("authKey" in attempt.proof && attempt.loginPublicKey !== undefined) {
      await repositories.users.adoptLoginKey(user.id, attempt.loginPublicKey);
    }

    const device = {
      deviceId: attempt.deviceId,
      deviceName: attempt.deviceName,
    };

    // The identity provider must vouch for the person too; tokens come from /api/auth/sso/finish,
    // which is also where an open recovery gets cancelled for such logins
    if (user.requireSso || (attempt.sso && this.#context.sso !== undefined)) {
      return createSsoTicket(repositories.sso, this.#context, {
        kind: "login",
        userId: user.id,
        ...device,
      });
    }

    return store.transaction((repos) =>
      completeLogin(repos, this.#context, ip, user, device),
    );
  }

  /**
   * ### #checkSecondFactor
   *
   * Checks and uses up the TOTP code of an account that has one.
   *
   * @param user The account
   * @param totp Code sent, if any
   * @param now Current time
   * @param onWrongCode Counts a wrong code
   */
  async #checkSecondFactor(
    user: LoginAccount,
    totp: string | undefined,
    now: Date,
    onWrongCode: () => void,
  ): Promise<void> {
    if (user.totpSecret === undefined) {
      return;
    }

    if (totp === undefined) {
      throw new DomainError(
        "unauthenticated",
        "totp_required",
        "Two-factor code required",
      );
    }

    const step = verifyTotp(user.totpSecret, totp, now, user.totpLastStep);

    // Claims the step atomically, so two logins racing with the same code cannot both pass
    if (
      step === undefined ||
      !(await this.#context.store
        .repositories()
        .users.claimTotpStep(user.id, step))
    ) {
      onWrongCode();

      throw new DomainError(
        "unauthenticated",
        "invalid_totp",
        "Two-factor code is incorrect or already used",
      );
    }
  }

  /**
   * ### #audit
   *
   * Records a failed login without waiting for it, so a wrong password for a real account
   * answers as fast as one for an unknown email.
   *
   * @param entry What to record
   */
  #audit(entry: AuditEntry): void {
    this.#context.store.repositories().audit.record(entry).catch(this.#report);
  }

  /**
   * ### #fakePrelogin
   *
   * Stable, plausible prelogin values for an email with no account.
   *
   * @param email Requested email
   * @returns A salt that is stable for the email, and the default KDF parameters
   */
  #fakePrelogin(email: string): { salt: Uint8Array; kdf: KdfParams } {
    return {
      salt: hmac(
        sha256,
        this.#context.serverSecret,
        utf8Encode(`prelogin-salt|${email}`),
      ).slice(0, SALT_LENGTH),
      kdf: DEFAULT_KDF_PARAMS,
    };
  }
}

/**
 * ### tooManyAttempts
 *
 * The failure for a rate-limited attempt.
 *
 * @returns The error to throw
 */
function tooManyAttempts(): DomainError {
  return new DomainError(
    "rate_limited",
    "rate_limited",
    "Too many failed attempts; try again later",
  );
}
