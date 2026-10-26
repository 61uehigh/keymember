import { ed25519 } from "@noble/curves/ed25519.js";

import { signStatement, verifyStatement } from "./signing.js";

/**
 * ### LoginPurpose
 *
 * What a signed challenge authorises: signing in, or proving the current credentials before
 * replacing them.
 */
export type LoginPurpose = "login" | "change-password";

/**
 * ### LoginChallengeStatement
 *
 * Everything a login signature covers. Binding the email, purpose and device stops a signature
 * from being reused for another account, action or device; the challenge is single-use.
 */
export interface LoginChallengeStatement {
  /**
   * ### purpose
   *
   * What the signature authorises.
   */
  readonly purpose: LoginPurpose;

  /**
   * ### email
   *
   * Account email, lower-cased.
   */
  readonly email: string;

  /**
   * ### challengeId
   *
   * Server-issued challenge id.
   */
  readonly challengeId: string;

  /**
   * ### challenge
   *
   * Server-issued random challenge bytes.
   */
  readonly challenge: Uint8Array;

  /**
   * ### deviceId
   *
   * Device signing in; empty for password changes.
   */
  readonly deviceId: string;
}

/**
 * ### loginPublicKey
 *
 * Public half of the login key, which the server stores in place of a password verifier.
 *
 * @param loginSigningSeed Seed from `deriveAccountSecrets`
 * @returns The Ed25519 public key
 */
export function loginPublicKey(loginSigningSeed: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(loginSigningSeed);
}

/**
 * ### toStatement
 *
 * The signed form of a challenge statement.
 *
 * @param statement Statement
 * @returns CBOR-ready map
 */
function toStatement(statement: LoginChallengeStatement) {
  return {
    purpose: statement.purpose,
    email: statement.email,
    challengeId: statement.challengeId,
    challenge: statement.challenge,
    deviceId: statement.deviceId,
  };
}

/**
 * ### signLoginChallenge
 *
 * Signs a login challenge with the login key.
 *
 * @param loginSigningSeed Seed from `deriveAccountSecrets`
 * @param statement What is being authorised
 * @returns The 64-byte signature
 */
export function signLoginChallenge(
  loginSigningSeed: Uint8Array,
  statement: LoginChallengeStatement,
): Uint8Array {
  return signStatement(
    loginSigningSeed,
    "keymember/login/v1",
    toStatement(statement),
  );
}

/**
 * ### verifyLoginChallenge
 *
 * Checks a login signature against the stored login public key.
 *
 * @param publicKey Stored login public key
 * @param statement The statement the server expects
 * @param signature Signature from the client
 * @returns Whether it is valid
 */
export function verifyLoginChallenge(
  publicKey: Uint8Array,
  statement: LoginChallengeStatement,
  signature: Uint8Array,
): boolean {
  return verifyStatement(
    publicKey,
    "keymember/login/v1",
    toStatement(statement),
    signature,
  );
}
