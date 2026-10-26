import { signStatement, verifyStatement } from "./signing.js";

/**
 * ### TrustedRoots
 *
 * The organisation keys a user trusts, signed by the user's own signing key and stored on the
 * server. Each new device of the user unlocks the account key set first, so it can check this
 * signature and adopt the roots without asking the user to compare a fingerprint again; the
 * server cannot alter them without the user's key.
 */
export interface TrustedRoots {
  /**
   * ### userId
   *
   * User who trusts these roots and signed them.
   */
  readonly userId: string;

  /**
   * ### orgId
   *
   * Organisation the roots belong to.
   */
  readonly orgId: string;

  /**
   * ### roots
   *
   * Trusted signing keys by user id, usually just the owner's.
   */
  readonly roots: ReadonlyArray<{
    readonly userId: string;
    readonly signingPublicKey: Uint8Array;
  }>;

  /**
   * ### issuedAt
   *
   * Unix seconds.
   */
  readonly issuedAt: number;
}

/**
 * ### signTrustedRoots
 *
 * Signs a user's trusted roots with the user's own signing key.
 *
 * @param signingPrivateKey User's Ed25519 seed
 * @param trusted Roots to sign
 * @returns The signature
 */
export function signTrustedRoots(
  signingPrivateKey: Uint8Array,
  trusted: TrustedRoots,
): Uint8Array {
  return signStatement(
    signingPrivateKey,
    "keymember/trusted-roots/v1",
    statementOf(trusted),
  );
}

/**
 * ### verifyTrustedRoots
 *
 * Checks that the user themself signed these roots.
 *
 * @param signingPublicKey The user's own signing key, from their unlocked key set
 * @param trusted Roots as served
 * @param signature Signature as served
 * @returns Whether the user signed exactly these roots
 */
export function verifyTrustedRoots(
  signingPublicKey: Uint8Array,
  trusted: TrustedRoots,
  signature: Uint8Array,
): boolean {
  return verifyStatement(
    signingPublicKey,
    "keymember/trusted-roots/v1",
    statementOf(trusted),
    signature,
  );
}

/**
 * ### statementOf
 *
 * The signed form of a roots record, with roots in a fixed order.
 *
 * @param trusted Roots record
 * @returns The statement to sign or verify
 */
function statementOf(trusted: TrustedRoots) {
  return {
    userId: trusted.userId,
    orgId: trusted.orgId,
    issuedAt: trusted.issuedAt,
    roots: [...trusted.roots]
      .sort((left, right) =>
        left.userId < right.userId ? -1 : left.userId > right.userId ? 1 : 0,
      )
      .map((root) => ({
        userId: root.userId,
        signingPublicKey: root.signingPublicKey,
      })),
  };
}
