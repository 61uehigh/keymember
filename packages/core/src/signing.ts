import { ed25519 } from "@noble/curves/ed25519.js";

import { encodeCbor } from "./cbor.js";
import type { CborValue } from "./cbor.js";

/**
 * ### SigningKeyPair
 *
 * An Ed25519 key pair used to sign public-key bundles, member certificates and security state.
 */
export interface SigningKeyPair {
  /**
   * ### publicKey
   *
   * 32-byte Ed25519 public key.
   */
  readonly publicKey: Uint8Array;

  /**
   * ### privateKey
   *
   * 32-byte Ed25519 seed. Stored only inside the encrypted account keyset.
   */
  readonly privateKey: Uint8Array;
}

/**
 * ### SignatureDomain
 *
 * Every statement type the core signs. The domain is part of the signed bytes,
 * so a signature over one kind of statement can never be replayed as another.
 */
export type SignatureDomain =
  | "keymember/public-bundle/v1"
  | "keymember/member-certificate/v1"
  | "keymember/security-state/v1"
  | "keymember/recovery-key/v1"
  | "keymember/group-certificate/v1"
  | "keymember/login/v1"
  | "keymember/key-grant/v1"
  | "keymember/member-invite/v1"
  | "keymember/recovery-request/v1"
  | "keymember/trusted-roots/v1"
  | "keymember/group-membership/v1";

/**
 * ### generateSigningKeyPair
 *
 * Generates a new Ed25519 key pair from the platform CSPRNG.
 *
 * @returns A fresh signing key pair
 */
export function generateSigningKeyPair(): SigningKeyPair {
  const privateKey = ed25519.utils.randomSecretKey();

  return { privateKey, publicKey: ed25519.getPublicKey(privateKey) };
}

/**
 * ### signStatement
 *
 * Signs a statement under a domain. The signed bytes are the deterministic CBOR of
 * `[domain, statement]`, so verification must be given the identical statement.
 *
 * @param privateKey Ed25519 seed of the signer
 * @param domain Statement type being signed
 * @param statement Statement content
 * @returns The 64-byte signature
 */
export function signStatement(
  privateKey: Uint8Array,
  domain: SignatureDomain,
  statement: CborValue,
): Uint8Array {
  return ed25519.sign(encodeCbor([domain, statement]), privateKey);
}

/**
 * ### verifyStatement
 *
 * Verifies a signature produced by {@link signStatement}.
 * Returns `false` for any invalid signature or key rather than throwing, since an
 * invalid signature is an expected outcome when the server is untrusted.
 *
 * @param publicKey Ed25519 public key of the claimed signer
 * @param domain Statement type that was signed
 * @param statement Statement content to check
 * @param signature Signature to verify
 * @returns Whether the signature is valid for the statement and key
 */
export function verifyStatement(
  publicKey: Uint8Array,
  domain: SignatureDomain,
  statement: CborValue,
  signature: Uint8Array,
): boolean {
  try {
    return ed25519.verify(
      signature,
      encodeCbor([domain, statement]),
      publicKey,
    );
  } catch {
    // noble throws on malformed points or lengths; for the caller that is just an invalid signature
    return false;
  }
}
