import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

import type { PublicKeyBundle } from "./AccountKeyset.js";
import { constantTimeEqual, utf8Encode } from "./bytes.js";
import { encodeCbor } from "./cbor.js";
import type { MemberInvite } from "./grants.js";

/**
 * ### inviteLinkSecret
 *
 * The secret an invite link carries in its URL fragment, which browsers never send to the
 * server. The invitee proves with it that the keys they published are theirs
 * ({@link inviteProof}), so the inviting admin can certify them without comparing fingerprints.
 *
 * It is derived from the admin's signing key and the invite rather than stored, so any device
 * of that admin can check the proof later; the server, which never sees the link, cannot.
 *
 * @param signingPrivateKey Inviting admin's Ed25519 seed
 * @param invite Signed invite; must have a nonce
 * @returns 32-byte secret
 */
export function inviteLinkSecret(
  signingPrivateKey: Uint8Array,
  invite: MemberInvite,
): Uint8Array {
  if (invite.nonce === undefined) {
    throw new Error("An invite without a nonce has no link secret");
  }

  const key = hkdf(
    sha256,
    signingPrivateKey,
    undefined,
    utf8Encode("keymember/invite-link-key/v1"),
    32,
  );

  return hmac(
    sha256,
    key,
    encodeCbor(["keymember/invite-link/v1", { ...invite }]),
  );
}

/**
 * ### inviteProof
 *
 * The invitee's proof that a public key bundle is theirs: a MAC over the bundle under the link
 * secret. A server that swaps the bundle cannot make a matching proof without the link.
 *
 * @param linkSecret Secret from the invite link
 * @param bundle Keys the invitee published at sign-up
 * @returns 32-byte proof
 */
export function inviteProof(
  linkSecret: Uint8Array,
  bundle: Pick<
    PublicKeyBundle,
    "userId" | "encryptionPublicKey" | "signingPublicKey"
  >,
): Uint8Array {
  return hmac(
    sha256,
    linkSecret,
    encodeCbor([
      "keymember/invite-proof/v1",
      bundle.userId,
      bundle.encryptionPublicKey,
      bundle.signingPublicKey,
    ]),
  );
}

/**
 * ### verifyInviteProof
 *
 * Checks an invitee's proof in constant time.
 *
 * @param linkSecret Secret of the invite, recomputed by the inviting admin
 * @param bundle Keys the server says the invitee published
 * @param proof Proof the invitee sent
 * @returns Whether the proof was made for exactly this bundle with this link
 */
export function verifyInviteProof(
  linkSecret: Uint8Array,
  bundle: Pick<
    PublicKeyBundle,
    "userId" | "encryptionPublicKey" | "signingPublicKey"
  >,
  proof: Uint8Array,
): boolean {
  return constantTimeEqual(inviteProof(linkSecret, bundle), proof);
}
