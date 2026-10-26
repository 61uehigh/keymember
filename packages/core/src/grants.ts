import { sha256 } from "@noble/hashes/sha2.js";

import { signStatement, verifyStatement } from "./signing.js";

/**
 * ### KeyGrant
 *
 * A vault key handed to a member or group, as its granter signs it. Wrapping alone does not
 * authenticate the sender (anyone can wrap a key to a public key), so recipients accept a
 * wrapped vault key only with a grant signed by themselves or a certified member; otherwise a
 * server could slip in a vault key it knows and read whatever is written under it.
 */
export interface KeyGrant {
  /**
   * ### vaultId
   *
   * Vault the key belongs to.
   */
  readonly vaultId: string;

  /**
   * ### keyGeneration
   *
   * Vault key generation.
   */
  readonly keyGeneration: number;

  /**
   * ### principalType
   *
   * Whether the key is wrapped to a member or a group.
   */
  readonly principalType: "user" | "group";

  /**
   * ### principalId
   *
   * Member or group the key is wrapped to.
   */
  readonly principalId: string;

  /**
   * ### wrappedKey
   *
   * The wrapped key bytes; the signature covers their hash.
   */
  readonly wrappedKey: Uint8Array;
}

/**
 * ### grantStatement
 *
 * The signed form of a grant.
 *
 * @param grant Grant
 * @returns CBOR-ready map
 */
function grantStatement(grant: KeyGrant) {
  return {
    vaultId: grant.vaultId,
    keyGeneration: grant.keyGeneration,
    principalType: grant.principalType,
    principalId: grant.principalId,
    wrappedKeyHash: sha256(grant.wrappedKey),
  };
}

/**
 * ### signKeyGrant
 *
 * Signs a grant with the granter's signing key.
 *
 * @param signingPrivateKey Granter's Ed25519 seed
 * @param grant What is granted
 * @returns The signature
 */
export function signKeyGrant(
  signingPrivateKey: Uint8Array,
  grant: KeyGrant,
): Uint8Array {
  return signStatement(
    signingPrivateKey,
    "keymember/key-grant/v1",
    grantStatement(grant),
  );
}

/**
 * ### verifyKeyGrant
 *
 * Checks a grant signature.
 *
 * @param signingPublicKey Granter's verified signing key
 * @param grant The grant as served
 * @param signature Signature as served
 * @returns Whether the granter signed exactly this grant
 */
export function verifyKeyGrant(
  signingPublicKey: Uint8Array,
  grant: KeyGrant,
  signature: Uint8Array,
): boolean {
  return verifyStatement(
    signingPublicKey,
    "keymember/key-grant/v1",
    grantStatement(grant),
    signature,
  );
}

/**
 * ### MemberInvite
 *
 * An admin's signed statement of who was invited and with which role. Certification takes the
 * role and email from here rather than from the server, so a server cannot turn a member into
 * an admin (and a recovery-key holder) behind the certifying admin's back.
 */
export interface MemberInvite {
  /**
   * ### orgId
   *
   * Organisation.
   */
  readonly orgId: string;

  /**
   * ### email
   *
   * Invited email, lower-cased.
   */
  readonly email: string;

  /**
   * ### role
   *
   * Role the invitee gets.
   */
  readonly role: "admin" | "member";

  /**
   * ### issuerId
   *
   * Inviting admin.
   */
  readonly issuerId: string;

  /**
   * ### issuedAt
   *
   * Unix seconds.
   */
  readonly issuedAt: number;

  /**
   * ### nonce
   *
   * Random base64url value that makes every invite's link secret different
   * ({@link inviteLinkSecret}). Invites made before links had none and need manual verification.
   */
  readonly nonce?: string;
}

/**
 * ### signMemberInvite
 *
 * Signs an invite with the inviting admin's signing key.
 *
 * @param signingPrivateKey Admin's Ed25519 seed
 * @param invite Invite
 * @returns The signature
 */
export function signMemberInvite(
  signingPrivateKey: Uint8Array,
  invite: MemberInvite,
): Uint8Array {
  return signStatement(signingPrivateKey, "keymember/member-invite/v1", {
    ...invite,
  });
}

/**
 * ### verifyMemberInvite
 *
 * Verifies an invite against trusted admin signing keys.
 *
 * @param invite Invite as served
 * @param signature Signature as served
 * @param trustedIssuers Trusted issuer keys by user id
 * @returns Whether a trusted admin signed exactly this invite
 */
export function verifyMemberInvite(
  invite: MemberInvite,
  signature: Uint8Array,
  trustedIssuers: ReadonlyMap<string, Uint8Array>,
): boolean {
  const issuerKey = trustedIssuers.get(invite.issuerId);

  return (
    issuerKey !== undefined &&
    verifyStatement(
      issuerKey,
      "keymember/member-invite/v1",
      { ...invite },
      signature,
    )
  );
}

/**
 * ### RecoveryRequest
 *
 * The requesting admin's signed statement of whose account a recovery is for. The admin who
 * completes the recovery re-wraps keys only to the user named here, so a server cannot point a
 * recovery at someone else.
 */
export interface RecoveryRequest {
  /**
   * ### orgId
   *
   * Organisation.
   */
  readonly orgId: string;

  /**
   * ### recoveryId
   *
   * Recovery id.
   */
  readonly recoveryId: string;

  /**
   * ### userId
   *
   * Member being recovered.
   */
  readonly userId: string;

  /**
   * ### requestedBy
   *
   * Requesting admin.
   */
  readonly requestedBy: string;

  /**
   * ### keysetVersion
   *
   * Version of the member's keys when the recovery was requested. Re-enrolling makes the next
   * version, so the completing admin checks this signature against the certificate's version
   * minus one: a server that serves the old, possibly stolen keys cannot make it verify.
   */
  readonly keysetVersion: number;
}

/**
 * ### signRecoveryRequest
 *
 * Signs a recovery request with the requesting admin's signing key.
 *
 * @param signingPrivateKey Admin's Ed25519 seed
 * @param request Request
 * @returns The signature
 */
export function signRecoveryRequest(
  signingPrivateKey: Uint8Array,
  request: RecoveryRequest,
): Uint8Array {
  return signStatement(signingPrivateKey, "keymember/recovery-request/v1", {
    ...request,
  });
}

/**
 * ### verifyRecoveryRequest
 *
 * Verifies a recovery request against trusted admin signing keys.
 *
 * @param request Request as served
 * @param signature Signature as served
 * @param trustedIssuers Trusted issuer keys by user id
 * @returns Whether a trusted admin signed exactly this request
 */
export function verifyRecoveryRequest(
  request: RecoveryRequest,
  signature: Uint8Array,
  trustedIssuers: ReadonlyMap<string, Uint8Array>,
): boolean {
  const issuerKey = trustedIssuers.get(request.requestedBy);

  return (
    issuerKey !== undefined &&
    verifyStatement(
      issuerKey,
      "keymember/recovery-request/v1",
      { ...request },
      signature,
    )
  );
}
