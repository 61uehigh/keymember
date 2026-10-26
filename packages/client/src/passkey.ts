import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  concatBytes,
  fromBase64Url,
  randomBytes,
  toBase64Url,
  utf8Encode,
} from "@keymember/core";
import type { StoredPasskey } from "@keymember/core";
import { encode, rfc8949EncodeOptions } from "cborg";
import { parse } from "tldts";

/**
 * ### KEYMEMBER_AAGUID
 *
 * Authenticator model identifier reported at registration. Fixed for every keymember
 * passkey, so relying parties can recognise (but not track) the provider.
 */
export const KEYMEMBER_AAGUID = Uint8Array.from([
  0x6b, 0x65, 0x79, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x2d, 0x70, 0x61, 0x73,
  0x73, 0x6b, 0x31,
]);

const ES256 = -7;

// Authenticator data flags (WebAuthn §6.1)
const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const FLAG_BACKUP_ELIGIBLE = 0x08;
const FLAG_BACKED_UP = 0x10;
const FLAG_ATTESTED_DATA = 0x40;

// DER prefix of a SubjectPublicKeyInfo for an uncompressed P-256 point
const P256_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
]);

/**
 * ### WebAuthnContext
 *
 * Where a ceremony happens. `origin` must come from the browser (the requesting frame),
 * never from the page; `rpId` is what the page asked for, already checked with {@link rpIdAllowed}.
 */
export interface WebAuthnContext {
  /**
   * ### origin
   *
   * Origin of the requesting top-level frame.
   */
  readonly origin: string;

  /**
   * ### rpId
   *
   * Relying party id.
   */
  readonly rpId: string;

  /**
   * ### challenge
   *
   * Relying party challenge bytes.
   */
  readonly challenge: Uint8Array;

  /**
   * ### userVerified
   *
   * Whether the user proved who they are (unlocked the vault) for this ceremony.
   */
  readonly userVerified: boolean;
}

/**
 * ### rpIdAllowed
 *
 * Applies the WebAuthn relying-party-id rules: the origin must be https (or http on
 * localhost), and the rp id must equal the origin's host or be a registrable-domain suffix
 * of it. Public suffixes (`co.kr`, `github.io`) and IP addresses are refused, so one site can
 * never claim credentials scoped to another.
 *
 * @param rpId Relying party id the page requested
 * @param origin Origin of the requesting frame, from the browser
 * @returns Whether the page may use that rp id
 */
export function rpIdAllowed(rpId: string, origin: string): boolean {
  let url: URL;

  try {
    url = new URL(origin);
  } catch {
    // An unparsable origin cannot be a secure context
    return false;
  }

  const host = url.hostname.toLowerCase();
  const id = rpId.toLowerCase();
  const isLocalhost = host === "localhost" || host.endsWith(".localhost");

  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocalhost)) {
    return false;
  }

  if (host !== id && !host.endsWith(`.${id}`)) {
    return false;
  }

  if (id === "localhost") {
    return isLocalhost;
  }

  const info = parse(id, { allowPrivateDomains: true });

  return (
    info.isIp !== true &&
    info.domain !== null &&
    (id === info.domain || id.endsWith(`.${info.domain}`))
  );
}

/**
 * ### clientDataJson
 *
 * Builds `clientDataJSON` exactly as browsers serialise it, with the browser-supplied origin.
 *
 * @param type Ceremony type
 * @param context Ceremony context
 * @returns The UTF-8 JSON bytes
 */
function clientDataJson(
  type: "webauthn.create" | "webauthn.get",
  context: WebAuthnContext,
): Uint8Array {
  return utf8Encode(
    JSON.stringify({
      type,
      challenge: toBase64Url(context.challenge),
      origin: context.origin,
      crossOrigin: false,
    }),
  );
}

/**
 * ### authenticatorData
 *
 * Builds authenticator data. The signature counter stays 0, as for every synced passkey,
 * and the backup flags say the credential is synced.
 *
 * @param rpId Relying party id
 * @param userVerified Whether to set the UV flag
 * @param attested Attested credential data to append at registration
 * @returns The authenticator data bytes
 */
function authenticatorData(
  rpId: string,
  userVerified: boolean,
  attested?: Uint8Array,
): Uint8Array {
  const flags =
    FLAG_USER_PRESENT |
    (userVerified ? FLAG_USER_VERIFIED : 0) |
    FLAG_BACKUP_ELIGIBLE |
    FLAG_BACKED_UP |
    (attested === undefined ? 0 : FLAG_ATTESTED_DATA);

  return concatBytes(
    sha256(utf8Encode(rpId)),
    Uint8Array.of(flags),
    new Uint8Array(4),
    attested ?? new Uint8Array(),
  );
}

/**
 * ### RegistrationResult
 *
 * A new passkey to store, and the credential to hand back to the relying party.
 */
export interface RegistrationResult {
  /**
   * ### passkey
   *
   * The passkey to store in an item, private key included.
   */
  readonly passkey: StoredPasskey;

  /**
   * ### credential
   *
   * Values for the `PublicKeyCredential` returned to the page.
   */
  readonly credential: {
    readonly rawId: Uint8Array;
    readonly clientDataJSON: Uint8Array;
    readonly attestationObject: Uint8Array;
    readonly authenticatorData: Uint8Array;
    readonly publicKey: Uint8Array;
    readonly publicKeyAlgorithm: number;
  };
}

/**
 * ### createPasskey
 *
 * Creates an ES256 passkey with `none` attestation.
 *
 * @param context Ceremony context
 * @param user Relying party's user id and names
 * @returns The passkey and the credential for the page
 */
export function createPasskey(
  context: WebAuthnContext,
  user: { id: Uint8Array; name: string; displayName: string },
): RegistrationResult {
  const privateKey = p256.utils.randomSecretKey();
  const publicPoint = p256.getPublicKey(privateKey, false);
  const credentialId = randomBytes(16);
  const coseKey = encode(
    new Map<number, number | Uint8Array>([
      [1, 2],
      [3, ES256],
      [-1, 1],
      [-2, publicPoint.slice(1, 33)],
      [-3, publicPoint.slice(33, 65)],
    ]),
    rfc8949EncodeOptions,
  );
  const credentialIdLength = new Uint8Array(2);

  new DataView(credentialIdLength.buffer).setUint16(0, credentialId.length);

  const authData = authenticatorData(
    context.rpId,
    context.userVerified,
    concatBytes(KEYMEMBER_AAGUID, credentialIdLength, credentialId, coseKey),
  );

  return {
    passkey: {
      credentialId: toBase64Url(credentialId),
      rpId: context.rpId,
      userHandle: toBase64Url(user.id),
      userName: user.name,
      userDisplayName: user.displayName,
      privateKey: toBase64Url(privateKey),
      createdAt: new Date().toISOString(),
    },
    credential: {
      rawId: credentialId,
      clientDataJSON: clientDataJson("webauthn.create", context),
      attestationObject: encode(
        new Map<string, unknown>([
          ["fmt", "none"],
          ["attStmt", new Map()],
          ["authData", authData],
        ]),
        rfc8949EncodeOptions,
      ),
      authenticatorData: authData,
      publicKey: concatBytes(P256_SPKI_PREFIX, publicPoint),
      publicKeyAlgorithm: ES256,
    },
  };
}

/**
 * ### AssertionResult
 *
 * Values for the `PublicKeyCredential` returned to a sign-in request.
 */
export interface AssertionResult {
  readonly rawId: Uint8Array;
  readonly clientDataJSON: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly signature: Uint8Array;
  readonly userHandle: Uint8Array;
}

/**
 * ### assertPasskey
 *
 * Signs a sign-in challenge with a stored passkey. Throws when the passkey's rp id differs from
 * the context's, so a stored credential can never answer for another site.
 *
 * @param passkey Stored passkey
 * @param context Ceremony context
 * @returns The assertion for the page
 */
export function assertPasskey(
  passkey: StoredPasskey,
  context: WebAuthnContext,
): AssertionResult {
  if (passkey.rpId !== context.rpId) {
    throw new Error("Passkey belongs to another relying party");
  }

  const privateKey = fromBase64Url(passkey.privateKey);
  const rawId = fromBase64Url(passkey.credentialId);
  const userHandle = fromBase64Url(passkey.userHandle);

  if (
    privateKey === undefined ||
    rawId === undefined ||
    userHandle === undefined
  ) {
    throw new Error("Stored passkey is corrupted");
  }

  const authData = authenticatorData(context.rpId, context.userVerified);
  const clientData = clientDataJson("webauthn.get", context);

  return {
    rawId,
    clientDataJSON: clientData,
    authenticatorData: authData,
    // ECDSA over authenticatorData ‖ SHA-256(clientDataJSON); noble hashes the message with SHA-256 itself
    signature: p256.sign(
      concatBytes(authData, sha256(clientData)),
      privateKey,
      { format: "der" },
    ),
    userHandle,
  };
}
