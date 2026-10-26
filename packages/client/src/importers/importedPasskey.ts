import { p256 } from "@noble/curves/nist.js";
import { fromBase64Url, toBase64Url } from "@keymember/core";
import type { StoredPasskey } from "@keymember/core";

// DER object identifiers of id-ecPublicKey (1.2.840.10045.2.1) and prime256v1 (1.2.840.10045.3.1.7)
const EC_PUBLIC_KEY = Uint8Array.from([
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
]);
const PRIME256V1 = Uint8Array.from([
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
]);

interface Tlv {
  readonly tag: number;
  readonly value: Uint8Array;
}

/**
 * ### readChildren
 *
 * Splits DER-encoded bytes into their top-level TLVs. Returns `undefined` on any malformed
 * length rather than throwing, since the input comes from an export file.
 *
 * @param bytes DER bytes
 * @returns The TLVs, or `undefined`
 */
function readChildren(bytes: Uint8Array): Array<Tlv> | undefined {
  const children: Array<Tlv> = [];
  let offset = 0;

  while (offset < bytes.length) {
    const tag = bytes[offset];
    let length = bytes[offset + 1];

    if (tag === undefined || length === undefined) {
      return undefined;
    }

    offset += 2;

    if (length & 0x80) {
      const count = length & 0x7f;

      if (count === 0 || count > 2 || offset + count > bytes.length) {
        return undefined;
      }

      length = 0;

      for (const byte of bytes.subarray(offset, offset + count)) {
        length = (length << 8) | byte;
      }

      offset += count;
    }

    if (offset + length > bytes.length) {
      return undefined;
    }

    children.push({ tag, value: bytes.subarray(offset, offset + length) });
    offset += length;
  }

  return children;
}

/**
 * ### equalBytes
 *
 * Compares two short public byte strings.
 *
 * @param a First
 * @param b Second
 * @returns Whether they are equal
 */
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

/**
 * ### p256PrivateKeyFromPkcs8
 *
 * Extracts the 32-byte private scalar from a PKCS#8 `PrivateKeyInfo` holding a P-256 key, the
 * form passkey exports use. Other curves and algorithms give `undefined`.
 *
 * @param der PKCS#8 DER bytes
 * @returns The private scalar, or `undefined`
 */
export function p256PrivateKeyFromPkcs8(
  der: Uint8Array,
): Uint8Array | undefined {
  const [outer] = readChildren(der) ?? [];
  const [version, algorithm, privateKey] =
    outer?.tag === 0x30 ? (readChildren(outer.value) ?? []) : [];
  const [algorithmOid, curveOid] =
    algorithm?.tag === 0x30 ? (readChildren(algorithm.value) ?? []) : [];

  if (
    version?.tag !== 0x02 ||
    privateKey?.tag !== 0x04 ||
    algorithmOid === undefined ||
    curveOid === undefined ||
    !equalBytes(algorithmOid.value, EC_PUBLIC_KEY) ||
    !equalBytes(curveOid.value, PRIME256V1)
  ) {
    return undefined;
  }

  // ECPrivateKey ::= SEQUENCE { version 1, privateKey OCTET STRING, ... }
  const [ecPrivateKey] = readChildren(privateKey.value) ?? [];
  const [, scalar] =
    ecPrivateKey?.tag === 0x30 ? (readChildren(ecPrivateKey.value) ?? []) : [];

  if (scalar?.tag !== 0x04 || scalar.value.length > 32) {
    return undefined;
  }

  const padded = new Uint8Array(32);

  padded.set(scalar.value, 32 - scalar.value.length);

  return p256.utils.isValidSecretKey(padded) ? padded : undefined;
}

/**
 * ### normalizeBase64Url
 *
 * Accepts base64 or base64url (padded or not) and returns unpadded base64url.
 *
 * @param text Encoded bytes
 * @returns base64url, or `undefined` when it does not decode
 */
export function normalizeBase64Url(text: string): string | undefined {
  const bytes = fromBase64Url(
    text.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
  );

  return bytes === undefined ? undefined : toBase64Url(bytes);
}

/**
 * ### importedPasskey
 *
 * Builds a stored passkey from exported parts, or explains why it cannot be imported.
 *
 * @param parts Exported credential
 * @returns The passkey, or the reason it was skipped
 */
export function importedPasskey(parts: {
  credentialId: string;
  rpId: string;
  userHandle: string;
  userName: string;
  userDisplayName: string;
  pkcs8: string;
  createdAt: string;
}): StoredPasskey | string {
  const credentialId = normalizeBase64Url(parts.credentialId);
  const userHandle = normalizeBase64Url(parts.userHandle);
  const pkcs8 = normalizeBase64Url(parts.pkcs8);
  const der = pkcs8 === undefined ? undefined : fromBase64Url(pkcs8);
  const privateKey =
    der === undefined ? undefined : p256PrivateKeyFromPkcs8(der);

  if (credentialId === undefined || userHandle === undefined) {
    return `passkey for ${parts.rpId}: malformed credential id or user handle`;
  }

  if (privateKey === undefined) {
    return `passkey for ${parts.rpId}: only P-256 (ES256) keys are supported`;
  }

  return {
    credentialId,
    rpId: parts.rpId,
    userHandle,
    userName: parts.userName,
    userDisplayName: parts.userDisplayName,
    privateKey: toBase64Url(privateKey),
    createdAt: parts.createdAt,
  };
}
