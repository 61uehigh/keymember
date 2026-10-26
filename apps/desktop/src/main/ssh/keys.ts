import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  sign,
} from "node:crypto";
import type { KeyObject, webcrypto } from "node:crypto";

type JsonWebKey = webcrypto.JsonWebKey;

import { SshReader, SshWireError, SshWriter } from "./wire.js";

/**
 * ### SshKeyError
 *
 * A private key could not be used: unsupported type, passphrase-protected, or malformed.
 */
export class SshKeyError extends Error {
  override readonly name = "SshKeyError";
}

/**
 * ### SshKey
 *
 * A private key ready for the agent.
 */
export interface SshKey {
  /**
   * ### keyType
   *
   * SSH key type name, e.g. `ssh-ed25519`.
   */
  readonly keyType: string;

  /**
   * ### publicBlob
   *
   * Public key in SSH wire form, as the agent lists it.
   */
  readonly publicBlob: Uint8Array;

  /**
   * ### comment
   *
   * Comment stored with the key, if any.
   */
  readonly comment: string;

  /**
   * ### sign
   *
   * Signs data for an SSH client.
   *
   * @param data Data to sign
   * @param flags Agent sign-request flags (RSA SHA-2 choice)
   * @returns SSH signature blob
   */
  sign(data: Uint8Array, flags: number): Uint8Array;
}

// Agent sign-request flags (draft-miller-ssh-agent §5.3)
const RSA_SHA2_256 = 2;
const RSA_SHA2_512 = 4;

const CURVES: Readonly<
  Record<string, { jwk: string; hash: string; size: number }>
> = {
  nistp256: { jwk: "P-256", hash: "sha256", size: 32 },
  nistp384: { jwk: "P-384", hash: "sha384", size: 48 },
  nistp521: { jwk: "P-521", hash: "sha512", size: 66 },
};

/**
 * ### b64url
 *
 * base64url without padding, for JWK fields.
 *
 * @param bytes Bytes
 * @returns Encoded text
 */
function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/**
 * ### fromB64url
 *
 * Decodes a JWK field.
 *
 * @param text base64url text
 * @returns Bytes
 */
function fromB64url(text: string | undefined): Uint8Array {
  return new Uint8Array(Buffer.from(text ?? "", "base64url"));
}

/**
 * ### leftPad
 *
 * Pads a big-endian integer to a fixed width.
 *
 * @param bytes Integer bytes
 * @param size Width
 * @returns Padded bytes
 */
function leftPad(bytes: Uint8Array, size: number): Uint8Array {
  if (bytes.length >= size) {
    return bytes.subarray(bytes.length - size);
  }

  const out = new Uint8Array(size);

  out.set(bytes, size - bytes.length);

  return out;
}

/**
 * ### toBigInt
 *
 * Reads a big-endian magnitude.
 *
 * @param bytes Magnitude
 * @returns The integer
 */
function toBigInt(bytes: Uint8Array): bigint {
  return bytes.length === 0
    ? 0n
    : BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
}

/**
 * ### fromBigInt
 *
 * Writes a big-endian magnitude.
 *
 * @param value Integer
 * @returns Bytes
 */
function fromBigInt(value: bigint): Uint8Array {
  const hex = value.toString(16);

  return new Uint8Array(
    Buffer.from(hex.length % 2 === 0 ? hex : `0${hex}`, "hex"),
  );
}

/**
 * ### publicBlobOf
 *
 * Builds the SSH public key blob of a key.
 *
 * @param jwk Public (or private) JWK
 * @returns Key type and blob
 */
function publicBlobOf(jwk: JsonWebKey): { keyType: string; blob: Uint8Array } {
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
    return {
      keyType: "ssh-ed25519",
      blob: new SshWriter()
        .string("ssh-ed25519")
        .string(fromB64url(jwk.x))
        .bytes(),
    };
  }

  if (jwk.kty === "EC") {
    const entry = Object.entries(CURVES).find(
      ([, curve]) => curve.jwk === jwk.crv,
    );

    if (entry === undefined) {
      throw new SshKeyError(`Unsupported curve ${String(jwk.crv)}`);
    }

    const [name, curve] = entry;
    const keyType = `ecdsa-sha2-${name}`;
    const point = Uint8Array.from([
      4,
      ...leftPad(fromB64url(jwk.x), curve.size),
      ...leftPad(fromB64url(jwk.y), curve.size),
    ]);

    return {
      keyType,
      blob: new SshWriter().string(keyType).string(name).string(point).bytes(),
    };
  }

  if (jwk.kty === "RSA") {
    return {
      keyType: "ssh-rsa",
      blob: new SshWriter()
        .string("ssh-rsa")
        .mpint(fromB64url(jwk.e))
        .mpint(fromB64url(jwk.n))
        .bytes(),
    };
  }

  throw new SshKeyError("Only Ed25519, ECDSA and RSA keys are supported");
}

/**
 * ### signerFor
 *
 * Makes the signing function for a key.
 *
 * @param key Private key
 * @param keyType SSH key type
 * @returns The signing function
 */
function signerFor(
  key: KeyObject,
  keyType: string,
): (data: Uint8Array, flags: number) => Uint8Array {
  if (keyType === "ssh-ed25519") {
    return (data) =>
      new SshWriter()
        .string("ssh-ed25519")
        .string(new Uint8Array(sign(null, data, key)))
        .bytes();
  }

  if (keyType.startsWith("ecdsa-sha2-")) {
    const curve = CURVES[keyType.slice("ecdsa-sha2-".length)];

    if (curve === undefined) {
      throw new SshKeyError(`Unsupported key type ${keyType}`);
    }

    return (data) => {
      const raw = new Uint8Array(
        sign(curve.hash, data, { key, dsaEncoding: "ieee-p1363" }),
      );
      const half = raw.length / 2;

      return new SshWriter()
        .string(keyType)
        .string(
          new SshWriter()
            .mpint(raw.subarray(0, half))
            .mpint(raw.subarray(half))
            .bytes(),
        )
        .bytes();
    };
  }

  return (data, flags) => {
    // SHA-1 RSA signatures ("ssh-rsa") are refused; every current OpenSSH client asks for SHA-2
    const [algorithm, hash] =
      flags & RSA_SHA2_512
        ? ["rsa-sha2-512", "sha512"]
        : flags & RSA_SHA2_256
          ? ["rsa-sha2-256", "sha256"]
          : [undefined, undefined];

    if (algorithm === undefined) {
      throw new SshKeyError("SHA-1 RSA signatures are not supported");
    }

    return new SshWriter()
      .string(algorithm)
      .string(new Uint8Array(sign(hash, data, key)))
      .bytes();
  };
}

/**
 * ### parseOpenSsh
 *
 * Reads an unencrypted `openssh-key-v1` private key into a JWK.
 *
 * @param body Base64-decoded key body
 * @returns JWK and comment
 */
function parseOpenSsh(body: Uint8Array): { jwk: JsonWebKey; comment: string } {
  const magic = new TextEncoder().encode("openssh-key-v1\0");

  if (
    body.length < magic.length ||
    !magic.every((byte, index) => body[index] === byte)
  ) {
    throw new SshKeyError("Not an OpenSSH private key");
  }

  const reader = new SshReader(body.subarray(magic.length));
  const cipher = reader.text();

  reader.text();
  reader.string();

  if (cipher !== "none") {
    throw new SshKeyError(
      "Passphrase-protected key: remove the passphrase first (ssh-keygen -p); the vault encrypts it",
    );
  }

  if (reader.uint32() !== 1) {
    throw new SshKeyError("Files with several keys are not supported");
  }

  reader.string();

  const secret = new SshReader(reader.string());

  if (secret.uint32() !== secret.uint32()) {
    throw new SshKeyError("Corrupted private key");
  }

  const keyType = secret.text();

  if (keyType === "ssh-ed25519") {
    const publicKey = secret.string();
    const privateKey = secret.string();

    return {
      jwk: {
        kty: "OKP",
        crv: "Ed25519",
        x: b64url(publicKey),
        d: b64url(privateKey.subarray(0, 32)),
      },
      comment: secret.text(),
    };
  }

  if (keyType.startsWith("ecdsa-sha2-")) {
    const name = secret.text();
    const curve = CURVES[name];
    const point = secret.string();
    const d = secret.mpint();

    if (curve === undefined || point[0] !== 4) {
      throw new SshKeyError(`Unsupported key type ${keyType}`);
    }

    return {
      jwk: {
        kty: "EC",
        crv: curve.jwk,
        x: b64url(point.subarray(1, 1 + curve.size)),
        y: b64url(point.subarray(1 + curve.size)),
        d: b64url(leftPad(d, curve.size)),
      },
      comment: secret.text(),
    };
  }

  if (keyType === "ssh-rsa") {
    const n = secret.mpint();
    const e = secret.mpint();
    const d = secret.mpint();
    const iqmp = secret.mpint();
    const p = secret.mpint();
    const q = secret.mpint();
    const dBig = toBigInt(d);

    return {
      jwk: {
        kty: "RSA",
        n: b64url(n),
        e: b64url(e),
        d: b64url(d),
        p: b64url(p),
        q: b64url(q),
        dp: b64url(fromBigInt(dBig % (toBigInt(p) - 1n))),
        dq: b64url(fromBigInt(dBig % (toBigInt(q) - 1n))),
        qi: b64url(iqmp),
      },
      comment: secret.text(),
    };
  }

  throw new SshKeyError(`Unsupported key type ${keyType}`);
}

/**
 * ### loadSshKey
 *
 * Loads an unencrypted private key in OpenSSH or PEM (PKCS#8, PKCS#1, SEC1) form.
 *
 * @param text Private key text
 * @returns The key
 */
export function loadSshKey(text: string): SshKey {
  let jwk: JsonWebKey;
  let comment = "";

  try {
    const match =
      /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/.exec(
        text,
      );

    if (match !== null) {
      ({ jwk, comment } = parseOpenSsh(
        new Uint8Array(
          Buffer.from((match[1] ?? "").replace(/\s+/g, ""), "base64"),
        ),
      ));
    } else if (text.includes("ENCRYPTED")) {
      throw new SshKeyError(
        "Passphrase-protected key: remove the passphrase first; the vault encrypts it",
      );
    } else {
      jwk = createPrivateKey({ key: text, format: "pem" }).export({
        format: "jwk",
      });
    }
  } catch (error) {
    if (error instanceof SshKeyError) {
      throw error;
    }

    throw new SshKeyError(
      error instanceof SshWireError
        ? "Corrupted private key"
        : "Not a private key keymember can read",
      { cause: error },
    );
  }

  const { keyType, blob } = publicBlobOf(jwk);
  let key: KeyObject;

  try {
    key = createPrivateKey({ key: jwk, format: "jwk" });
  } catch (error) {
    throw new SshKeyError("Corrupted private key", { cause: error });
  }

  return {
    keyType,
    publicBlob: blob,
    comment,
    sign: signerFor(key, keyType),
  };
}

/**
 * ### fingerprintOf
 *
 * `SHA256:` fingerprint of a public key blob, as `ssh-keygen -l` prints it.
 *
 * @param blob Public key blob
 * @returns The fingerprint
 */
export function fingerprintOf(blob: Uint8Array): string {
  return `SHA256:${createHash("sha256").update(blob).digest("base64").replace(/=+$/, "")}`;
}

/**
 * ### publicKeyLine
 *
 * The `authorized_keys` line of a key.
 *
 * @param key Key
 * @param comment Comment to append
 * @returns The line
 */
export function publicKeyLine(key: SshKey, comment: string): string {
  return [key.keyType, Buffer.from(key.publicBlob).toString("base64"), comment]
    .filter((part) => part !== "")
    .join(" ");
}

/**
 * ### generateEd25519
 *
 * Generates an Ed25519 key in OpenSSH format.
 *
 * @param comment Comment, usually `user@host` or a purpose
 * @returns Private key text, public key line and fingerprint
 */
export function generateEd25519(comment: string): {
  privateKey: string;
  publicKey: string;
  fingerprint: string;
} {
  const { privateKey } = generateKeyPairSync("ed25519");
  const jwk = privateKey.export({ format: "jwk" });
  const seed = fromB64url(jwk.d);
  const publicKey = fromB64url(jwk.x);
  const publicBlob = new SshWriter()
    .string("ssh-ed25519")
    .string(publicKey)
    .bytes();
  const check = randomBytes(4).readUInt32BE(0);
  const secret = new SshWriter()
    .uint32(check)
    .uint32(check)
    .string("ssh-ed25519")
    .string(publicKey)
    .string(Uint8Array.from([...seed, ...publicKey]))
    .string(comment);
  // The private section is padded with 1, 2, 3, … to the cipher block size (8 for "none")
  for (
    let length = secret.bytes().length, pad = 1;
    length % 8 !== 0;
    length += 1, pad += 1
  ) {
    secret.byte(pad);
  }

  const body = new SshWriter()
    .raw(new TextEncoder().encode("openssh-key-v1\0"))
    .string("none")
    .string("none")
    .string("")
    .uint32(1)
    .string(publicBlob)
    .string(secret.bytes())
    .bytes();
  const base64 = Buffer.from(body).toString("base64");
  const lines = base64.match(/.{1,70}/g) ?? [];
  const text = [
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    ...lines,
    "-----END OPENSSH PRIVATE KEY-----",
    "",
  ].join("\n");
  const key = loadSshKey(text);

  return {
    privateKey: text,
    publicKey: publicKeyLine(key, comment),
    fingerprint: fingerprintOf(key.publicBlob),
  };
}
