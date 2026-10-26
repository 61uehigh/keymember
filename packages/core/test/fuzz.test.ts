import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { decodeCbor, encodeCbor } from "../src/cbor.js";
import { unwrapKey, wrapKey } from "../src/keyWrap.js";
import { verifyStatement } from "../src/signing.js";
import {
  DecryptionError,
  fromBase64Url,
  generateEncryptionKeyPair,
  generateSymmetricKey,
  MalformedDataError,
  openBytes,
  parseSecretKey,
  sealBytes,
} from "../src/index.js";

const RUNS = { numRuns: 500 };

/**
 * ### rejectsCleanly
 *
 * Runs parsing or decryption of untrusted bytes and checks it either succeeds or fails with one
 * of keymember's own error types, never a crash from deeper down (TypeError, RangeError, …).
 *
 * @param work Work on untrusted input
 * @returns Whether the outcome is acceptable
 */
function rejectsCleanly(work: () => unknown): boolean {
  try {
    work();

    return true;
  } catch (error) {
    return (
      error instanceof MalformedDataError || error instanceof DecryptionError
    );
  }
}

/**
 * ### flipOneBit
 *
 * Copies bytes with one bit flipped.
 *
 * @param bytes Original
 * @param position Bit to flip, taken modulo the length
 * @returns The altered copy
 */
function flipOneBit(bytes: Uint8Array, position: number): Uint8Array {
  const copy = bytes.slice();
  const bit = position % (copy.length * 8);
  const index = Math.floor(bit / 8);

  copy[index] = (copy[index] ?? 0) ^ (1 << (bit % 8));

  return copy;
}

describe("fuzzing untrusted input", () => {
  it("decodes arbitrary bytes as CBOR or refuses them with MalformedDataError", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 512 }), (bytes) =>
        rejectsCleanly(() => decodeCbor(bytes)),
      ),
      RUNS,
    );
  });

  it("never opens an envelope that is random or has a single flipped bit", () => {
    const key = generateSymmetricKey();
    const context = { kind: "fuzz", scope: ["a", 1] };
    const sealed = sealBytes(key, new TextEncoder().encode("secret"), context);

    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 512 }), (bytes) =>
        rejectsCleanly(() => openBytes(key, bytes, context)),
      ),
      RUNS,
    );
    fc.assert(
      fc.property(fc.nat(), (position) => {
        expect(() =>
          openBytes(key, flipOneBit(sealed, position), context),
        ).toThrow(Error);

        return rejectsCleanly(() =>
          openBytes(key, flipOneBit(sealed, position), context),
        );
      }),
      RUNS,
    );
  });

  it("never unwraps a random or altered wrapped key", async () => {
    const recipient = generateEncryptionKeyPair();
    const context = { purpose: "fuzz", scope: ["x"] };
    const wrapped = await wrapKey(
      generateSymmetricKey(),
      recipient.publicKey,
      context,
    );

    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 256 }), async (bytes) => {
        try {
          await unwrapKey(bytes, recipient, context);

          return false;
        } catch (error) {
          return (
            error instanceof MalformedDataError ||
            error instanceof DecryptionError
          );
        }
      }),
      { numRuns: 200 },
    );
    await fc.assert(
      fc.asyncProperty(fc.nat(), async (position) => {
        await expect(
          unwrapKey(flipOneBit(wrapped, position), recipient, context),
        ).rejects.toThrow(Error);

        return true;
      }),
      { numRuns: 200 },
    );
  });

  it("answers signature checks on junk with false, never an exception", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ maxLength: 64 }),
        fc.uint8Array({ maxLength: 80 }),
        fc.string(),
        (publicKey, signature, statement) =>
          !verifyStatement(
            publicKey,
            "keymember/login/v1",
            statement,
            signature,
          ),
      ),
      RUNS,
    );
  });

  it("parses arbitrary text as a Secret Key or base64url without throwing", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 120 }), (text) => {
        parseSecretKey(text);
        fromBase64Url(text);

        return true;
      }),
      RUNS,
    );
  });
});

describe("wrapped key suites", () => {
  it("refuses a wrapped key for a suite this build does not implement", async () => {
    const recipient = generateEncryptionKeyPair();
    // Suite 2 is reserved for the hybrid X25519 + ML-KEM (X-Wing) wrap; see docs/design/pq-migration.md
    const future = encodeCbor({
      suite: 2,
      enc: new Uint8Array(1120),
      ct: new Uint8Array(64),
    });

    await expect(
      unwrapKey(future, recipient, { purpose: "vault-key", scope: [] }),
    ).rejects.toBeInstanceOf(MalformedDataError);
  });
});
