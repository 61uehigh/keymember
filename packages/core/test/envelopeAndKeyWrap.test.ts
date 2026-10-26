import { describe, expect, it } from "vitest";

import {
  DecryptionError,
  generateEncryptionKeyPair,
  generateSymmetricKey,
  openBytes,
  readEnvelopeKeyId,
  sealBytes,
  utf8Encode,
} from "../src/index.js";
import type { EnvelopeContext, WrapContext } from "../src/index.js";

import { unwrapKey, wrapKey } from "../src/keyWrap.js";

const context: EnvelopeContext = { kind: "item.details", scope: ["item-1"] };

describe("envelope", () => {
  it("round-trips and records the key id", () => {
    const key = generateSymmetricKey();
    const envelope = sealBytes(key, utf8Encode("hunter2"), context);

    expect(openBytes(key, envelope, context)).toEqual(utf8Encode("hunter2"));
    expect(readEnvelopeKeyId(envelope)).toEqual(key.id);
  });

  it("uses a fresh nonce for every seal", () => {
    const key = generateSymmetricKey();

    expect(sealBytes(key, utf8Encode("same"), context)).not.toEqual(
      sealBytes(key, utf8Encode("same"), context),
    );
  });

  it("fails with the wrong key", () => {
    const envelope = sealBytes(
      generateSymmetricKey(),
      utf8Encode("x"),
      context,
    );

    expect(() => openBytes(generateSymmetricKey(), envelope, context)).toThrow(
      DecryptionError,
    );
  });

  it("fails when the server moves the ciphertext to another item or field", () => {
    const key = generateSymmetricKey();
    const envelope = sealBytes(key, utf8Encode("x"), context);

    expect(() =>
      openBytes(key, envelope, { kind: "item.details", scope: ["item-2"] }),
    ).toThrow(DecryptionError);
    expect(() =>
      openBytes(key, envelope, { kind: "item.overview", scope: ["item-1"] }),
    ).toThrow(DecryptionError);
  });

  it("fails when any ciphertext byte is flipped", () => {
    const key = generateSymmetricKey();
    const envelope = sealBytes(key, utf8Encode("x"), context);
    const tampered = envelope.slice();
    const last = tampered.length - 1;

    tampered[last] = (tampered[last] ?? 0) ^ 1;

    expect(() => openBytes(key, tampered, context)).toThrow(DecryptionError);
  });

  it("hides the exact plaintext length inside a 32-byte block", () => {
    const key = generateSymmetricKey();
    const sizes = new Set<number>();

    for (let length = 0; length < 32; length += 1) {
      sizes.add(sealBytes(key, new Uint8Array(length), context).length);
    }

    expect(sizes.size).toBe(1);
  });
});

describe("keyWrap", () => {
  const wrapContext: WrapContext = {
    purpose: "vault-key",
    scope: ["vault-1", 1, "user-1"],
  };

  it("round-trips a key to the intended recipient", async () => {
    const recipient = generateEncryptionKeyPair();
    const key = generateSymmetricKey();
    const wrapped = await wrapKey(key, recipient.publicKey, wrapContext);

    expect(await unwrapKey(wrapped, recipient, wrapContext)).toEqual(key);
  });

  it("cannot be unwrapped by another recipient", async () => {
    const wrapped = await wrapKey(
      generateSymmetricKey(),
      generateEncryptionKeyPair().publicKey,
      wrapContext,
    );

    await expect(
      unwrapKey(wrapped, generateEncryptionKeyPair(), wrapContext),
    ).rejects.toThrow(DecryptionError);
  });

  it("cannot be replayed for another vault, generation or principal", async () => {
    const recipient = generateEncryptionKeyPair();
    const wrapped = await wrapKey(
      generateSymmetricKey(),
      recipient.publicKey,
      wrapContext,
    );

    for (const scope of [
      ["vault-2", 1, "user-1"],
      ["vault-1", 2, "user-1"],
      ["vault-1", 1, "user-2"],
    ]) {
      await expect(
        unwrapKey(wrapped, recipient, { purpose: "vault-key", scope }),
      ).rejects.toThrow(DecryptionError);
    }
  });
});
