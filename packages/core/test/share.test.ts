import { describe, expect, it } from "vitest";

import {
  deriveShareKeys,
  DecryptionError,
  generateShareSecret,
  openShare,
  sealShare,
  shareAccessHash,
  utf8Decode,
  utf8Encode,
} from "../src/index.js";

describe("share links", () => {
  const id = "4a9c3e9e-6d11-4b5e-9a39-0f1c2a7b5e10";

  it("round-trips a snapshot and binds it to the share id", async () => {
    const secret = generateShareSecret();
    const keys = await deriveShareKeys(secret, id);
    const sealed = sealShare(keys, id, utf8Encode("db-pass"));

    expect(utf8Decode(openShare(keys, id, sealed))).toBe("db-pass");
    expect(() => openShare(keys, "other-id", sealed)).toThrow(DecryptionError);
  });

  it("needs the passphrase for both the key and the access proof", async () => {
    const secret = generateShareSecret();
    const withPassphrase = await deriveShareKeys(secret, id, "공유 암호");
    const without = await deriveShareKeys(secret, id);
    const wrong = await deriveShareKeys(secret, id, "공유 암호!");
    const again = await deriveShareKeys(secret, id, "공유 암호");
    const sealed = sealShare(withPassphrase, id, utf8Encode("x"));

    expect(shareAccessHash(again.accessProof)).toEqual(
      shareAccessHash(withPassphrase.accessProof),
    );
    expect(shareAccessHash(wrong.accessProof)).not.toEqual(
      shareAccessHash(withPassphrase.accessProof),
    );
    expect(() => openShare(without, id, sealed)).toThrow(DecryptionError);
    expect(() => openShare(wrong, id, sealed)).toThrow(DecryptionError);
  });
});
