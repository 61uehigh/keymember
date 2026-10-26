import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";

import {
  assertKdfParams,
  DEFAULT_KDF_PARAMS,
  deriveAccountSecrets,
  deriveAuthVerifier,
  formatSecretKey,
  generateSecretKey,
  KdfParametersRejectedError,
  parseSecretKey,
  SECRET_KEY_ALPHABET,
} from "@keymember/core";
import type { SecretKey } from "@keymember/core";

const fixedSecretKey: SecretKey = {
  version: "K1",
  accountId: "ABCDEF",
  secret: "23456789ABCDEFGHJKLMNPQRST",
};
const fixedSalt = hexToBytes("000102030405060708090a0b0c0d0e0f");

describe("SecretKey", () => {
  it("round-trips through the formatted form", () => {
    const key = generateSecretKey();
    const formatted = formatSecretKey(key);

    expect(formatted).toMatch(
      /^K1-[2-9A-HJ-NP-TV-Z]{6}(-[2-9A-HJ-NP-TV-Z]{5,6}){5}$/,
    );
    expect(parseSecretKey(formatted)).toEqual(key);
  });

  it("accepts lowercase and missing or extra separators", () => {
    const formatted = formatSecretKey(fixedSecretKey);

    expect(parseSecretKey(formatted.toLowerCase().replace(/-/g, " "))).toEqual(
      fixedSecretKey,
    );
  });

  it("rejects ambiguous characters, wrong version and wrong length", () => {
    expect(
      parseSecretKey("K1-ABCDEF-0OIU1A-AAAAA-AAAAA-AAAAA-AAAAA"),
    ).toBeUndefined();
    expect(
      parseSecretKey("K2-ABCDEF-23456-789AB-CDEFG-HJKLM-NPQRST"),
    ).toBeUndefined();
    expect(parseSecretKey("K1-ABCDEF-2345")).toBeUndefined();
  });

  it("only draws characters from the alphabet", () => {
    const seen = new Set<string>();

    for (let i = 0; i < 200; i += 1) {
      for (const char of generateSecretKey().secret) {
        seen.add(char);
      }
    }

    expect([...seen].every((char) => SECRET_KEY_ALPHABET.includes(char))).toBe(
      true,
    );
    expect(seen.size).toBe(SECRET_KEY_ALPHABET.length);
  });
});

describe("assertKdfParams", () => {
  it("accepts the defaults", () => {
    expect(() => {
      assertKdfParams(DEFAULT_KDF_PARAMS);
    }).not.toThrow();
  });

  it.each([
    { memoryKiB: 32 * 1024 },
    { iterations: 2 },
    { parallelism: 0 },
    { memoryKiB: 2 * 1024 * 1024 },
    { iterations: 11 },
    { iterations: 3.5 },
  ])("rejects a downgraded or abusive value %o", (override) => {
    expect(() => {
      assertKdfParams({ ...DEFAULT_KDF_PARAMS, ...override });
    }).toThrow(KdfParametersRejectedError);
  });

  it("refuses to derive with rejected parameters", async () => {
    await expect(
      deriveAccountSecrets("pw", fixedSecretKey, fixedSalt, {
        ...DEFAULT_KDF_PARAMS,
        memoryKiB: 1024,
      }),
    ).rejects.toThrow(KdfParametersRejectedError);
  });
});

describe("deriveAccountSecrets", () => {
  // Cross-checked against an independent implementation (Python argon2-cffi + cryptography HKDF)
  it("matches the cross-implementation test vector", async () => {
    const secrets = await deriveAccountSecrets(
      "correct horse battery staple",
      fixedSecretKey,
      fixedSalt,
      DEFAULT_KDF_PARAMS,
    );

    expect(bytesToHex(secrets.accountUnlockKey)).toBe(
      "b2be316622a4b3d05acc1655ea78d20b44980d37fa6d6c55243236d8e97cc486",
    );
    expect(bytesToHex(secrets.authenticationKey)).toBe(
      "2c027cdfc9bb7d184b24812685d17cec7b793910a7784c80e5689f1bfc10d719",
    );
  });

  it("separates the unlock key from the authentication key", async () => {
    const secrets = await deriveAccountSecrets(
      "pw",
      fixedSecretKey,
      fixedSalt,
      DEFAULT_KDF_PARAMS,
    );

    expect(secrets.accountUnlockKey).not.toEqual(secrets.authenticationKey);
    expect(deriveAuthVerifier(secrets.authenticationKey)).not.toEqual(
      secrets.accountUnlockKey,
    );
  });

  it("normalises surrounding whitespace and Unicode composition", async () => {
    const composed = await deriveAccountSecrets(
      "café",
      fixedSecretKey,
      fixedSalt,
      DEFAULT_KDF_PARAMS,
    );
    const decomposed = await deriveAccountSecrets(
      " café ",
      fixedSecretKey,
      fixedSalt,
      DEFAULT_KDF_PARAMS,
    );

    expect(decomposed.accountUnlockKey).toEqual(composed.accountUnlockKey);
  });

  it("depends on the Secret Key", async () => {
    const original = await deriveAccountSecrets(
      "pw",
      fixedSecretKey,
      fixedSalt,
      DEFAULT_KDF_PARAMS,
    );
    const otherKey = await deriveAccountSecrets(
      "pw",
      { ...fixedSecretKey, secret: "33456789ABCDEFGHJKLMNPQRST" },
      fixedSalt,
      DEFAULT_KDF_PARAMS,
    );

    expect(otherKey.accountUnlockKey).not.toEqual(original.accountUnlockKey);
    expect(otherKey.authenticationKey).not.toEqual(original.authenticationKey);
  });
});
