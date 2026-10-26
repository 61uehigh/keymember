import { createHash, generateKeyPairSync, verify } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  assertPasskey,
  detectImportFormat,
  parseBitwardenJson,
  parseCxf,
} from "@keymember/client";
import { fromBase64Url, utf8Encode } from "@keymember/core";

/**
 * ### exportedKey
 *
 * A P-256 key as passkey exports carry it: PKCS#8 DER, plus the public key to check against.
 *
 * @param encoding base64url or plain base64
 * @returns The encoded private key and the public key object
 */
function exportedKey(encoding: "base64url" | "base64" = "base64url") {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });

  return {
    pkcs8: privateKey
      .export({ format: "der", type: "pkcs8" })
      .toString(encoding),
    publicKey,
  };
}

/**
 * ### signsFor
 *
 * Whether an imported passkey signs assertions that the original public key verifies.
 *
 * @param passkey Imported passkey
 * @param publicKey Original public key
 * @returns Whether the signature verifies
 */
function signsFor(
  passkey: Parameters<typeof assertPasskey>[0],
  publicKey: ReturnType<typeof exportedKey>["publicKey"],
): boolean {
  const assertion = assertPasskey(passkey, {
    origin: `https://${passkey.rpId}`,
    rpId: passkey.rpId,
    challenge: utf8Encode("challenge"),
    userVerified: true,
  });
  const clientHash = createHash("sha256")
    .update(assertion.clientDataJSON)
    .digest();

  return verify(
    "sha256",
    Buffer.concat([assertion.authenticatorData, clientHash]),
    publicKey,
    assertion.signature,
  );
}

describe("passkey import", () => {
  it("imports Bitwarden fido2Credentials, including GUID credential ids", () => {
    const key = exportedKey();
    const { items, skipped } = parseBitwardenJson(
      JSON.stringify({
        encrypted: false,
        items: [
          {
            type: 1,
            name: "GitHub",
            login: {
              username: "kim",
              password: "pw",
              uris: [{ uri: "https://github.com" }],
              fido2Credentials: [
                {
                  credentialId: "6b3a2f1e-0d4c-4b5a-9e8f-7a6b5c4d3e2f",
                  keyType: "public-key",
                  keyAlgorithm: "ECDSA",
                  keyCurve: "P-256",
                  keyValue: key.pkcs8,
                  rpId: "github.com",
                  userHandle: "dXNlci1oYW5kbGU",
                  userName: "kim",
                  userDisplayName: "Kim",
                  creationDate: "2026-01-02T03:04:05.000Z",
                },
                {
                  credentialId: "b64.AAEC",
                  keyValue: "bm90IGEga2V5",
                  rpId: "broken.example",
                },
              ],
            },
          },
        ],
      }),
    );
    const [passkey] = items[0]?.details.passkeys ?? [];

    expect(items[0]?.details.password).toBe("pw");
    expect(passkey).toMatchObject({
      rpId: "github.com",
      userName: "kim",
      userHandle: "dXNlci1oYW5kbGU",
      createdAt: "2026-01-02T03:04:05.000Z",
    });
    expect(fromBase64Url(passkey?.credentialId ?? "")).toEqual(
      Uint8Array.from(Buffer.from("6b3a2f1e0d4c4b5a9e8f7a6b5c4d3e2f", "hex")),
    );
    expect(passkey !== undefined && signsFor(passkey, key.publicKey)).toBe(
      true,
    );
    expect(skipped).toEqual([
      "GitHub: passkey for broken.example: only P-256 (ES256) keys are supported",
    ]);
  });

  it("imports a CXF export with logins, passkeys, TOTP, notes and collections", () => {
    const key = exportedKey("base64");
    const cxf = {
      version: { major: 1, minor: 0 },
      exporterRpId: "exporter.example",
      exporterDisplayName: "Exporter",
      timestamp: 1767225600,
      accounts: [
        {
          id: "YWNjb3VudA",
          username: "kim",
          email: "kim@example.com",
          collections: [
            { id: "Yw", title: "개발", items: [{ item: "aXRlbTE" }] },
          ],
          items: [
            {
              id: "aXRlbTE",
              creationAt: 1767225600,
              title: "AWS",
              scope: { urls: ["https://console.aws.amazon.com"] },
              credentials: [
                {
                  type: "basic-auth",
                  username: { fieldType: "string", value: "admin" },
                  password: { fieldType: "concealed-string", value: "s3cret" },
                },
                {
                  type: "totp",
                  secret: "JBSWY3DPEHPK3PXP",
                  period: 30,
                  digits: 6,
                  algorithm: "sha1",
                  issuer: "AWS",
                  username: "admin",
                },
                {
                  type: "passkey",
                  credentialId: "Y3JlZA",
                  rpId: "aws.amazon.com",
                  username: "admin",
                  userDisplayName: "Admin",
                  userHandle: "dXNlcg",
                  key: key.pkcs8,
                },
                { type: "credit-card", number: { value: "4111" } },
              ],
            },
            {
              id: "bm90ZQ",
              title: "Wi-Fi 메모",
              credentials: [
                {
                  type: "note",
                  content: { fieldType: "string", value: "SSID example" },
                },
              ],
            },
          ],
        },
      ],
    };
    const text = JSON.stringify(cxf);
    const { items, skipped } = parseCxf(text);
    const [aws, note] = items;

    expect(
      detectImportFormat("export.json", new TextEncoder().encode(text)),
    ).toBe("cxf-json");
    expect(aws).toMatchObject({
      folder: "개발",
      overview: {
        type: "login",
        title: "AWS",
        urls: ["https://console.aws.amazon.com"],
      },
      details: { username: "admin", password: "s3cret" },
    });
    expect(aws?.details.totp).toMatch(
      /^otpauth:\/\/totp\/AWS%3Aadmin\?secret=JBSWY3DPEHPK3PXP/,
    );
    expect(aws?.details.passkeys?.[0]?.rpId).toBe("aws.amazon.com");
    expect(
      aws?.details.passkeys?.[0] !== undefined &&
        signsFor(aws.details.passkeys[0], key.publicKey),
    ).toBe(true);
    expect(note).toMatchObject({
      overview: { type: "secure-note", title: "Wi-Fi 메모" },
      details: { notes: "SSID example" },
    });
    expect(skipped).toEqual(["AWS: unsupported credential type credit-card"]);
  });

  it("refuses passkeys on curves other than P-256", () => {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    const { items, skipped } = parseBitwardenJson(
      JSON.stringify({
        items: [
          {
            type: 1,
            name: "X",
            login: {
              fido2Credentials: [
                {
                  credentialId: "b64.AAEC",
                  keyValue: privateKey
                    .export({ format: "der", type: "pkcs8" })
                    .toString("base64url"),
                  rpId: "x.example",
                },
              ],
            },
          },
        ],
      }),
    );

    expect(items[0]?.details.passkeys).toBeUndefined();
    expect(skipped).toHaveLength(1);
  });
});
