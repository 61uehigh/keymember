import { strToU8, zipSync } from "fflate";
import fc from "fast-check";
import { describe, it } from "vitest";

import {
  bestMatch,
  ImportFormatError,
  parse1Pux,
  parseBitwardenJson,
  parseChromeCsv,
  parseCxf,
  parseShareLink,
  parseTotp,
} from "@keymember/client";

import { p256PrivateKeyFromPkcs8 } from "../src/importers/importedPasskey.js";

const RUNS = { numRuns: 400 };

/**
 * ### importsOrRefuses
 *
 * Checks that an importer either returns a result or refuses with {@link ImportFormatError};
 * a crash (TypeError and the like) on a hostile export file would be a bug.
 *
 * @param work Parse call
 * @returns Whether the outcome is acceptable
 */
function importsOrRefuses(work: () => unknown): boolean {
  try {
    work();

    return true;
  } catch (error) {
    return error instanceof ImportFormatError;
  }
}

/**
 * ### jsonAround
 *
 * JSON documents shaped roughly like an export, with arbitrary values in every slot, so the
 * fuzzer reaches past the first shape check.
 *
 * @param template Field names the importer looks for
 * @returns The arbitrary
 */
function jsonAround(template: ReadonlyArray<string>): fc.Arbitrary<string> {
  const anyValue = fc.jsonValue({ maxDepth: 3 });

  return fc
    .record(Object.fromEntries(template.map((key) => [key, anyValue])), {
      requiredKeys: [],
    })
    .map((value) => JSON.stringify(value));
}

describe("fuzzing importers and parsers", () => {
  it("never crashes on arbitrary CSV text", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 400 }), (text) =>
        importsOrRefuses(() =>
          parseChromeCsv(`name,url,username,password,note\n${text}`),
        ),
      ),
      RUNS,
    );
  });

  it("never crashes on arbitrary or export-shaped Bitwarden JSON", () => {
    const item = fc.record(
      {
        type: fc.oneof(fc.constant(1), fc.constant(2), fc.jsonValue()),
        name: fc.jsonValue(),
        login: fc.oneof(
          fc.jsonValue(),
          fc.record({
            username: fc.jsonValue(),
            password: fc.jsonValue(),
            uris: fc.jsonValue(),
            fido2Credentials: fc.array(
              fc.record({
                credentialId: fc.string(),
                keyValue: fc.oneof(fc.string(), fc.base64String()),
                rpId: fc.string(),
                userHandle: fc.oneof(fc.string(), fc.constant(null)),
              }),
              { maxLength: 2 },
            ),
          }),
        ),
      },
      { requiredKeys: [] },
    );

    fc.assert(
      fc.property(
        fc.oneof(
          fc.string({ maxLength: 300 }),
          jsonAround(["encrypted", "folders", "items"]),
          fc
            .array(item, { maxLength: 4 })
            .map((items) => JSON.stringify({ items })),
        ),
        (text) => importsOrRefuses(() => parseBitwardenJson(text)),
      ),
      RUNS,
    );
  });

  it("never crashes on arbitrary or export-shaped CXF JSON", () => {
    const credential = fc.oneof(
      fc.jsonValue(),
      fc.record(
        {
          type: fc.constantFrom("basic-auth", "passkey", "totp", "note", "x"),
          username: fc.jsonValue(),
          password: fc.jsonValue(),
          secret: fc.jsonValue(),
          key: fc.oneof(fc.string(), fc.base64String()),
          credentialId: fc.string(),
          userHandle: fc.string(),
          rpId: fc.string(),
          content: fc.jsonValue(),
        },
        { requiredKeys: ["type"] },
      ),
    );

    fc.assert(
      fc.property(
        fc.oneof(
          fc.string({ maxLength: 300 }),
          jsonAround(["version", "exporterRpId", "accounts"]),
          fc
            .array(
              fc.record({
                id: fc.string(),
                title: fc.jsonValue(),
                credentials: fc.array(credential, { maxLength: 3 }),
              }),
              { maxLength: 3 },
            )
            .map((items) =>
              JSON.stringify({
                version: { major: 1, minor: 0 },
                exporterRpId: "x",
                accounts: [{ items }],
              }),
            ),
        ),
        (text) => importsOrRefuses(() => parseCxf(text)),
      ),
      RUNS,
    );
  });

  it("never crashes on arbitrary bytes or zips posing as a 1PUX export", () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.uint8Array({ maxLength: 300 }),
          fc.string({ maxLength: 300 }).map((text) =>
            zipSync({
              "export.data": strToU8(text),
              "export.attributes": strToU8("{}"),
            }),
          ),
        ),
        (bytes) => importsOrRefuses(() => parse1Pux(bytes)),
      ),
      { numRuns: 200 },
    );
  });

  it("reads arbitrary bytes as PKCS#8 without throwing", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 200 }), (bytes) => {
        const key = p256PrivateKeyFromPkcs8(bytes);

        return key === undefined || key.length === 32;
      }),
      RUNS,
    );
  });

  it("parses arbitrary share links, TOTP values and URLs without throwing", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 200 }), fc.webUrl(), (text, url) => {
        parseShareLink(text);
        parseShareLink(`https://k.example/#/share/${text}`);
        parseTotp(text);
        parseTotp(`otpauth://totp/x?${text}`);
        bestMatch([text, url], url);
        bestMatch([url], text);

        return true;
      }),
      RUNS,
    );
  });
});
