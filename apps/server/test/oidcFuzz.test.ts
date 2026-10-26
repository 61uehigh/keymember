import { generateKeyPairSync, sign } from "node:crypto";

import fc from "fast-check";
import { describe, it } from "vitest";

import { OidcClient, OidcError } from "../src/services/OidcClient.js";
import { FakeIdp } from "./fakeIdp.js";

/**
 * ### verifiesOrRefuses
 *
 * Checks that ID token verification of hostile input fails only with {@link OidcError}.
 *
 * @param client OIDC client
 * @param token Token text
 * @returns Whether the outcome is acceptable
 */
async function verifiesOrRefuses(
  client: OidcClient,
  token: string,
): Promise<boolean> {
  try {
    await client.verifyIdToken(token, "nonce");

    // Nothing random should ever pass verification
    return false;
  } catch (error) {
    return error instanceof OidcError;
  }
}

describe("fuzzing ID token verification", () => {
  const idp = new FakeIdp();
  const client = new OidcClient(idp.config("example.com"), idp.fetch);
  const segment = fc
    .oneof(
      fc.string({ maxLength: 60 }),
      fc
        .jsonValue({ maxDepth: 2 })
        .map((value) =>
          Buffer.from(JSON.stringify(value)).toString("base64url"),
        ),
    )
    .filter((text) => !text.includes("."));

  it("refuses arbitrary and JWT-shaped garbage with OidcError only", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.oneof(
          fc.string({ maxLength: 200 }),
          fc.tuple(segment, segment, segment).map((parts) => parts.join(".")),
        ),
        (token) => verifiesOrRefuses(client, token),
      ),
      { numRuns: 300 },
    );
  });

  it("refuses well-formed tokens with arbitrary claims signed by an unknown key", async () => {
    const stranger = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const encode = (value: unknown): string =>
      Buffer.from(JSON.stringify(value)).toString("base64url");

    await fc.assert(
      fc.asyncProperty(
        fc.dictionary(
          fc.string({ maxLength: 8 }),
          fc.jsonValue({ maxDepth: 1 }),
        ),
        fc.constantFrom("RS256", "ES256", "none", "HS256"),
        async (claims, alg) => {
          const signed = `${encode({ alg, kid: "x" })}.${encode(claims)}`;
          const signature = sign(
            "sha256",
            Buffer.from(signed),
            stranger.privateKey,
          ).toString("base64url");

          return verifiesOrRefuses(client, `${signed}.${signature}`);
        },
      ),
      { numRuns: 100 },
    );
  });
});
