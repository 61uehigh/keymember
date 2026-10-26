import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  inviteLinkUrl,
  parseInviteLink,
  parseInviteParams,
} from "@keymember/client";
import { toBase64Url } from "@keymember/core";

const OWNER = "8a7a5c8e-0d6b-4e6f-9a3e-1f2b3c4d5e6f";
const KEY = new Uint8Array(32).fill(7);
const SECRET = new Uint8Array(32).fill(3);
const link = {
  token: "tok",
  email: "bob@example.com",
  secret: SECRET,
  roots: new Map([[OWNER, KEY]]),
};

/**
 * ### paramsWith
 *
 * The parameters of a valid link with some replaced.
 *
 * @param changes Parameters to set
 * @returns The parameters
 */
function paramsWith(changes: Record<string, string>): URLSearchParams {
  const params = new URLSearchParams({
    invite: "tok",
    email: "bob@example.com",
    secret: toBase64Url(SECRET),
    roots: `${OWNER}.${toBase64Url(KEY)}`,
  });

  for (const [name, value] of Object.entries(changes)) {
    params.set(name, value);
  }

  return params;
}

describe("invite links", () => {
  it("round-trips through the URL the admin sends", () => {
    const parsed = parseInviteLink(
      inviteLinkUrl("https://vault.example.com/some/path", link),
    );

    expect(parsed?.serverUrl).toBe("https://vault.example.com");
    expect(parsed?.token).toBe("tok");
    expect(parsed?.secret).toEqual(SECRET);
    expect([...(parsed?.roots ?? [])]).toEqual([[OWNER, KEY]]);
  });

  it("refuses links that are incomplete or malformed", () => {
    const refused = [
      paramsWith({ secret: toBase64Url(new Uint8Array(31)) }),
      paramsWith({ secret: "not base64!" }),
      paramsWith({ roots: "" }),
      paramsWith({ roots: `${OWNER}.${toBase64Url(new Uint8Array(16))}` }),
      paramsWith({ roots: `.${toBase64Url(KEY)}` }),
      paramsWith({ roots: OWNER }),
      paramsWith({ invite: "" }),
      paramsWith({ email: "" }),
    ];

    for (const params of refused) {
      expect(parseInviteParams(params)).toBeUndefined();
    }
  });

  it("keeps only well-formed roots from a mixed list", () => {
    const parsed = parseInviteParams(
      paramsWith({
        roots: `${OWNER}.${toBase64Url(KEY)},junk,other.${toBase64Url(new Uint8Array(5))}`,
      }),
    );

    expect([...(parsed?.roots.keys() ?? [])]).toEqual([OWNER]);
  });

  it("only reads join links", () => {
    expect(parseInviteLink("not a url")).toBeUndefined();
    expect(
      parseInviteLink(
        `https://vault.example.com/#/share/x?${paramsWith({}).toString()}`,
      ),
    ).toBeUndefined();
    expect(
      parseInviteLink(
        `https://vault.example.com/?${paramsWith({}).toString()}`,
      ),
    ).toBeUndefined();
  });

  it("never throws, and every root it accepts holds a 32-byte key", () => {
    fc.assert(
      fc.property(
        fc.string({ maxLength: 300 }),
        fc.dictionary(
          fc.constantFrom("invite", "email", "secret", "roots"),
          fc.string({ maxLength: 120 }),
        ),
        (text, params) => {
          parseInviteLink(text);
          parseInviteLink(`https://k.example/#/join?${text}`);

          const parsed = parseInviteParams(new URLSearchParams(params));

          return (
            parsed === undefined ||
            (parsed.secret.length === 32 &&
              [...parsed.roots.values()].every((key) => key.length === 32))
          );
        },
      ),
      { numRuns: 300 },
    );
  });
});
