import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { parseContentCommand } from "../src/content/command.js";
import {
  contentCommandSchema,
  contentRequestSchema,
  menuRequestSchema,
  passkeyContentRequestSchema,
  passkeyWindowRequestSchema,
  popupRequestSchema,
} from "../src/shared/messages.js";

const RUNS = { numRuns: 1000 };

/**
 * ### commandLike
 *
 * Objects close to real background-to-content commands, so the fuzzer explores the branches
 * of the validator instead of failing at the first check.
 */
const commandLike = fc.record(
  {
    type: fc.constantFrom("fill", "close-menu", "other", 1),
    expectedUrl: fc.oneof(fc.webUrl(), fc.jsonValue()),
    kind: fc.oneof(
      fc.constantFrom("username", "password", "otp"),
      fc.jsonValue(),
    ),
    username: fc.oneof(fc.string(), fc.jsonValue()),
    password: fc.oneof(fc.string(), fc.jsonValue()),
    totp: fc.oneof(fc.string(), fc.jsonValue()),
  },
  { requiredKeys: [] },
);

describe("fuzzing extension message validation", () => {
  it("accepts in the content script exactly the commands the schema accepts", () => {
    fc.assert(
      fc.property(fc.oneof(fc.anything(), commandLike), (message) => {
        const handWritten = parseContentCommand(message);
        const schema = contentCommandSchema.safeParse(message);

        expect(handWritten !== undefined).toBe(schema.success);

        if (handWritten !== undefined && schema.success) {
          expect(handWritten).toEqual(schema.data);
        }
      }),
      RUNS,
    );
  });

  it("validates arbitrary messages without throwing", () => {
    const schemas = [
      popupRequestSchema,
      contentRequestSchema,
      menuRequestSchema,
      passkeyContentRequestSchema,
      passkeyWindowRequestSchema,
    ];

    fc.assert(
      fc.property(fc.anything(), (message) => {
        for (const schema of schemas) {
          schema.safeParse(message);
        }

        return true;
      }),
      RUNS,
    );
  });
});
