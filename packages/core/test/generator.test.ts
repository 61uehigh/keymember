import { describe, expect, it } from "vitest";

import { generatePassword } from "@keymember/core";

describe("generatePassword", () => {
  it("honours length and always includes every class", () => {
    for (let i = 0; i < 200; i += 1) {
      const password = generatePassword({ length: 8 });

      expect(password).toHaveLength(8);
      expect(password).toMatch(/[a-z]/);
      expect(password).toMatch(/[A-Z]/);
      expect(password).toMatch(/[2-9]/);
      expect(password).toMatch(/[!@#$%^&*\-_=+]/);
    }
  });

  it("omits symbols on request and never emits ambiguous characters", () => {
    const sample = Array.from({ length: 200 }, () =>
      generatePassword({ symbols: false }),
    ).join("");

    expect(sample).not.toMatch(/[!@#$%^&*\-_=+]/);
    expect(sample).not.toMatch(/[01lIO]/);
  });

  it("rejects unsafe lengths", () => {
    expect(() => generatePassword({ length: 7 })).toThrow(RangeError);
    expect(() => generatePassword({ length: 129 })).toThrow(RangeError);
  });
});
