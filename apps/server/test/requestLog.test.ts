import { describe, expect, it } from "vitest";

import { redactQuery } from "../src/buildApp.js";

describe("request log", () => {
  it("keeps query names but drops their values", () => {
    expect(
      redactQuery("/api/auth/sso/callback?code=secret-code&state=abc"),
    ).toBe("/api/auth/sso/callback?code=[redacted]&state=[redacted]");
    expect(redactQuery("/api/auth/sso/start?ticket=t1")).toBe(
      "/api/auth/sso/start?ticket=[redacted]",
    );
    expect(redactQuery("/api/org")).toBe("/api/org");
  });
});
