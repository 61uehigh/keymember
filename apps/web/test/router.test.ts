// @vitest-environment happy-dom
import { describe, expect, it } from "vitest";

import { clearSensitiveParams, parseRoute } from "../src/lib/router.js";

describe("parseRoute", () => {
  it("reads the path and query of a hash route", () => {
    const route = parseRoute("#/join?invite=abc&email=bob%40example.com");

    expect(route.path).toBe("/join");
    expect(route.params.get("invite")).toBe("abc");
    expect(route.params.get("email")).toBe("bob@example.com");
  });

  it("treats an empty hash as the root route", () => {
    expect(parseRoute("").path).toBe("/");
    expect(parseRoute("#").path).toBe("/");
    expect(parseRoute("#?x=1").path).toBe("/");
  });

  it("splits only at the first question mark", () => {
    expect(parseRoute("#/share/id?k=a?b").params.get("k")).toBe("a?b");
  });

  it("accepts a hash without the leading #", () => {
    expect(parseRoute("/vault").path).toBe("/vault");
  });
});

describe("clearSensitiveParams", () => {
  it("drops the query from the address without adding a history entry", () => {
    location.hash = "#/join?invite=secret-token";

    const before = history.length;

    clearSensitiveParams("/join");

    expect(location.hash).toBe("#/join");
    expect(location.href).not.toContain("secret-token");
    expect(history.length).toBe(before);
  });
});
