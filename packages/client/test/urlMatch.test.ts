import { describe, expect, it } from "vitest";

import { bestMatch, matchUrl, siteKeyOf } from "@keymember/client";

describe("matchUrl", () => {
  it("matches subdomains of the same registrable domain, ranking the exact host higher", () => {
    expect(
      matchUrl(
        "https://nid.naver.com/nidlogin.login",
        "https://nid.naver.com/other",
      ),
    ).toBe("host");
    expect(
      matchUrl("https://naver.com", "https://nid.naver.com/nidlogin.login"),
    ).toBe("site");
    expect(
      matchUrl("accounts.kakao.com", "https://accounts.kakao.com/login"),
    ).toBe("host");
  });

  it("treats Korean second-level and private suffixes as public, so unrelated sites never match", () => {
    expect(
      matchUrl("https://shop-a.co.kr", "https://shop-b.co.kr"),
    ).toBeUndefined();
    expect(
      matchUrl("https://alice.github.io", "https://mallory.github.io"),
    ).toBeUndefined();
    expect(
      matchUrl("https://www.gov.kr", "https://evil-gov.kr"),
    ).toBeUndefined();
  });

  it("does not match lookalike or nested phishing hosts", () => {
    expect(
      matchUrl("https://github.com", "https://github.com.evil.example"),
    ).toBeUndefined();
    expect(
      matchUrl("https://github.com", "https://githuh.com"),
    ).toBeUndefined();
    expect(
      matchUrl("https://paypal.com", "https://xn--pypal-4ve.com"),
    ).toBeUndefined();
  });

  it("compares IP addresses and localhost by exact host and port", () => {
    expect(
      matchUrl("http://localhost:3000", "http://localhost:3000/login"),
    ).toBe("host");
    expect(
      matchUrl("http://localhost:3000", "http://localhost:4000"),
    ).toBeUndefined();
    expect(matchUrl("https://10.0.0.5", "https://10.0.0.6")).toBeUndefined();
  });

  it("reads an item saved without a scheme but with a port as https", () => {
    expect(
      matchUrl(
        "intranet.example.com:8443",
        "https://intranet.example.com:8443/x",
      ),
    ).toBe("host");
    expect(matchUrl("localhost:3000", "https://localhost:3000/login")).toBe(
      "host",
    );
  });

  it("treats another port on a named host as another service", () => {
    expect(
      matchUrl(
        "https://intranet.example.com:8443",
        "https://intranet.example.com:9000",
      ),
    ).toBeUndefined();
    expect(
      matchUrl("https://example.com", "https://example.com:8443/admin"),
    ).toBeUndefined();
    expect(matchUrl("https://example.com:443", "https://example.com")).toBe(
      "host",
    );
  });

  it("flags an https item on an http page instead of matching it", () => {
    expect(
      matchUrl(
        "https://intranet.example.com",
        "http://intranet.example.com/login",
      ),
    ).toBe("insecure");
    expect(matchUrl("http://old.example.com", "http://old.example.com")).toBe(
      "host",
    );
  });

  it("never matches non-web schemes", () => {
    expect(siteKeyOf("javascript:alert(1)")).toBeUndefined();
    expect(siteKeyOf("chrome-extension://abc/popup.html")).toBeUndefined();
    expect(
      matchUrl("https://example.com", "file:///etc/passwd"),
    ).toBeUndefined();
  });

  it("picks the best quality across an item's URLs", () => {
    expect(
      bestMatch(
        ["https://example.com", "https://login.example.com"],
        "https://login.example.com",
      ),
    ).toBe("host");
    expect(
      bestMatch(["https://other.test"], "https://example.com"),
    ).toBeUndefined();
  });
});
