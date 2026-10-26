import { describe, expect, it } from "vitest";

import { parseTotp, totpCode } from "@keymember/client";

// RFC 6238 Appendix B test secrets ("12345678901234567890" repeated to the hash size), base32-encoded
const SHA1_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

describe("totpCode", () => {
  it("matches the RFC 6238 SHA-1 test vectors", () => {
    const parameters = parseTotp(
      `otpauth://totp/x?secret=${SHA1_SECRET}&digits=8`,
    );

    expect(parameters).toBeDefined();

    if (parameters === undefined) {
      return;
    }

    expect(totpCode(parameters, new Date(59 * 1000)).code).toBe("94287082");
    expect(totpCode(parameters, new Date(1111111109 * 1000)).code).toBe(
      "07081804",
    );
    expect(totpCode(parameters, new Date(2000000000 * 1000)).code).toBe(
      "69279037",
    );
  });

  it("accepts a bare base32 secret and rejects garbage", () => {
    expect(parseTotp("jbsw y3dp ehpk 3pxp")).toMatchObject({
      digits: 6,
      period: 30,
    });
    expect(parseTotp("not base32!")).toBeUndefined();
    expect(
      parseTotp("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4"),
    ).toBeUndefined();
  });
});
