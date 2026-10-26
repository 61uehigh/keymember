import { describe, expect, it } from "vitest";

import { buildApp, PgliteDatabase, SqlStore } from "@keymember/server";

describe("trustProxy", () => {
  const clientIp = async (trustProxy: boolean | number | undefined) => {
    const db = new PgliteDatabase();
    const app = buildApp({
      store: new SqlStore(db),
      serverSecret: new Uint8Array(32).fill(1),
      ...(trustProxy === undefined ? {} : { trustProxy }),
    });

    app.get("/ip", (request) => request.ip);

    const response = await app.inject({
      url: "/ip",
      remoteAddress: "10.0.0.9",
      // The client wrote the first address; the proxy appended the one it saw
      headers: { "x-forwarded-for": "6.6.6.6, 203.0.113.7" },
    });

    await app.close();
    await db.close();

    return response.body;
  };

  it("takes the address the trusted proxy appended", async () => {
    expect(await clientIp(1)).toBe("203.0.113.7");
  });

  it("ignores the header unless told to trust it", async () => {
    expect(await clientIp(undefined)).toBe("10.0.0.9");
  });

  it("takes the client-chosen first address when every hop is trusted", async () => {
    expect(await clientIp(true)).toBe("6.6.6.6");
  });
});
