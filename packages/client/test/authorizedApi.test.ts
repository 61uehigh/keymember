import { describe, expect, it } from "vitest";

import { AuthorizedApi } from "../src/session/AuthorizedApi.js";
import { ApiError } from "../src/transport.js";
import type { ApiRequest, Transport } from "../src/transport.js";

/**
 * ### fakeServer
 *
 * A transport that accepts one access token at a time and swaps a refresh token for the next
 * pair once, as the real server does.
 *
 * @returns The transport and the requests it saw
 */
function fakeServer(): { transport: Transport; seen: Array<ApiRequest> } {
  const seen: Array<ApiRequest> = [];
  let valid = "access-1";
  let refresh = "refresh-1";
  const transport: Transport = (request) => {
    seen.push(request);

    if (request.path === "/api/auth/refresh") {
      const body = request.body as { refreshToken: string };

      if (body.refreshToken !== refresh) {
        return Promise.resolve({
          status: 401,
          body: { error: "unauthorized" },
        });
      }

      valid = "access-2";
      refresh = "refresh-2";

      return Promise.resolve({
        status: 200,
        body: {
          accessToken: valid,
          refreshToken: refresh,
          accessExpiresAt: "2026-10-23T00:15:00Z",
        },
      });
    }

    return Promise.resolve(
      request.token === valid
        ? { status: 200, body: { ok: true } }
        : { status: 401, body: { error: "unauthorized" } },
    );
  };

  return { transport, seen };
}

describe("AuthorizedApi", () => {
  it("refreshes once on a 401, retries, and tells the listener", async () => {
    const { transport, seen } = fakeServer();
    const api = new AuthorizedApi(transport, {
      accessToken: "expired",
      refreshToken: "refresh-1",
    });
    let refreshed = 0;

    api.onTokensChanged(() => {
      refreshed += 1;
    });

    expect(await api.request({ method: "GET", path: "/api/org" })).toEqual({
      ok: true,
    });
    expect(api.tokens).toEqual({
      accessToken: "access-2",
      refreshToken: "refresh-2",
    });
    expect(refreshed).toBe(1);
    expect(seen.map((request) => request.path)).toEqual([
      "/api/org",
      "/api/auth/refresh",
      "/api/org",
    ]);
  });

  it("gives up when the refresh token is no longer valid", async () => {
    const { transport } = fakeServer();
    const api = new AuthorizedApi(transport, {
      accessToken: "expired",
      refreshToken: "replayed",
    });

    await expect(
      api.request({ method: "GET", path: "/api/org" }),
    ).rejects.toBeInstanceOf(ApiError);
  });
});
