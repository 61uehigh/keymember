import { describe, expect, it } from "vitest";

import { RateLimiter } from "../src/services/RateLimiter.js";

describe("RateLimiter", () => {
  it("blocks a key after its failures and forgets it after the window", () => {
    const limiter = new RateLimiter(2, 1000);

    limiter.recordFailure("a", 0);
    expect(limiter.isBlocked("a", 0)).toBe(false);
    limiter.recordFailure("a", 10);
    expect(limiter.isBlocked("a", 10)).toBe(true);
    expect(limiter.isBlocked("a", 1000)).toBe(false);
  });

  it("drops expired windows as new keys arrive", () => {
    const limiter = new RateLimiter(1, 1000);

    for (let index = 0; index < 50; index += 1) {
      limiter.recordFailure(`old-${String(index)}`, 0);
    }
    limiter.recordFailure("new", 2000);

    expect(limiter.size).toBe(1);
  });

  it("drops the oldest key when full instead of growing", () => {
    const limiter = new RateLimiter(1, 60_000, 3);

    for (const [index, key] of ["a", "b", "c", "d"].entries()) {
      limiter.recordFailure(key, index);
    }

    expect(limiter.size).toBe(3);
    expect(limiter.isBlocked("a", 10)).toBe(false);
    expect(limiter.isBlocked("d", 10)).toBe(true);
  });
});
