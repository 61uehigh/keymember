// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { clearCopiedSecret, copySecret } from "../src/lib/clipboard.js";

/**
 * ### fakeClipboard
 *
 * A clipboard whose reads can be refused, as browsers do without permission.
 *
 * @param readable Whether the page may read the clipboard
 * @returns The fake and its current content
 */
function fakeClipboard(readable: boolean): { content: { value: string } } {
  const content = { value: "" };

  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: {
      writeText: (text: string) => {
        content.value = text;

        return Promise.resolve();
      },
      readText: () =>
        readable
          ? Promise.resolve(content.value)
          : Promise.reject(new Error("permission denied")),
    },
  });

  return { content };
}

/**
 * ### settle
 *
 * Lets the clipboard promises started by a timer finish.
 */
async function settle(): Promise<void> {
  await vi.runAllTimersAsync();
}

describe("copySecret", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    clearCopiedSecret();
    vi.useRealTimers();
  });

  it("clears the copied secret after 30 seconds", async () => {
    const { content } = fakeClipboard(true);

    await copySecret("s3cret");
    expect(content.value).toBe("s3cret");

    await vi.advanceTimersByTimeAsync(29_000);
    expect(content.value).toBe("s3cret");

    await vi.advanceTimersByTimeAsync(1_000);
    await settle();
    expect(content.value).toBe("");
  });

  it("leaves something the user copied afterwards", async () => {
    const { content } = fakeClipboard(true);

    await copySecret("s3cret");
    content.value = "copied later";
    await vi.advanceTimersByTimeAsync(30_000);
    await settle();

    expect(content.value).toBe("copied later");
  });

  it("clears anyway when the page may not read the clipboard", async () => {
    const { content } = fakeClipboard(false);

    await copySecret("s3cret");
    await vi.advanceTimersByTimeAsync(30_000);
    await settle();

    expect(content.value).toBe("");
  });

  it("clears at once when locking, and only the latest copy is pending", async () => {
    const { content } = fakeClipboard(true);

    await copySecret("first");
    await copySecret("second");
    clearCopiedSecret();
    await settle();

    expect(content.value).toBe("");

    content.value = "unrelated";
    clearCopiedSecret();
    await settle();
    expect(content.value).toBe("unrelated");
  });
});
