import { beforeEach, describe, expect, it } from "vitest";

import {
  CLIPBOARD_ALARM,
  ClipboardGuard,
} from "../src/background/ClipboardGuard.js";
import type { ClipboardAccess } from "../src/background/ClipboardGuard.js";
import { installChromeMock } from "./chromeMock.js";
import type { FakeBrowser } from "./chromeMock.js";

describe("clipboard guard", () => {
  let browser: FakeBrowser;
  let clipboard: string;
  let released: number;
  let guard: ClipboardGuard;

  beforeEach(() => {
    browser = installChromeMock();
    clipboard = "";
    released = 0;

    const access: ClipboardAccess = {
      read: () => Promise.resolve(clipboard),
      clear: () => {
        clipboard = "";

        return Promise.resolve();
      },
      release: () => {
        released += 1;

        return Promise.resolve();
      },
    };

    guard = new ClipboardGuard(() => Promise.resolve(access));
  });

  it("clears a copied secret after the delay, keeping only its hash meanwhile", async () => {
    clipboard = "db-secret-123";
    await guard.copied(clipboard);

    const scheduled = browser.alarms.get(CLIPBOARD_ALARM)?.when ?? 0;

    expect(scheduled - Date.now()).toBeGreaterThan(29_000);
    expect([...browser.session.values()]).not.toContain("db-secret-123");
    expect(await guard.clearIfUnchanged()).toBe(true);
    expect(clipboard).toBe("");
    expect(released).toBe(1);
    expect(browser.alarms.has(CLIPBOARD_ALARM)).toBe(false);
  });

  it("leaves the clipboard alone when the user copied something else since", async () => {
    await guard.copied("db-secret-123");
    clipboard = "meeting notes";

    expect(await guard.clearIfUnchanged()).toBe(false);
    expect(clipboard).toBe("meeting notes");
  });

  it("does nothing when nothing was copied", async () => {
    clipboard = "unrelated";

    expect(await guard.clearIfUnchanged()).toBe(false);
    expect(clipboard).toBe("unrelated");
    expect(released).toBe(0);
  });
});
