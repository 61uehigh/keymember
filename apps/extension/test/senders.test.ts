import { describe, expect, it } from "vitest";

import {
  classifySender,
  hasRealOrigin,
  routeMessage,
} from "../src/background/senders.js";
import type { MessageSender } from "../src/background/senders.js";

const ID = "ext-id";
const tab = { id: 7 } as const;

/**
 * ### sender
 *
 * A message sender as the browser would report it.
 *
 * @param fields Fields to set
 * @returns The sender
 */
function sender(fields: Partial<MessageSender>): MessageSender {
  return { id: ID, ...fields };
}

describe("classifySender", () => {
  it("recognises extension pages in Chrome and Firefox", () => {
    for (const base of [
      "chrome-extension://abcdef",
      "moz-extension://6a2f0c1e-1111-4222-8333-944455556666",
    ]) {
      expect(classifySender(sender({ url: `${base}/popup.html` }), ID)).toBe(
        "popup",
      );
      expect(
        classifySender(sender({ url: `${base}/menu.html#token`, tab }), ID),
      ).toBe("menu");
      expect(
        classifySender(sender({ url: `${base}/passkey.html?id=1` }), ID),
      ).toBe("passkey-window");
      expect(
        classifySender(sender({ url: `${base}/offscreen.html` }), ID),
      ).toBe("unknown");
    }
  });

  it("recognises content scripts only in a web page frame of a tab", () => {
    expect(
      classifySender(
        sender({ url: "https://example.com/login", tab, frameId: 0 }),
        ID,
      ),
    ).toBe("content");
    expect(
      classifySender(sender({ url: "https://example.com/login" }), ID),
    ).toBe("unknown");
    expect(
      classifySender(
        sender({ url: "file:///etc/passwd", tab, frameId: 0 }),
        ID,
      ),
    ).toBe("unknown");
  });

  it("refuses senders from another extension or with a page path that only looks right", () => {
    expect(
      classifySender(
        { id: "other", url: "chrome-extension://other/popup.html" },
        ID,
      ),
    ).toBe("unknown");
    // A web page cannot claim an extension page by its path or query
    expect(
      classifySender(
        sender({
          url: "https://evil.example/popup.html?chrome-extension://x/popup.html",
          tab,
          frameId: 0,
        }),
        ID,
      ),
    ).toBe("content");
    expect(classifySender(sender({ url: "javascript:popup.html" }), ID)).toBe(
      "unknown",
    );
  });
});

describe("hasRealOrigin", () => {
  it("rejects sandboxed frames", () => {
    expect(hasRealOrigin(sender({ origin: "null" }))).toBe(false);
    expect(hasRealOrigin(sender({ origin: "https://example.com" }))).toBe(true);
    expect(hasRealOrigin(sender({ url: "https://example.com/x" }))).toBe(true);
  });
});

describe("routeMessage", () => {
  const popup = sender({ url: "moz-extension://uuid/popup.html" });
  const passkeyWindow = sender({
    url: "chrome-extension://abc/passkey.html",
  });
  const page = sender({
    url: "https://example.com/login",
    tab,
    frameId: 0,
    origin: "https://example.com",
  });

  it("lets the popup make popup requests, including from Firefox", () => {
    expect(routeMessage({ type: "state" }, popup, ID)).toEqual({
      to: "popup",
      request: { type: "state" },
    });
  });

  it("lets the passkey window only read the lock state and unlock among popup requests", () => {
    expect(routeMessage({ type: "state" }, passkeyWindow, ID)?.to).toBe(
      "popup",
    );
    expect(routeMessage({ type: "lock" }, passkeyWindow, ID)).toBeUndefined();
    expect(
      routeMessage(
        { type: "reveal", itemId: "x", field: "password" },
        passkeyWindow,
        ID,
      ),
    ).toBeUndefined();
  });

  it("never lets a web page make popup requests", () => {
    expect(routeMessage({ type: "state" }, page, ID)).toBeUndefined();
    expect(
      routeMessage(
        { type: "reveal", itemId: "x", field: "password" },
        page,
        ID,
      ),
    ).toBeUndefined();
  });

  it("takes a content script's frame from the sender, never the message", () => {
    const routed = routeMessage(
      {
        type: "menu-open",
        kind: "password",
        url: "https://bank.example",
        tabId: 99,
      },
      page,
      ID,
    );

    expect(routed).toMatchObject({
      to: "content",
      target: { tabId: 7, frameId: 0, url: "https://example.com/login" },
    });
  });

  it("drops messages from unknown senders", () => {
    expect(
      routeMessage({ type: "state" }, { id: "other", url: "x" }, ID),
    ).toBeUndefined();
  });
});
