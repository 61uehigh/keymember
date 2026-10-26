// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from "vitest";

import { parseContentCommand } from "../src/content/command.js";
import { applyFill } from "../src/content/fill.js";

const URL_NOW = "https://login.example.com/signin";

/**
 * ### field
 *
 * Looks up an input or fails the test.
 *
 * @param selector CSS selector
 * @returns The input
 */
function field(selector: string): HTMLInputElement {
  const element = document.querySelector<HTMLInputElement>(selector);

  if (element === null) {
    throw new Error(`Missing ${selector}`);
  }

  return element;
}

describe("applyFill", () => {
  afterEach(() => {
    document.body.innerHTML = "";
  });

  it("fills user name and password through the native setter with input events", () => {
    document.body.innerHTML = `<form><input id="u" name="username"><input id="p" type="password"></form>`;

    const seen: Array<string> = [];

    field("#u").addEventListener("input", (event) =>
      seen.push((event.target as HTMLInputElement).value),
    );

    const filled = applyFill(
      {
        type: "fill",
        expectedUrl: URL_NOW,
        username: "me@example.com",
        password: "pw",
      },
      field("#p"),
      URL_NOW,
    );

    expect(filled).toBe(2);
    expect(field("#u").value).toBe("me@example.com");
    expect(field("#p").value).toBe("pw");
    expect(seen).toEqual(["me@example.com"]);
  });

  it("refuses when the frame navigated after the background matched it", () => {
    document.body.innerHTML = `<form><input id="u" name="username"><input id="p" type="password"></form>`;

    expect(
      applyFill(
        { type: "fill", expectedUrl: URL_NOW, password: "pw" },
        field("#p"),
        "https://evil.example/phish",
      ),
    ).toBe(0);
    expect(field("#p").value).toBe("");
  });

  it("never fills a signup form or a hidden field", () => {
    document.body.innerHTML = `<form><input id="u" name="username"><input id="p1" type="password"><input id="p2" type="password"></form>`;

    expect(
      applyFill(
        { type: "fill", expectedUrl: URL_NOW, password: "pw" },
        field("#p1"),
        URL_NOW,
      ),
    ).toBe(0);

    document.body.innerHTML = `<form><input id="u" name="username" style="display:none"><input id="p" type="password"></form>`;

    expect(
      applyFill(
        { type: "fill", expectedUrl: URL_NOW, username: "me", password: "pw" },
        field("#p"),
        URL_NOW,
      ),
    ).toBe(1);
    expect(field("#u").value).toBe("");
  });

  it("writes only the code into a one-time-code field", () => {
    document.body.innerHTML = `<form><label for="c">인증번호</label><input id="c" maxlength="6"></form>`;

    const filled = applyFill(
      {
        type: "fill",
        expectedUrl: URL_NOW,
        kind: "otp",
        totp: "123456",
        password: "must-not-appear",
      },
      field("#c"),
      URL_NOW,
    );

    expect(filled).toBe(1);
    expect(field("#c").value).toBe("123456");
  });
});

describe("parseContentCommand", () => {
  it("accepts well-formed commands and rejects anything else", () => {
    expect(
      parseContentCommand({
        type: "fill",
        expectedUrl: URL_NOW,
        password: "x",
      }),
    ).toEqual({
      type: "fill",
      expectedUrl: URL_NOW,
      password: "x",
    });
    expect(parseContentCommand({ type: "close-menu" })).toEqual({
      type: "close-menu",
    });
    expect(parseContentCommand({ type: "fill" })).toBeUndefined();
    expect(
      parseContentCommand({ type: "fill", expectedUrl: URL_NOW, password: 1 }),
    ).toBeUndefined();
    expect(
      parseContentCommand({
        type: "fill",
        expectedUrl: URL_NOW,
        kind: "credit-card",
      }),
    ).toBeUndefined();
    expect(parseContentCommand("fill")).toBeUndefined();
  });
});
