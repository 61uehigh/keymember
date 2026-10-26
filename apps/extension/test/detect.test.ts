// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from "vitest";

import { findLoginFields, focusedKind } from "../src/content/detect.js";
import { LOGIN_FIXTURES } from "./fixtures/loginPages.js";

/**
 * ### input
 *
 * Looks up an input in the current document or fails the test.
 *
 * @param selector CSS selector
 * @returns The input
 */
function input(selector: string): HTMLInputElement {
  const element = document.querySelector<HTMLInputElement>(selector);

  if (element === null) {
    throw new Error(`Fixture has no ${selector}`);
  }

  return element;
}

describe("login field detection (regression set)", () => {
  afterEach(() => {
    document.body.innerHTML = "";
  });

  for (const fixture of LOGIN_FIXTURES) {
    it(fixture.name, () => {
      document.body.innerHTML = fixture.html;

      const focused = input(fixture.focus);
      const fields = findLoginFields(focused);

      expect(focusedKind(focused)).toBe(fixture.expected.kind);
      expect(fields.isSignup).toBe(fixture.expected.isSignup);
      expect(fields.username?.id).toBe(fixture.expected.username?.slice(1));
      expect(fields.password?.id).toBe(fixture.expected.password?.slice(1));

      if (fixture.expected.otp !== undefined) {
        expect(fields.otp?.id).toBe(fixture.expected.otp.slice(1));
      }
    });
  }

  it("finds fields inside an open shadow root", () => {
    const host = document.createElement("login-widget");

    document.body.append(host);

    const shadow = host.attachShadow({ mode: "open" });

    shadow.innerHTML = `<form><input id="sid" autocomplete="username"><input id="spw" type="password"></form>`;

    const password = shadow.querySelector<HTMLInputElement>("#spw");

    expect(password).not.toBeNull();

    if (password !== null) {
      expect(findLoginFields(password).username?.id).toBe("sid");
      expect(focusedKind(password)).toBe("password");
    }
  });

  it("ignores fields hidden by an ancestor", () => {
    document.body.innerHTML = `<div style="visibility:hidden"><form><input id="u" name="user"><input id="p" type="password"></form></div>`;

    expect(focusedKind(input("#p"))).toBeUndefined();
  });
});
