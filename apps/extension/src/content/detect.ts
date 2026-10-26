import type { FieldKind } from "../shared/messages.js";

const USERNAME_HINTS =
  /(user|login|account|e-?mail|identifier|\bid\b|^id$|userid|memberid|아이디|이메일|계정|사번|휴대폰|휴대전화|전화번호|사용자)/i;
const OTP_HINTS =
  /(otp|totp|2fa|mfa|one.?time|verification.?code|security.?code|auth.?code|인증\s?번호|인증\s?코드|보안\s?코드|일회용)/i;
const SEARCH_HINTS = /(search|query|keyword|검색|^q$)/i;
const TEXT_LIKE_TYPES = new Set(["text", "email", "tel", ""]);

/**
 * ### LoginFields
 *
 * The login-related inputs found around a focused field.
 */
export interface LoginFields {
  /**
   * ### username
   *
   * User name or email input, if any.
   */
  readonly username?: HTMLInputElement;

  /**
   * ### password
   *
   * Current-password input, if any. Absent on signup and change-password forms.
   */
  readonly password?: HTMLInputElement;

  /**
   * ### otp
   *
   * One-time code input, if any.
   */
  readonly otp?: HTMLInputElement;

  /**
   * ### isSignup
   *
   * Whether the form creates or changes a password (two or more password inputs, or
   * `autocomplete="new-password"`). Such forms are offered for saving, never filled.
   */
  readonly isSignup: boolean;
}

/**
 * ### isVisible
 *
 * Whether an input could be seen and typed into. Hidden decoy fields must never receive a
 * credential, because a page can read them silently.
 *
 * @param input Input to check
 * @returns Whether the input is visible and enabled
 */
export function isVisible(input: HTMLInputElement): boolean {
  if (
    input.type === "hidden" ||
    input.disabled ||
    input.readOnly ||
    input.hidden
  ) {
    return false;
  }

  const view = input.ownerDocument.defaultView;
  let element: Element | null = input;

  while (element !== null && view !== null) {
    const style = view.getComputedStyle(element);

    if (
      style.display === "none" ||
      style.visibility === "hidden" ||
      style.opacity === "0"
    ) {
      return false;
    }

    element = element.parentElement ?? shadowHostOf(element);
  }

  return true;
}

/**
 * ### shadowHostOf
 *
 * The host element of the shadow root an element lives in, so visibility checks can climb
 * out of shadow DOM.
 *
 * @param element Element inside a document or shadow root
 * @returns The shadow host, or `null` at the document level
 */
function shadowHostOf(element: Element): Element | null {
  const root = element.getRootNode();

  return "host" in root && root.host instanceof Element ? root.host : null;
}

/**
 * ### describe
 *
 * Collects the text a human would associate with an input: name, id, autocomplete,
 * placeholder, aria-label, and its label elements.
 *
 * @param input Input to describe
 * @returns Lower-case descriptive text
 */
export function describe(input: HTMLInputElement): string {
  // An input attached to a page has a Document or ShadowRoot as its root; the DOM types say Node
  const root = input.getRootNode() as Document | ShadowRoot;
  const labels: Array<string> = [];

  if (input.id !== "") {
    for (const label of root.querySelectorAll(
      `label[for="${CSS.escape(input.id)}"]`,
    )) {
      labels.push(label.textContent);
    }
  }

  const wrapping = input.closest("label");

  if (wrapping !== null) {
    labels.push(wrapping.textContent);
  }

  for (const id of (input.getAttribute("aria-labelledby") ?? "").split(/\s+/)) {
    const label = id === "" ? null : root.querySelector(`#${CSS.escape(id)}`);

    if (label !== null) {
      labels.push(label.textContent);
    }
  }

  return [
    input.name,
    input.id,
    input.autocomplete,
    input.placeholder,
    input.getAttribute("aria-label") ?? "",
    ...labels,
  ]
    .join(" ")
    .toLowerCase();
}

/**
 * ### autocompleteTokens
 *
 * The autocomplete tokens of an input, the strongest signal a site gives.
 *
 * @param input Input to read
 * @returns Lower-case tokens
 */
function autocompleteTokens(input: HTMLInputElement): Array<string> {
  return (input.getAttribute("autocomplete") ?? "")
    .toLowerCase()
    .split(/\s+/)
    .filter((token) => token.length > 0);
}

/**
 * ### isSearchField
 *
 * Whether an input is a search box, which must never receive a user name.
 *
 * @param input Input to check
 * @returns Whether it looks like search
 */
function isSearchField(input: HTMLInputElement): boolean {
  return (
    input.type === "search" ||
    input.getAttribute("role") === "searchbox" ||
    input.closest('[role="search"]') !== null ||
    SEARCH_HINTS.test(input.name) ||
    SEARCH_HINTS.test(input.id) ||
    SEARCH_HINTS.test(input.placeholder)
  );
}

/**
 * ### classifyField
 *
 * Decides what a single input is for, using autocomplete tokens first and descriptive text second.
 *
 * @param input Input to classify
 * @returns The field kind, or `undefined` for unrelated inputs
 */
export function classifyField(
  input: HTMLInputElement,
): FieldKind | "new-password" | undefined {
  if (!isVisible(input)) {
    return undefined;
  }

  const tokens = autocompleteTokens(input);

  if (tokens.includes("one-time-code")) {
    return "otp";
  }

  if (input.type === "password") {
    return tokens.includes("new-password") ? "new-password" : "password";
  }

  if (!TEXT_LIKE_TYPES.has(input.type) || isSearchField(input)) {
    return undefined;
  }

  if (tokens.includes("username") || tokens.includes("email")) {
    return "username";
  }

  const text = describe(input);

  if (OTP_HINTS.test(text)) {
    return "otp";
  }

  if (input.type === "email" || USERNAME_HINTS.test(text)) {
    return "username";
  }

  return undefined;
}

/**
 * ### deepInputs
 *
 * Every input under a root, descending into open shadow roots and, in Chrome content
 * scripts, closed ones too.
 *
 * @param root Root to search
 * @returns Inputs in document order
 */
export function deepInputs(
  root: Document | ShadowRoot | Element,
): Array<HTMLInputElement> {
  const found: Array<HTMLInputElement> = [];
  const openShadow = (element: Element): ShadowRoot | null => {
    // chrome.dom exists only in Chrome content scripts; it also reveals closed shadow roots
    const api =
      typeof chrome === "undefined"
        ? undefined
        : // Chrome only: Firefox has no chrome.dom, which the types do not express
          (chrome.dom as typeof chrome.dom | undefined);

    if (api !== undefined && element instanceof HTMLElement) {
      return api.openOrClosedShadowRoot(element);
    }

    return element.shadowRoot;
  };
  const walk = (node: Document | ShadowRoot | Element): void => {
    for (const element of node.querySelectorAll("*")) {
      if (element.localName === "input") {
        // localName "input" is only ever produced by HTMLInputElement
        found.push(element as HTMLInputElement);
      }

      const shadow = openShadow(element);

      if (shadow !== null) {
        walk(shadow);
      }
    }
  };

  walk(root);

  return found;
}

/**
 * ### scopeOf
 *
 * The container a login form lives in: its `<form>`, or for formless single-page apps the
 * whole document (or shadow root).
 *
 * @param input Field inside the form
 * @returns The scope to search for sibling fields
 */
export function scopeOf(
  input: HTMLInputElement,
): Element | Document | ShadowRoot {
  // An input attached to a page has a Document or ShadowRoot as its root; the DOM types say Node
  return input.form ?? (input.getRootNode() as Document | ShadowRoot);
}

/**
 * ### findLoginFields
 *
 * Finds the login fields that belong with a focused input. The user name is the nearest
 * text-like field before the password; a page with only a user name (step one of a
 * multi-step login) still yields that field.
 *
 * @param focused Input the user focused
 * @returns The related login fields
 */
export function findLoginFields(focused: HTMLInputElement): LoginFields {
  const inputs = deepInputs(scopeOf(focused)).filter((input) =>
    isVisible(input),
  );
  const kinds = new Map(
    inputs.map((input) => [input, classifyField(input)] as const),
  );
  const passwords = inputs.filter((input) => input.type === "password");
  const isSignup =
    passwords.length >= 2 || [...kinds.values()].includes("new-password");
  const password = isSignup
    ? undefined
    : passwords.find((input) => kinds.get(input) === "password");
  const otp = inputs.find((input) => kinds.get(input) === "otp");
  const anchorIndex =
    password === undefined ? inputs.length : inputs.indexOf(password);
  const username =
    inputs
      .slice(0, anchorIndex)
      .reverse()
      .find((input) => kinds.get(input) === "username") ??
    (password === undefined
      ? undefined
      : inputs
          .slice(0, anchorIndex)
          .reverse()
          .find((input) => isPlainTextBefore(input)));

  return {
    ...(username === undefined ? {} : { username }),
    ...(password === undefined ? {} : { password }),
    ...(otp === undefined ? {} : { otp }),
    isSignup,
  };
}

/**
 * ### isPlainTextBefore
 *
 * Fallback for sites that label nothing: a plain text input right before a password is
 * almost always the user name, unless it is a search box.
 *
 * @param input Candidate input
 * @returns Whether it can serve as the user name
 */
function isPlainTextBefore(input: HTMLInputElement): boolean {
  return (
    TEXT_LIKE_TYPES.has(input.type) &&
    input.type !== "tel" &&
    !isSearchField(input) &&
    classifyField(input) !== "otp"
  );
}

/**
 * ### focusedKind
 *
 * What the focused input is in its form, so the menu can offer the right values.
 *
 * @param focused Input the user focused
 * @returns The kind to offer, or `undefined` when the input is not a fillable login field
 */
export function focusedKind(focused: HTMLInputElement): FieldKind | undefined {
  const kind = classifyField(focused);

  if (kind === undefined || kind === "new-password") {
    return undefined;
  }

  const fields = findLoginFields(focused);

  if (fields.isSignup && kind !== "otp") {
    return undefined;
  }

  return kind === "username" && fields.username !== focused ? undefined : kind;
}
