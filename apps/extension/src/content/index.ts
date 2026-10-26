import type { ContentRequest, FieldKind } from "../shared/messages.js";
import { findLoginFields, focusedKind } from "./detect.js";
import { parseContentCommand } from "./command.js";
import { applyFill } from "./fill.js";
import { InlineUi } from "./inline.js";

/**
 * ### send
 *
 * Sends a request to the background. A missing receiver (extension reloading) is treated as
 * "nothing to do" rather than an error, because content scripts outlive extension reloads.
 *
 * @param request Request to send
 * @returns The response, or `undefined` when the background did not answer
 */
async function send(request: ContentRequest): Promise<unknown> {
  try {
    return (await chrome.runtime.sendMessage(request)) as unknown;
  } catch {
    // The extension was reloaded or updated; this orphaned script just goes quiet
    return undefined;
  }
}

let focused: HTMLInputElement | undefined;
let focusedFieldKind: FieldKind | undefined;

const ui = new InlineUi(async () => {
  if (focusedFieldKind === undefined) {
    return undefined;
  }

  const response = await send({ type: "menu-open", kind: focusedFieldKind });

  return typeof response === "object" &&
    response !== null &&
    "token" in response &&
    typeof response.token === "string"
    ? response.token
    : undefined;
});

/**
 * ### targetInput
 *
 * The real input behind an event, looking through shadow DOM retargeting.
 *
 * @param event Focus or key event
 * @returns The input, if the event came from one
 */
function targetInput(event: Event): HTMLInputElement | undefined {
  const [target] = event.composedPath();

  return target instanceof HTMLInputElement ? target : undefined;
}

document.addEventListener(
  "focusin",
  (event) => {
    const input = targetInput(event);
    const kind = input === undefined ? undefined : focusedKind(input);

    if (input === undefined || kind === undefined) {
      if (!ui.contains(event.target)) {
        ui.hide();
      }

      return;
    }

    focused = input;
    focusedFieldKind = kind;
    ui.show(input);
  },
  true,
);

document.addEventListener(
  "keydown",
  (event) => {
    if (event.key === "Escape") {
      ui.closeMenu();
    }

    // Enter inside a password field submits many SPA logins without a submit event
    if (event.key === "Enter" && event.isTrusted) {
      const input = targetInput(event);

      if (input?.type === "password") {
        reportCredentials(input);
      }
    }
  },
  true,
);

document.addEventListener(
  "pointerdown",
  (event) => {
    if (!ui.contains(event.target) && event.composedPath()[0] !== focused) {
      ui.closeMenu();
    }
  },
  true,
);

/**
 * ### reportCredentials
 *
 * Offers the credentials just submitted to the background as a save or update candidate.
 *
 * @param anchor Any input of the submitted form
 */
function reportCredentials(anchor: HTMLInputElement): void {
  const fields = findLoginFields(anchor);
  const passwordInput =
    fields.password ??
    [
      ...(anchor.form ?? document).querySelectorAll<HTMLInputElement>(
        'input[type="password"]',
      ),
    ].find((input) => input.value.length > 0);
  const password = passwordInput?.value ?? "";

  if (password.length === 0) {
    return;
  }

  const username = fields.username?.value;

  void send({
    type: "save-candidate",
    password,
    ...(username === undefined || username === "" ? {} : { username }),
  });
}

// Last real keystroke or click; a script submitting a form on its own is not the user logging in
let lastUserGesture = Number.NEGATIVE_INFINITY;

for (const type of ["keydown", "pointerdown"] as const) {
  document.addEventListener(
    type,
    (event) => {
      if (event.isTrusted) {
        lastUserGesture = performance.now();
      }
    },
    true,
  );
}

document.addEventListener(
  "submit",
  (event) => {
    const form = event.target;

    if (
      form instanceof HTMLFormElement &&
      performance.now() - lastUserGesture < 2000
    ) {
      const anchor = form.querySelector<HTMLInputElement>(
        'input[type="password"]',
      );

      if (anchor !== null) {
        reportCredentials(anchor);
      }
    }
  },
  true,
);

document.addEventListener(
  "click",
  (event) => {
    // Many login pages submit through a script-driven button instead of a form submit
    if (!event.isTrusted || focused === undefined) {
      return;
    }

    // Click targets are elements (or null); the DOM types only promise an EventTarget
    const button = (event.target as Element | null)?.closest(
      'button, [role="button"], input[type="submit"]',
    );

    if (
      button !== null &&
      button !== undefined &&
      /로그인|log\s?in|sign\s?in|확인|continue|다음|next/i.test(
        button.textContent,
      )
    ) {
      reportCredentials(focused);
    }
  },
  true,
);

chrome.runtime.onMessage.addListener((message: unknown, sender, respond) => {
  // Only the extension itself may command a content script
  if (sender.id !== chrome.runtime.id || sender.tab !== undefined) {
    return false;
  }

  const command = parseContentCommand(message);

  if (command === undefined) {
    return false;
  }

  if (command.type === "close-menu") {
    ui.closeMenu();
    respond({ filled: 0 });

    return false;
  }

  const filled = applyFill(command, focused, location.href);

  ui.closeMenu();
  respond({ filled });

  return false;
});
