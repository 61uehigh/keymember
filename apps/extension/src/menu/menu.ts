import type { ItemRow, MenuPasskey, MenuRequest } from "../shared/messages.js";

// Clicks in the first half second after the menu appears are ignored (clickjacking defence)
const ARM_DELAY_MS = 500;
const shownAt = performance.now();

/**
 * ### WithoutToken
 *
 * A menu request before the token is attached, kept as a discriminated union.
 */
type WithoutToken<T> = T extends unknown ? Omit<T, "token"> : never;

const token = location.hash.slice(1);
const root = document.getElementById("root");

/**
 * ### send
 *
 * Sends a token-authorised request to the background.
 *
 * @param request Request without the token
 * @returns The background's response
 */
async function send(request: WithoutToken<MenuRequest>): Promise<unknown> {
  return (await chrome.runtime.sendMessage({ ...request, token })) as unknown;
}

/**
 * ### message
 *
 * Replaces the menu with a single line of text.
 *
 * @param text Text to show
 */
function message(text: string): void {
  if (root !== null) {
    root.replaceChildren(
      Object.assign(document.createElement("p"), {
        className: "message",
        textContent: text,
      }),
    );
  }
}

/**
 * ### render
 *
 * Shows the matching items, with passkeys for a waiting autofill sign-in first. Rows hold only
 * titles and user names; passwords and private keys never reach this page.
 *
 * @param items Rows from the background
 * @param passkeys Passkeys that can answer the page's autofill sign-in
 */
function render(
  items: ReadonlyArray<ItemRow>,
  passkeys: ReadonlyArray<MenuPasskey>,
): void {
  if (root === null) {
    return;
  }

  const header = Object.assign(document.createElement("header"), {
    textContent: "keymember",
  });
  const list = document.createElement("ul");

  for (const passkey of passkeys) {
    const button = document.createElement("button");

    button.type = "button";
    button.className = "row";
    button.append(
      Object.assign(document.createElement("span"), {
        className: "title",
        textContent: `Sign in with passkey · ${passkey.userName}`,
      }),
      Object.assign(document.createElement("span"), {
        className: "sub",
        textContent: passkey.title,
      }),
    );
    button.addEventListener("click", (event) => {
      if (!event.isTrusted || performance.now() - shownAt < ARM_DELAY_MS) {
        return;
      }

      void send({
        type: "menu-passkey",
        itemId: passkey.itemId,
        credentialId: passkey.credentialId,
      }).then((response) => {
        const signed =
          typeof response === "object" &&
          response !== null &&
          "signed" in response &&
          response.signed === true;

        if (signed) {
          void send({ type: "menu-close" });
        } else {
          message("Couldn't sign in with the passkey. Try reloading the page.");
        }
      });
    });

    const entry = document.createElement("li");

    entry.append(button);
    list.append(entry);
  }

  for (const item of items) {
    const button = document.createElement("button");

    button.type = "button";
    button.className = "row";
    button.disabled = item.insecure;
    button.append(
      Object.assign(document.createElement("span"), {
        className: "title",
        textContent: item.title,
      }),
      Object.assign(document.createElement("span"), {
        className: "sub",
        textContent: item.insecure
          ? "Won't fill on an HTTP page"
          : (item.username ?? item.vaultName),
      }),
    );
    button.addEventListener("click", (event) => {
      // Synthetic clicks cannot reach an extension page from the website, but check anyway; and a
      // click right after the menu appeared was probably aimed at whatever the page showed there
      if (!event.isTrusted || performance.now() - shownAt < ARM_DELAY_MS) {
        return;
      }

      void send({ type: "menu-fill", itemId: item.id }).then((response) => {
        const filled =
          typeof response === "object" &&
          response !== null &&
          "filled" in response
            ? response.filled
            : 0;

        if (filled === 0) {
          message(
            "Couldn't fill. The page changed or the fields weren't found.",
          );
        }
      });
    });

    const entry = document.createElement("li");

    entry.append(button);
    list.append(entry);
  }

  root.replaceChildren(header, list);
  list.querySelector("button")?.focus();
}

document.addEventListener("keydown", (event) => {
  const buttons = [
    ...document.querySelectorAll<HTMLButtonElement>(
      "button.row:not(:disabled)",
    ),
  ];
  // indexOf only compares identity; any other focused element simply gives -1
  const index = buttons.indexOf(document.activeElement as HTMLButtonElement);

  if (event.key === "ArrowDown") {
    buttons[Math.min(index + 1, buttons.length - 1)]?.focus();
    event.preventDefault();
  } else if (event.key === "ArrowUp") {
    buttons[Math.max(index - 1, 0)]?.focus();
    event.preventDefault();
  } else if (event.key === "Escape") {
    void send({ type: "menu-close" });
  }
});

void send({ type: "menu-items" }).then((response) => {
  if (
    typeof response !== "object" ||
    response === null ||
    "error" in response
  ) {
    message("This menu has expired. Click the field again.");

    return;
  }

  // The background's own reply to menu-items
  const { locked, items, passkeys } = response as {
    locked: boolean;
    items: Array<ItemRow>;
    passkeys: Array<MenuPasskey>;
  };

  if (locked) {
    message(
      "keymember is locked. Click the keymember icon in the browser toolbar to unlock.",
    );
  } else if (items.length === 0 && passkeys.length === 0) {
    message("No items match this site.");
  } else {
    render(items, passkeys);
  }
});
