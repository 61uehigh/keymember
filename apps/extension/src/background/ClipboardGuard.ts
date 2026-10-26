import { toBase64Url, utf8Encode } from "@keymember/core";
import { sha256 } from "@noble/hashes/sha2.js";

import { clearClipboard, readClipboard } from "../offscreen/clipboardDom.js";
import { sessionValue, setSessionValue } from "./storage.js";
import { isRecord } from "../shared/records.js";

/**
 * ### CLIPBOARD_CLEAR_DELAY_MS
 *
 * How long a copied secret stays on the clipboard: 30 seconds.
 */
export const CLIPBOARD_CLEAR_DELAY_MS = 30_000;

/**
 * ### CLIPBOARD_ALARM
 *
 * Alarm that wakes the background to clear the clipboard.
 */
export const CLIPBOARD_ALARM = "clear-clipboard";

/**
 * ### ClipboardAccess
 *
 * Reading and clearing the clipboard from a context that can.
 */
export interface ClipboardAccess {
  /**
   * ### read
   *
   * Reads the clipboard's text.
   */
  read(): Promise<string>;

  /**
   * ### clear
   *
   * Empties the clipboard.
   */
  clear(): Promise<void>;

  /**
   * ### release
   *
   * Frees whatever was opened to get access.
   */
  release(): Promise<void>;
}

/**
 * ### fingerprint
 *
 * What is remembered about a copied value: its hash, never the value.
 *
 * @param text Copied text
 * @returns base64url SHA-256
 */
function fingerprint(text: string): string {
  return toBase64Url(sha256(utf8Encode(text)));
}

/**
 * ### platformClipboard
 *
 * Clipboard access for this browser: an offscreen document in Chrome (the service worker has no
 * DOM), the background page itself in Firefox.
 *
 * @returns Clipboard access
 */
export async function platformClipboard(): Promise<ClipboardAccess> {
  if (
    process.env.KEYMEMBER_BROWSER === "firefox" ||
    typeof chrome.offscreen === "undefined"
  ) {
    return {
      read: () => Promise.resolve(readClipboard()),
      clear: () => {
        clearClipboard();

        return Promise.resolve();
      },
      release: () => Promise.resolve(),
    };
  }

  if (!(await chrome.offscreen.hasDocument())) {
    await chrome.offscreen.createDocument({
      url: "offscreen.html",
      reasons: [chrome.offscreen.Reason.CLIPBOARD],
      justification: "Clear copied passwords from the clipboard",
    });
  }

  const ask = async (type: string): Promise<unknown> =>
    chrome.runtime.sendMessage({ target: "offscreen", type });

  return {
    read: async () => {
      const response = await ask("clipboard-read");

      return isRecord(response) && typeof response.text === "string"
        ? response.text
        : "";
    },
    clear: async () => {
      await ask("clipboard-clear");
    },
    release: () => chrome.offscreen.closeDocument(),
  };
}

/**
 * ### ClipboardGuard
 *
 * Clears a secret copied from the popup after {@link CLIPBOARD_CLEAR_DELAY_MS}, but only if the
 * clipboard still holds it: anything the user copied since is left alone. Only a hash of the
 * copied value is kept, in memory-only session storage, and an alarm survives the service
 * worker being stopped.
 */
export class ClipboardGuard {
  readonly #access: () => Promise<ClipboardAccess>;

  /**
   * ### constructor
   *
   * @param access Opens clipboard access when needed
   */
  constructor(access: () => Promise<ClipboardAccess> = platformClipboard) {
    this.#access = access;
  }

  /**
   * ### copied
   *
   * Records that a secret was just copied and schedules clearing it.
   *
   * @param text The copied text
   */
  async copied(text: string): Promise<void> {
    await setSessionValue("clipboard", fingerprint(text));
    await chrome.alarms.create(CLIPBOARD_ALARM, {
      when: Date.now() + CLIPBOARD_CLEAR_DELAY_MS,
    });
  }

  /**
   * ### clearIfUnchanged
   *
   * Empties the clipboard if it still holds the copied secret. Called by the alarm and on lock.
   *
   * @returns Whether the clipboard was cleared
   */
  async clearIfUnchanged(): Promise<boolean> {
    const expected = await sessionValue("clipboard");

    if (typeof expected !== "string") {
      return false;
    }

    await setSessionValue("clipboard", undefined);
    await chrome.alarms.clear(CLIPBOARD_ALARM);

    const access = await this.#access();

    try {
      if (fingerprint(await access.read()) !== expected) {
        return false;
      }

      await access.clear();

      return true;
    } finally {
      await access.release();
    }
  }
}
