import { clearClipboard, readClipboard } from "./clipboardDom.js";
import { isRecord } from "../shared/records.js";

/**
 * Offscreen document (Chrome): the service worker has no DOM, so it asks this page to read or
 * clear the clipboard. Only messages from this extension's own background are answered.
 */
chrome.runtime.onMessage.addListener((message: unknown, sender, respond) => {
  const request = isRecord(message) ? message : undefined;

  if (
    sender.id !== chrome.runtime.id ||
    sender.tab !== undefined ||
    request?.target !== "offscreen"
  ) {
    return false;
  }

  if (request.type === "clipboard-read") {
    respond({ text: readClipboard() });
  } else if (request.type === "clipboard-clear") {
    clearClipboard();
    respond({ cleared: true });
  }

  return false;
});
