/**
 * ### readClipboard
 *
 * Reads the clipboard's text in a page that has a DOM (the offscreen document in Chrome, the
 * background page in Firefox). Needs the `clipboardRead` permission.
 *
 * @returns The clipboard text, empty when it holds no text
 */
export function readClipboard(): string {
  const area = document.createElement("textarea");

  document.body.append(area);
  area.focus();
  // navigator.clipboard needs a focused page, which offscreen and background pages never are;
  // Chrome's offscreen-clipboard guidance uses execCommand for exactly this reason
  // eslint-disable-next-line @typescript-eslint/no-deprecated
  document.execCommand("paste");

  const text = area.value;

  area.remove();

  return text;
}

/**
 * ### clearClipboard
 *
 * Replaces the clipboard's content with an empty string. A copy command with nothing selected
 * does nothing, so the copy event is intercepted to put an empty text in.
 */
export function clearClipboard(): void {
  const onCopy = (event: ClipboardEvent): void => {
    event.clipboardData?.setData("text/plain", "");
    event.preventDefault();
  };

  document.addEventListener("copy", onCopy, { once: true });
  // Same reason as in readClipboard: there is no focused page to use navigator.clipboard from
  // eslint-disable-next-line @typescript-eslint/no-deprecated
  document.execCommand("copy");
  document.removeEventListener("copy", onCopy);
}
