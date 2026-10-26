import type { PasskeyReply } from "../../shared/messages.js";

/**
 * ### errorReply
 *
 * A DOMException for the page to throw.
 *
 * @param name DOMException name
 * @param message Message for the page
 * @returns The reply
 */
export function errorReply(name: string, message: string): PasskeyReply {
  return { outcome: "error", name, message };
}
