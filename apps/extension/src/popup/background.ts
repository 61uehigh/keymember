import type { PopupRequest } from "../shared/messages.js";

/**
 * ### call
 *
 * Sends a request to the background and unwraps an `{ error }` response into a thrown error.
 *
 * @param request Popup request
 * @returns The background's response
 */
export async function call<T>(request: PopupRequest): Promise<T> {
  const response = (await chrome.runtime.sendMessage(request)) as unknown;

  if (
    typeof response === "object" &&
    response !== null &&
    "error" in response &&
    typeof response.error === "string"
  ) {
    throw new Error(response.error);
  }

  // The background answers each request type with a fixed shape
  return response as T;
}
