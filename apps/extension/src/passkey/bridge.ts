/**
 * Isolated-world relay between the page script's WebAuthn interception and the background.
 * Loaded at document start in the top frame only, so a page calling `navigator.credentials`
 * right away is still answered.
 */

import { isRecord } from "../shared/records.js";

// The background takes the origin from the browser, never from this message
if (window === window.top) {
  // Autofill requests parked in the background, by request id, until the user picks a passkey
  const parked = new Set<string>();
  const reply = (id: string, outcome: unknown): void => {
    const body =
      typeof outcome === "object" && outcome !== null && "outcome" in outcome
        ? outcome
        : { outcome: "fallback" };

    window.postMessage(
      { ...body, source: "keymember-content", id },
      window.location.origin,
    );
  };

  chrome.runtime.onMessage.addListener((message: unknown, sender) => {
    const data = isRecord(message) ? message : undefined;

    // Only the extension's own background delivers results, and only for requests parked here
    if (
      sender.id !== chrome.runtime.id ||
      sender.tab !== undefined ||
      data?.type !== "passkey-conditional-result" ||
      typeof data.requestId !== "string" ||
      !parked.delete(data.requestId)
    ) {
      return false;
    }

    reply(data.requestId, data.reply);

    return false;
  });

  window.addEventListener("message", (event: MessageEvent<unknown>) => {
    const data = isRecord(event.data) ? event.data : undefined;

    if (
      event.source !== window ||
      data?.source !== "keymember-page" ||
      typeof data.id !== "string"
    ) {
      return;
    }

    const id = data.id;

    if (data.kind === "cancel") {
      if (parked.delete(id)) {
        void chrome.runtime
          .sendMessage({ type: "passkey-conditional-cancel", requestId: id })
          // A background that is gone has nothing waiting to cancel
          .catch(() => undefined);
      }

      return;
    }

    if (
      data.kind !== "create" &&
      data.kind !== "get" &&
      data.kind !== "get-conditional"
    ) {
      return;
    }

    void (async () => {
      let response: unknown;

      try {
        response = await chrome.runtime.sendMessage(
          data.kind === "get-conditional"
            ? {
                type: "passkey-conditional",
                requestId: id,
                options: data.options,
              }
            : {
                type: data.kind === "create" ? "passkey-create" : "passkey-get",
                options: data.options,
              },
        );
      } catch {
        // The extension went away mid-request; let the browser handle the ceremony itself
        response = undefined;
      }

      const outcome =
        typeof response === "object" &&
        response !== null &&
        "outcome" in response
          ? response.outcome
          : undefined;

      if (outcome === "registered") {
        parked.add(id);

        return;
      }

      reply(id, response);
    })();
  });
}
