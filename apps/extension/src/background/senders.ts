import {
  contentRequestSchema,
  menuRequestSchema,
  passkeyConditionalRequestSchema,
  passkeyContentRequestSchema,
  passkeyWindowRequestSchema,
  popupRequestSchema,
} from "../shared/messages.js";
import type {
  ContentRequest,
  MenuRequest,
  PasskeyConditionalRequest,
  PasskeyContentRequest,
  PasskeyWindowRequest,
  PopupRequest,
} from "../shared/messages.js";
import type { FillTarget } from "./Vault.js";

/**
 * ### SenderKind
 *
 * Who sent a message, decided from browser-supplied sender data only.
 */
export type SenderKind =
  "popup" | "passkey-window" | "menu" | "content" | "unknown";

/**
 * ### MessageSender
 *
 * The parts of `chrome.runtime.MessageSender` the rules below read, so tests can build one. The
 * browser fills them in; a page cannot forge them.
 */
export interface MessageSender {
  readonly id?: string | undefined;
  readonly url?: string | undefined;
  readonly origin?: string | undefined;
  readonly frameId?: number | undefined;
  readonly tab?: { readonly id?: number | undefined } | undefined;
}
/**
 * ### EXTENSION_PROTOCOLS
 *
 * URL schemes of extension pages: Chrome's and Firefox's.
 */
const EXTENSION_PROTOCOLS: ReadonlySet<string> = new Set([
  "chrome-extension:",
  "moz-extension:",
]);

/**
 * ### extensionPagePath
 *
 * The path of an extension page URL, or `undefined` for any other URL.
 *
 * @param url Sender URL
 * @returns The page path, such as `/popup.html`
 */
function extensionPagePath(url: string): string | undefined {
  try {
    const parsed = new URL(url);

    return EXTENSION_PROTOCOLS.has(parsed.protocol)
      ? parsed.pathname
      : undefined;
  } catch {
    // Not a URL at all; such a sender is not an extension page
    return undefined;
  }
}

/**
 * ### classifySender
 *
 * Identifies the sender. `sender.id` proves the message comes from this extension. Extension
 * pages are then told apart by path rather than host: web-accessible pages run under a dynamic
 * host in Chrome (`use_dynamic_url`) and Firefox gives every install its own host. Content
 * scripts must sit in a web page frame of a tab.
 *
 * @param sender Sender reported by the browser
 * @param extensionId This extension's id (`chrome.runtime.id`)
 * @returns The sender kind
 */
export function classifySender(
  sender: MessageSender,
  extensionId: string,
): SenderKind {
  if (sender.id !== extensionId) {
    return "unknown";
  }

  const url = sender.url ?? "";

  switch (extensionPagePath(url)) {
    case "/popup.html":
      return "popup";
    case "/menu.html":
      return "menu";
    case "/passkey.html":
      return "passkey-window";
    case undefined:
      break;
    default:
      return "unknown";
  }

  if (
    sender.tab?.id !== undefined &&
    sender.frameId !== undefined &&
    /^https?:\/\//.test(url)
  ) {
    return "content";
  }

  return "unknown";
}

/**
 * ### hasRealOrigin
 *
 * Whether a content script runs in a page with a real (not opaque, sandboxed) origin. Chrome
 * reports the origin directly; where a browser does not, the frame URL's origin is used, which
 * cannot tell sandboxed pages apart.
 *
 * @param sender Message sender
 * @returns Whether passkeys may be offered there
 */
export function hasRealOrigin(sender: MessageSender): boolean {
  const origin =
    sender.origin ??
    (sender.url === undefined ? undefined : new URL(sender.url).origin);

  return origin !== undefined && origin !== "null";
}

/**
 * ### RoutedMessage
 *
 * A message that a sender is allowed to send, parsed, with what the handler may rely on.
 */
export type RoutedMessage =
  | { readonly to: "popup"; readonly request: PopupRequest }
  | { readonly to: "passkey-window"; readonly request: PasskeyWindowRequest }
  | {
      readonly to: "menu";
      readonly request: MenuRequest;
      readonly tabId: number | undefined;
    }
  | {
      readonly to: "content";
      readonly request: ContentRequest;
      readonly target: FillTarget;
    }
  | {
      readonly to: "passkey";
      readonly request: PasskeyContentRequest;
      readonly url: string;
      readonly tabId: number;
      readonly allowed: boolean;
    }
  | {
      readonly to: "passkey-conditional";
      readonly request: PasskeyConditionalRequest;
      readonly url: string;
      readonly tabId: number;
      readonly allowed: boolean;
    };

/**
 * ### routeMessage
 *
 * Decides which request a sender may make: the popup any popup request; the passkey window its
 * own requests plus reading the lock state and unlocking; the inline menu menu requests; content
 * scripts content and passkey requests for their own frame, with passkeys only in a top frame
 * with a real origin. Anything else is dropped.
 *
 * @param message Message as received
 * @param sender Sender reported by the browser
 * @param extensionId This extension's id
 * @returns The routed request, or `undefined` to ignore the message
 */
export function routeMessage(
  message: unknown,
  sender: MessageSender,
  extensionId: string,
): RoutedMessage | undefined {
  switch (classifySender(sender, extensionId)) {
    case "popup": {
      const request = popupRequestSchema.safeParse(message);

      return request.success
        ? { to: "popup", request: request.data }
        : undefined;
    }
    case "passkey-window": {
      const windowRequest = passkeyWindowRequestSchema.safeParse(message);

      if (windowRequest.success) {
        return { to: "passkey-window", request: windowRequest.data };
      }

      const popupRequest = popupRequestSchema.safeParse(message);

      // The consent window may read the lock state and unlock, nothing else the popup can do
      return popupRequest.success &&
        (popupRequest.data.type === "state" ||
          popupRequest.data.type === "unlock")
        ? { to: "popup", request: popupRequest.data }
        : undefined;
    }
    case "menu": {
      const request = menuRequestSchema.safeParse(message);

      return request.success
        ? { to: "menu", request: request.data, tabId: sender.tab?.id }
        : undefined;
    }
    case "content":
      return routeContent(message, sender);
    case "unknown":
      return undefined;
  }
}

/**
 * ### routeContent
 *
 * Routes a content script's message. The frame URL always comes from the sender, never the
 * message.
 *
 * @param message Message as received
 * @param sender Content script sender
 * @returns The routed request, or `undefined` to ignore the message
 */
function routeContent(
  message: unknown,
  sender: MessageSender,
): RoutedMessage | undefined {
  const tabId = sender.tab?.id;
  const { frameId, url } = sender;

  if (tabId === undefined || frameId === undefined || url === undefined) {
    return undefined;
  }

  const request = contentRequestSchema.safeParse(message);

  if (request.success) {
    return {
      to: "content",
      request: request.data,
      target: { tabId, frameId, url },
    };
  }

  // WebAuthn is only offered to top-level pages with a real origin (not sandboxed ones);
  // frames would need permissions-policy checks
  const allowed = frameId === 0 && hasRealOrigin(sender);
  const passkeyRequest = passkeyContentRequestSchema.safeParse(message);

  if (passkeyRequest.success) {
    return { to: "passkey", request: passkeyRequest.data, url, tabId, allowed };
  }

  const conditional = passkeyConditionalRequestSchema.safeParse(message);

  return conditional.success
    ? {
        to: "passkey-conditional",
        request: conditional.data,
        url,
        tabId,
        allowed,
      }
    : undefined;
}
