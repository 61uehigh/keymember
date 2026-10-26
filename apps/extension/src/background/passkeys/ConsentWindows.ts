import type {
  PasskeyContentRequest,
  PasskeyDecision,
} from "../../shared/messages.js";

/**
 * ### DEFAULT_TIMEOUT_MS
 *
 * How long a consent window waits when the page sets no timeout.
 */
const DEFAULT_TIMEOUT_MS = 5 * 60_000;

/**
 * ### ConsentRequest
 *
 * A passkey request waiting for the user's choice in a consent window.
 */
export interface ConsentRequest {
  readonly request: PasskeyContentRequest;
  readonly origin: string;
  readonly rpId: string;
  readonly tabId: number | undefined;
  readonly unlocksAtStart: number;
}

/**
 * ### OpenRequest
 *
 * A waiting request with how to answer it and the window showing it.
 */
interface OpenRequest extends ConsentRequest {
  readonly resolve: (decision: PasskeyDecision) => void;
  windowId?: number;
}

/**
 * ### ConsentWindows
 *
 * The extension windows that ask the user about passkey requests: opening one per request,
 * collecting the choice, and treating a closed window or a timeout as a cancel.
 */
export class ConsentWindows {
  readonly #open = new Map<string, OpenRequest>();

  /**
   * ### hasOpenFor
   *
   * Whether a tab already has a consent window open.
   *
   * @param tabId Tab
   * @returns Whether one is open
   */
  hasOpenFor(tabId: number): boolean {
    return [...this.#open.values()].some((open) => open.tabId === tabId);
  }

  /**
   * ### waiting
   *
   * A request still waiting for its window's answer.
   *
   * @param id Request id from the window URL
   * @returns The request, or `undefined` when it is gone
   */
  waiting(id: string): ConsentRequest | undefined {
    return this.#open.get(id);
  }

  /**
   * ### ask
   *
   * Opens the consent window and waits for a choice, the window closing, or the timeout.
   *
   * @param request The request to ask about
   * @returns The user's decision
   */
  async ask(request: ConsentRequest): Promise<PasskeyDecision> {
    const id = crypto.randomUUID();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const decision = new Promise<PasskeyDecision>((resolve) => {
      this.#open.set(id, { ...request, resolve });
      timer = setTimeout(() => {
        resolve({ action: "cancel" });
      }, request.request.options.timeout ?? DEFAULT_TIMEOUT_MS);
    });
    const created = await chrome.windows.create({
      url: chrome.runtime.getURL(`passkey.html#${id}`),
      type: "popup",
      width: 400,
      height: 560,
      focused: true,
    });
    const open = this.#open.get(id);

    if (open !== undefined && created?.id !== undefined) {
      open.windowId = created.id;
    }

    try {
      return await decision;
    } finally {
      clearTimeout(timer);
      this.#open.delete(id);

      if (created?.id !== undefined) {
        // The user may have closed the window already; then there is nothing left to remove
        await chrome.windows.remove(created.id).catch(() => undefined);
      }
    }
  }

  /**
   * ### decide
   *
   * Records the user's choice from a consent window.
   *
   * @param id Request id
   * @param decision The choice
   */
  decide(id: string, decision: PasskeyDecision): void {
    this.#open.get(id)?.resolve(decision);
  }

  /**
   * ### windowClosed
   *
   * Treats closing a consent window as cancelling its request.
   *
   * @param windowId Closed window
   */
  windowClosed(windowId: number): void {
    for (const open of this.#open.values()) {
      if (open.windowId === windowId) {
        open.resolve({ action: "cancel" });
      }
    }
  }
}
