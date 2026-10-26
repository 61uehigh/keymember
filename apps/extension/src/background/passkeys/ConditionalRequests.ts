import { z } from "zod";

import { sessionValue, setSessionValue } from "../storage.js";

/**
 * ### conditionalRequestSchema
 *
 * An autofill sign-in a page is waiting on, as kept in session storage.
 */
const conditionalRequestSchema = z.object({
  requestId: z.string(),
  origin: z.string(),
  rpId: z.string(),
  challenge: z.string(),
  allowCredentials: z.array(z.string()),
});

/**
 * ### ConditionalRequest
 *
 * An autofill sign-in (conditional mediation) a page is waiting on.
 */
export type ConditionalRequest = z.infer<typeof conditionalRequestSchema>;

/**
 * ### conditionalKey
 *
 * Session storage key of a tab's conditional request.
 *
 * @param tabId Tab
 * @returns The key
 */
function conditionalKey(tabId: number): string {
  return `conditional:${String(tabId)}`;
}

/**
 * ### ConditionalRequests
 *
 * The autofill sign-in each tab is waiting on, kept in session storage so it survives the
 * service worker being stopped. At most one per tab.
 */
export class ConditionalRequests {
  /**
   * ### get
   *
   * Reads a tab's waiting autofill sign-in.
   *
   * @param tabId Tab
   * @returns The request, or `undefined` when none is waiting or the stored value is unreadable
   */
  async get(tabId: number): Promise<ConditionalRequest | undefined> {
    const parsed = conditionalRequestSchema.safeParse(
      await sessionValue(conditionalKey(tabId)),
    );

    return parsed.success ? parsed.data : undefined;
  }

  /**
   * ### set
   *
   * Records a tab's waiting autofill sign-in, replacing any earlier one.
   *
   * @param tabId Tab
   * @param request The request
   */
  async set(tabId: number, request: ConditionalRequest): Promise<void> {
    await setSessionValue(conditionalKey(tabId), request);
  }

  /**
   * ### forget
   *
   * Drops a tab's waiting autofill sign-in.
   *
   * @param tabId Tab
   */
  async forget(tabId: number): Promise<void> {
    await setSessionValue(conditionalKey(tabId), undefined);
  }
}
