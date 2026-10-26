import { z } from "zod";

import { ApiError } from "./transport.js";
import type { Transport } from "./transport.js";

/**
 * ### SsoChallenge
 *
 * What the user must do: open `path` (relative to the server URL) in a browser and sign in with
 * the organisation's identity provider before `expiresAt`.
 */
export interface SsoChallenge {
  /**
   * ### path
   *
   * Server path that starts the provider sign-in, e.g. `/api/auth/sso/start?ticket=…`.
   */
  readonly path: string;

  /**
   * ### expiresAt
   *
   * When the check expires, as an ISO 8601 timestamp.
   */
  readonly expiresAt: string;
}

/**
 * ### SsoHandler
 *
 * How a client takes part in an SSO check: it shows or opens the challenge, and the SDK waits
 * for the server to report the outcome.
 */
export interface SsoHandler {
  /**
   * ### onChallenge
   *
   * Called once with the challenge; open it in a browser or show it to the user.
   */
  onChallenge(challenge: SsoChallenge): void | Promise<void>;

  /**
   * ### signal
   *
   * Aborts the wait, e.g. when the user cancels.
   */
  readonly signal?: AbortSignal;

  /**
   * ### pollIntervalMs
   *
   * Delay between checks.
   *
   * @defaultValue `1500`
   */
  readonly pollIntervalMs?: number;
}

/**
 * ### SsoRequiredError
 *
 * The organisation requires SSO, but the caller gave no {@link SsoHandler}.
 */
export class SsoRequiredError extends Error {
  override readonly name = "SsoRequiredError";
}

/**
 * ### ssoTicketSchema
 *
 * A ticket returned by login (when SSO is required) or by `/api/auth/sso/link`.
 */
export const ssoTicketSchema = z.object({
  ssoRequired: z.literal(true),
  ticketId: z.string(),
  ticketSecret: z.string(),
  url: z.string().startsWith("/api/auth/sso/start?"),
  expiresAt: z.string(),
});

/**
 * ### delay
 *
 * Waits, or rejects when the signal aborts.
 *
 * @param ms Milliseconds to wait
 * @param signal Abort signal
 */
async function delay(
  ms: number,
  signal: AbortSignal | undefined,
): Promise<void> {
  signal?.throwIfAborted();

  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(
        signal?.reason instanceof Error
          ? signal.reason
          : new Error("Cancelled while waiting for the identity provider"),
      );
    };

    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * ### completeSso
 *
 * Hands the challenge to the handler, then polls the server until the provider check finished.
 * Throws {@link ApiError} with `sso_failed` or `sso_expired` when it did not succeed.
 *
 * @param transport Transport to the server
 * @param ticket Ticket from the server
 * @param handler Client's SSO handler
 * @returns The server's final response body (a login response, or `{ status: "linked" }`)
 */
export async function completeSso(
  transport: Transport,
  ticket: z.infer<typeof ssoTicketSchema>,
  handler: SsoHandler,
): Promise<unknown> {
  await handler.onChallenge({ path: ticket.url, expiresAt: ticket.expiresAt });

  for (;;) {
    const response = await transport({
      method: "POST",
      path: "/api/auth/sso/finish",
      body: { ticketId: ticket.ticketId, ticketSecret: ticket.ticketSecret },
    });

    if (response.status !== 202) {
      if (response.status < 200 || response.status >= 300) {
        throw new ApiError(response.status, response.body);
      }

      return response.body;
    }

    await delay(handler.pollIntervalMs ?? 1500, handler.signal);
  }
}

/**
 * ### resolveSso
 *
 * Passes a login-like response through, or completes the SSO check it asks for.
 *
 * @param transport Transport to the server
 * @param body Response body that may be an SSO ticket
 * @param handler Client's SSO handler, if it supports SSO
 * @returns The final response body
 */
export async function resolveSso(
  transport: Transport,
  body: unknown,
  handler: SsoHandler | undefined,
): Promise<unknown> {
  const ticket = ssoTicketSchema.safeParse(body);

  if (!ticket.success) {
    return body;
  }

  if (handler === undefined) {
    throw new SsoRequiredError(
      "Your organisation requires signing in with its identity provider",
    );
  }

  return completeSso(transport, ticket.data, handler);
}
