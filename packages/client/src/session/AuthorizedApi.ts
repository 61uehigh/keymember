import { parseResponse, tokensSchema } from "../schemas.js";
import { ApiError, loginEnded, send } from "../transport.js";
import type { ApiRequest, Transport } from "../transport.js";

/**
 * ### TokenPair
 *
 * A login's access token and its single-use refresh token.
 */
export interface TokenPair {
  readonly accessToken: string;
  readonly refreshToken: string;
}

/**
 * ### AuthorizedRequest
 *
 * Sends a request as the logged-in user. What every part of a session talks to the server
 * through.
 */
export type AuthorizedRequest = (
  request: Omit<ApiRequest, "token">,
) => Promise<unknown>;

/**
 * ### AuthorizedApi
 *
 * The server as seen by one login: attaches the access token to every request and, on a 401,
 * swaps the refresh token for a new pair once and retries. Tells a listener about each new
 * pair, because an old refresh token is single-use and a stored snapshot must follow along.
 */
export class AuthorizedApi {
  /**
   * ### transport
   *
   * The transport underneath, for the few unauthenticated calls a session makes.
   */
  readonly transport: Transport;

  #tokens: TokenPair;
  #listener: (() => void) | undefined;
  #endedListeners = new Set<() => void>();

  /**
   * ### #refreshing
   *
   * The refresh in flight. A refresh token is single-use and the server treats a second use as
   * theft, so concurrent 401s all wait for this one instead of refreshing again.
   */
  #refreshing: Promise<void> | undefined;

  /**
   * ### #ended
   *
   * Whether the server ended this login: the refresh token was refused.
   */
  #ended = false;

  /**
   * ### constructor
   *
   * @param transport Transport to the server
   * @param tokens The login's initial token pair
   */
  constructor(transport: Transport, tokens: TokenPair) {
    this.transport = transport;
    this.#tokens = {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  /**
   * ### tokens
   *
   * The current token pair, as a copy.
   */
  get tokens(): TokenPair {
    return { ...this.#tokens };
  }

  /**
   * ### onTokensChanged
   *
   * Registers the callback for token refreshes.
   *
   * @param listener Called after every refresh; replaces any previous listener
   */
  onTokensChanged(listener: () => void): void {
    this.#listener = listener;
  }

  /**
   * ### onEnded
   *
   * Registers a callback for when the server ends this login (the refresh token is refused,
   * or the membership is suspended or put into recovery: see {@link loginEnded}), so the app
   * can lock and drop the keys instead of showing errors.
   *
   * @param listener Called once when the login ends
   * @returns Removes the listener
   */
  onEnded(listener: () => void): () => void {
    this.#endedListeners.add(listener);

    return () => {
      this.#endedListeners.delete(listener);
    };
  }

  /**
   * ### request
   *
   * Sends an authenticated request, refreshing the token pair once on a 401. Requests that
   * meet a 401 together share one refresh; a request whose token was already replaced by
   * then just retries with the new one.
   *
   * @param request Request without a token
   * @returns The response body
   */
  readonly request: AuthorizedRequest = async (request) => {
    const sentWith = this.#tokens.accessToken;

    try {
      return await send(this.transport, { ...request, token: sentWith });
    } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 401 || this.#ended) {
        this.#endIf(error);
        throw error;
      }

      if (this.#tokens.accessToken === sentWith) {
        await this.#refresh();
      }

      try {
        return await send(this.transport, {
          ...request,
          token: this.#tokens.accessToken,
        });
      } catch (retryError) {
        this.#endIf(retryError);
        throw retryError;
      }
    }
  };

  /**
   * ### #endIf
   *
   * Ends the login when a failure says it is over (see {@link loginEnded}).
   *
   * @param error Failure of a request
   */
  #endIf(error: unknown): void {
    if (loginEnded(error)) {
      this.#end();
    }
  }

  /**
   * ### #refresh
   *
   * Swaps the refresh token for a new pair, at most once at a time.
   */
  #refresh(): Promise<void> {
    this.#refreshing ??= this.#swapTokens().finally(() => {
      this.#refreshing = undefined;
    });

    return this.#refreshing;
  }

  /**
   * ### #swapTokens
   *
   * Calls the refresh endpoint and stores the new pair. A refused refresh ends the login.
   */
  async #swapTokens(): Promise<void> {
    let response: unknown;

    try {
      response = await send(this.transport, {
        method: "POST",
        path: "/api/auth/refresh",
        body: { refreshToken: this.#tokens.refreshToken },
      });
    } catch (error) {
      if (
        error instanceof ApiError &&
        (error.status === 401 || error.status === 403)
      ) {
        this.#end();
      }

      throw error;
    }

    const refreshed = parseResponse(tokensSchema, response);

    this.#tokens = {
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken,
    };
    this.#listener?.();
  }

  /**
   * ### #end
   *
   * Marks the login as ended and tells the listeners, once.
   */
  #end(): void {
    if (this.#ended) {
      return;
    }

    this.#ended = true;

    for (const listener of this.#endedListeners) {
      listener();
    }
  }
}
