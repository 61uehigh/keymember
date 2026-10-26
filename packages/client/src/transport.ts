/**
 * ### ApiRequest
 *
 * One HTTP call to the keymember server.
 */
export interface ApiRequest {
  /**
   * ### method
   *
   * HTTP method.
   */
  readonly method: "GET" | "POST" | "PUT" | "DELETE";

  /**
   * ### path
   *
   * Path including any query string, for example `/api/sync?since=12`.
   */
  readonly path: string;

  /**
   * ### body
   *
   * JSON body; omitted for requests without one.
   */
  readonly body?: unknown;

  /**
   * ### token
   *
   * Access token sent as a bearer credential.
   */
  readonly token?: string;
}

/**
 * ### ApiResponse
 *
 * Status and parsed JSON body of a response. `body` is `undefined` for empty responses.
 */
export interface ApiResponse {
  /**
   * ### status
   *
   * HTTP status code.
   */
  readonly status: number;

  /**
   * ### body
   *
   * Parsed JSON body, not yet validated.
   */
  readonly body: unknown;
}

/**
 * ### Transport
 *
 * Sends an {@link ApiRequest}. Swappable so tests can call a server in-process.
 */
export type Transport = (request: ApiRequest) => Promise<ApiResponse>;

/**
 * ### fetchTransport
 *
 * Transport over `fetch`. Refuses plain `http://` for any host other than localhost,
 * because access tokens and authentication keys travel in requests.
 *
 * @param baseUrl Server origin, for example `https://keymember.example.com`
 * @returns A transport bound to the server
 */
export function fetchTransport(baseUrl: string): Transport {
  const origin = new URL(baseUrl);
  const isLocal = ["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname);

  if (
    origin.protocol !== "https:" &&
    !(origin.protocol === "http:" && isLocal)
  ) {
    throw new Error(
      `Can't use a server address without a secure connection (${baseUrl}). Use an https address.`,
    );
  }

  return async (request) => {
    const headers: Record<string, string> = {};

    if (request.body !== undefined) {
      headers["content-type"] = "application/json";
    }

    if (request.token !== undefined) {
      headers.authorization = `Bearer ${request.token}`;
    }

    const response = await fetch(new URL(request.path, origin), {
      method: request.method,
      headers,
      body: request.body === undefined ? null : JSON.stringify(request.body),
    });
    const text = await response.text();

    return {
      status: response.status,
      body: text.length === 0 ? undefined : (JSON.parse(text) as unknown),
    };
  };
}

/**
 * ### ApiError
 *
 * A non-2xx response from the server, carrying its machine-readable code.
 */
export class ApiError extends Error {
  /**
   * ### status
   *
   * HTTP status code.
   */
  readonly status: number;

  /**
   * ### code
   *
   * Error code from the response body, or `unknown` when the body had none.
   */
  readonly code: string;

  /**
   * ### body
   *
   * Full response body for callers that need extra fields such as `currentRevision`.
   */
  readonly body: unknown;

  /**
   * ### constructor
   *
   * @param status HTTP status code
   * @param body Parsed response body
   */
  constructor(status: number, body: unknown) {
    const record =
      typeof body === "object" && body !== null
        ? // Any object will do: only string fields are read below, and each is type-checked
          (body as Record<string, unknown>)
        : {};
    const code = typeof record.error === "string" ? record.error : "unknown";
    const message =
      typeof record.message === "string"
        ? record.message
        : `HTTP ${String(status)}`;

    super(`${message} (${code})`);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

/**
 * ### loginEnded
 *
 * Whether a failure means the login is over and the app should lock: the token was refused
 * (401), or the membership was suspended or put into recovery (403 `membership_ended`).
 *
 * @param error Caught value
 * @returns True when the user has to sign in again
 */
export function loginEnded(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    (error.status === 401 ||
      (error.status === 403 && error.code === "membership_ended"))
  );
}

/**
 * ### send
 *
 * Sends a request and returns the body of a 2xx response.
 * Throws {@link ApiError} for any other status.
 *
 * @param transport Transport to send with
 * @param request Request to send
 * @returns The unvalidated response body
 */
export async function send(
  transport: Transport,
  request: ApiRequest,
): Promise<unknown> {
  const response = await transport(request);

  if (response.status < 200 || response.status >= 300) {
    throw new ApiError(response.status, response.body);
  }

  return response.body;
}
