/**
 * ### ErrorKind
 *
 * What sort of failure an error is, independent of how it is reported. The HTTP edge maps each
 * kind to a status code.
 */
export type ErrorKind =
  | "invalid"
  | "unauthenticated"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "gone"
  | "rate_limited"
  | "unavailable";

/**
 * ### ErrorCode
 *
 * Machine-readable reason clients act on, sent as the `error` field of every failed response.
 * Stable: clients map these to messages.
 */
export type ErrorCode =
  | "bad_request"
  | "unauthorized"
  | "invalid_credentials"
  | "totp_required"
  | "invalid_totp"
  | "totp_enrollment_required"
  | "forbidden"
  | "membership_ended"
  | "bootstrap_token_invalid"
  | "not_confirmed"
  | "not_found"
  | "conflict"
  | "revision_conflict"
  | "rate_limited"
  | "sso_required"
  | "sso_revoked"
  | "sso_failed"
  | "sso_expired"
  | "sso_unavailable"
  | "sso_not_linked"
  | "share_unavailable"
  | "share_denied";

/**
 * ### DomainError
 *
 * An expected failure of a request, raised by services and the HTTP edge alike. Anything else
 * that is thrown is a bug and answers 500.
 */
export class DomainError extends Error {
  /**
   * ### kind
   *
   * What sort of failure this is.
   */
  readonly kind: ErrorKind;

  /**
   * ### code
   *
   * Machine-readable reason.
   */
  readonly code: ErrorCode;

  /**
   * ### detail
   *
   * Extra fields for the client, for example the current revision on a conflict.
   */
  readonly detail: Readonly<Record<string, unknown>>;

  /**
   * ### constructor
   *
   * @param kind What sort of failure this is
   * @param code Machine-readable reason
   * @param message Explanation that is safe to show the client
   * @param detail Extra fields for the client
   */
  constructor(
    kind: ErrorKind,
    code: ErrorCode,
    message: string,
    detail: Readonly<Record<string, unknown>> = {},
  ) {
    super(message);
    this.name = "DomainError";
    this.kind = kind;
    this.code = code;
    this.detail = detail;
  }
}
