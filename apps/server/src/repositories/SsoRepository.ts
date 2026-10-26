/**
 * ### SsoTicketRecord
 *
 * One pass through the identity provider, for a login or for linking a login that exists. It
 * moves from `pending` to `verified` (or `failed`) at the callback, and to `used` when the
 * client collects it.
 */
export interface SsoTicketRecord {
  readonly id: string;
  /** Hash of the secret only the client that started the pass holds */
  readonly secretHash: Uint8Array;
  readonly kind: "login" | "link";
  readonly userId: string;
  /** The login being linked, for `link` tickets */
  readonly familyId: string | undefined;
  readonly deviceId: string | undefined;
  readonly deviceName: string | undefined;
  readonly state: string;
  readonly nonce: string;
  readonly codeVerifier: string;
  readonly status: "pending" | "verified" | "failed" | "used";
  readonly failure: string | undefined;
  /** The provider account that passed, once verified */
  readonly subject: string | undefined;
  /** The provider refresh token, sealed with the server's key, once verified */
  readonly encryptedRefreshToken: Uint8Array | undefined;
  readonly expiresAt: Date;
  readonly createdAt: Date;
}

/**
 * ### SsoLink
 *
 * A login that passed the identity provider, with what the server re-checks it with.
 */
export interface SsoLink {
  readonly subject: string;
  readonly encryptedRefreshToken: Uint8Array;
  readonly checkedAt: Date;
}

/**
 * ### SsoRepository
 *
 * Storage of identity-provider passes (`sso_tickets`) and of the logins they vouch for
 * (`sso_sessions`).
 */
export interface SsoRepository {
  /**
   * ### insertTicket
   *
   * Stores a new pending ticket, first dropping tickets that expired a day ago or more.
   *
   * @param ticket The ticket
   * @param now Current time
   */
  insertTicket(
    ticket: Omit<
      SsoTicketRecord,
      "createdAt" | "encryptedRefreshToken" | "failure" | "status" | "subject"
    >,
    now: Date,
  ): Promise<void>;

  /**
   * ### ticket
   *
   * Any ticket by id.
   *
   * @param ticketId Ticket
   * @returns The ticket, or `undefined`
   */
  ticket(ticketId: string): Promise<SsoTicketRecord | undefined>;

  /**
   * ### pendingTicket
   *
   * A pending, unexpired ticket with the email of its user.
   *
   * @param by The ticket's id or its provider `state`
   * @param now Current time
   * @returns The ticket and its user's email, current provider subject and organisation
   */
  pendingTicket(
    by: { id: string } | { state: string },
    now: Date,
  ): Promise<
    | (SsoTicketRecord & {
        email: string;
        boundSubject: string | undefined;
        orgId: string;
      })
    | undefined
  >;

  /**
   * ### failTicket
   *
   * Marks a pending ticket failed.
   *
   * @param ticketId Ticket
   * @param reason Why
   */
  failTicket(ticketId: string, reason: string): Promise<void>;

  /**
   * ### verifyTicket
   *
   * Marks a pending ticket verified with the provider account that passed.
   *
   * @param ticketId Ticket
   * @param subject Provider account
   * @param encryptedRefreshToken Provider refresh token, sealed
   */
  verifyTicket(
    ticketId: string,
    subject: string,
    encryptedRefreshToken: Uint8Array,
  ): Promise<void>;

  /**
   * ### claimTicket
   *
   * Uses up a verified ticket.
   *
   * @param ticketId Ticket
   * @returns Whether this call claimed it; `false` when someone already did
   */
  claimTicket(ticketId: string): Promise<boolean>;

  /**
   * ### link
   *
   * The provider link of a login.
   *
   * @param familyId Login
   * @returns The link, or `undefined` when the login never passed the provider
   */
  link(familyId: string): Promise<SsoLink | undefined>;

  /**
   * ### putLink
   *
   * Records that a login passed the provider, replacing an earlier pass.
   *
   * @param familyId Login
   * @param userId Its user
   * @param link Provider account, sealed refresh token and time of the check
   */
  putLink(familyId: string, userId: string, link: SsoLink): Promise<void>;

  /**
   * ### recordCheck
   *
   * Notes a successful re-check, with the provider's new refresh token if it issued one.
   *
   * @param familyId Login
   * @param at Time of the check
   * @param encryptedRefreshToken New sealed refresh token, if any
   */
  recordCheck(
    familyId: string,
    at: Date,
    encryptedRefreshToken: Uint8Array | undefined,
  ): Promise<void>;

  /**
   * ### removeLink
   *
   * Forgets a login's provider link.
   *
   * @param familyId Login
   * @returns The link that was removed, or `undefined` when there was none
   */
  removeLink(familyId: string): Promise<SsoLink | undefined>;

  /**
   * ### subjectTakenByOther
   *
   * Whether another user is already bound to a provider account.
   *
   * @param subject Provider account
   * @param userId The user who may use it
   * @returns Whether someone else holds it
   */
  subjectTakenByOther(subject: string, userId: string): Promise<boolean>;

  /**
   * ### bindSubject
   *
   * Binds a user to a provider account on first use, unless another user holds it.
   *
   * @param userId User
   * @param subject Provider account
   * @returns The account the user is bound to afterwards, or `undefined` when the bind lost a race
   */
  bindSubject(userId: string, subject: string): Promise<string | undefined>;
}
