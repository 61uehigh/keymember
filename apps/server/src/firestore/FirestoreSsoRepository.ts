import { DuplicateKeyError } from "../repositories/DuplicateKeyError.js";
import type {
  SsoLink,
  SsoRepository,
  SsoTicketRecord,
} from "../repositories/SsoRepository.js";
import { COLLECTIONS } from "./collections.js";
import type { DocumentData, Documents } from "./Documents.js";
import { bytes, date, optionalBytes, optionalText, text } from "./fields.js";
import { insertNew } from "./insertNew.js";
import { claimUnique } from "./uniqueKeys.js";

const TICKETS = COLLECTIONS.ssoTickets;
const SESSIONS = COLLECTIONS.ssoSessions;
const USERS = COLLECTIONS.users;
const MEMBERSHIPS = COLLECTIONS.memberships;

/**
 * ### TICKET_RETENTION_MS
 *
 * How long after expiry a ticket is kept before {@link FirestoreSsoRepository.insertTicket}
 * drops it.
 */
const TICKET_RETENTION_MS = 24 * 60 * 60 * 1000;

/**
 * ### CLEANUP_PAGE
 *
 * Most stale tickets removed while creating one.
 */
const CLEANUP_PAGE = 20;

/**
 * ### FirestoreSsoRepository
 *
 * {@link SsoRepository} on Firestore. Tickets are keyed by id and provider links by the login's
 * family id; the bound provider account is the `ssoSubject` field of the user document.
 */
export class FirestoreSsoRepository implements SsoRepository {
  readonly #docs: Documents;

  /**
   * ### constructor
   *
   * @param docs Documents to work in, inside a transaction or not
   */
  constructor(docs: Documents) {
    this.#docs = docs;
  }

  /**
   * ### insertTicket
   *
   * @see {@link SsoRepository.insertTicket}
   */
  async insertTicket(
    ticket: Omit<
      SsoTicketRecord,
      "createdAt" | "encryptedRefreshToken" | "failure" | "status" | "subject"
    >,
    now: Date,
  ): Promise<void> {
    // Only stale tickets are read, a page at a time, so each is read once when removed
    for (const stale of await this.#docs.findBefore(
      TICKETS,
      "expiresAt",
      new Date(now.getTime() - TICKET_RETENTION_MS),
      CLEANUP_PAGE,
    )) {
      await this.#docs.delete(TICKETS, stale.id);
    }

    await insertNew(this.#docs, TICKETS, ticket.id, {
      id: ticket.id,
      secretHash: ticket.secretHash,
      kind: ticket.kind,
      userId: ticket.userId,
      familyId: ticket.familyId ?? null,
      deviceId: ticket.deviceId ?? null,
      deviceName: ticket.deviceName ?? null,
      state: ticket.state,
      nonce: ticket.nonce,
      codeVerifier: ticket.codeVerifier,
      status: "pending",
      failure: null,
      subject: null,
      encRefreshToken: null,
      expiresAt: ticket.expiresAt,
      // The SQL column defaults to now(), the database's clock rather than the request's
      createdAt: new Date(),
    });
  }

  /**
   * ### ticket
   *
   * @see {@link SsoRepository.ticket}
   */
  async ticket(ticketId: string): Promise<SsoTicketRecord | undefined> {
    const ticket = await this.#docs.get(TICKETS, ticketId);

    return ticket === undefined ? undefined : toTicket(ticketId, ticket);
  }

  /**
   * ### pendingTicket
   *
   * @see {@link SsoRepository.pendingTicket}
   */
  async pendingTicket(
    by: { id: string } | { state: string },
    now: Date,
  ): Promise<
    | (SsoTicketRecord & {
        email: string;
        boundSubject: string | undefined;
        orgId: string;
      })
    | undefined
  > {
    const found =
      "id" in by
        ? await this.#ticketDocument(by.id)
        : (
            await this.#docs.find(TICKETS, [
              ["state", by.state],
              ["status", "pending"],
            ])
          )[0];

    if (
      found?.data.status !== "pending" ||
      date(found.data, "expiresAt") <= now
    ) {
      return undefined;
    }

    const ticket = toTicket(found.id, found.data);
    const user = await this.#docs.get(USERS, ticket.userId);
    const [membership] = await this.#docs.find(MEMBERSHIPS, [
      ["userId", ticket.userId],
    ]);

    // The SQL version joins users and memberships, so a ticket without either is not found
    if (user === undefined || membership === undefined) {
      return undefined;
    }

    return {
      ...ticket,
      email: text(user, "email"),
      boundSubject: optionalText(user, "ssoSubject"),
      orgId: text(membership.data, "orgId"),
    };
  }

  /**
   * ### failTicket
   *
   * @see {@link SsoRepository.failTicket}
   */
  async failTicket(ticketId: string, reason: string): Promise<void> {
    if ((await this.#docs.get(TICKETS, ticketId))?.status === "pending") {
      await this.#docs.update(TICKETS, ticketId, {
        status: "failed",
        failure: reason,
      });
    }
  }

  /**
   * ### verifyTicket
   *
   * @see {@link SsoRepository.verifyTicket}
   */
  async verifyTicket(
    ticketId: string,
    subject: string,
    encryptedRefreshToken: Uint8Array,
  ): Promise<void> {
    if ((await this.#docs.get(TICKETS, ticketId))?.status === "pending") {
      await this.#docs.update(TICKETS, ticketId, {
        status: "verified",
        subject,
        encRefreshToken: encryptedRefreshToken,
      });
    }
  }

  /**
   * ### claimTicket
   *
   * Only atomic inside a transaction, which is where the routes call it.
   *
   * @see {@link SsoRepository.claimTicket}
   */
  async claimTicket(ticketId: string): Promise<boolean> {
    if ((await this.#docs.get(TICKETS, ticketId))?.status !== "verified") {
      return false;
    }

    await this.#docs.update(TICKETS, ticketId, { status: "used" });

    return true;
  }

  /**
   * ### link
   *
   * @see {@link SsoRepository.link}
   */
  async link(familyId: string): Promise<SsoLink | undefined> {
    const link = await this.#docs.get(SESSIONS, familyId);

    return link === undefined ? undefined : toLink(link);
  }

  /**
   * ### putLink
   *
   * @see {@link SsoRepository.putLink}
   */
  async putLink(
    familyId: string,
    userId: string,
    link: SsoLink,
  ): Promise<void> {
    const existing = await this.#docs.get(SESSIONS, familyId);

    await this.#docs.set(SESSIONS, familyId, {
      familyId,
      // An existing row keeps its user, as the SQL upsert only replaces the provider fields
      userId: existing === undefined ? userId : text(existing, "userId"),
      subject: link.subject,
      encRefreshToken: link.encryptedRefreshToken,
      checkedAt: link.checkedAt,
    });
  }

  /**
   * ### recordCheck
   *
   * @see {@link SsoRepository.recordCheck}
   */
  async recordCheck(
    familyId: string,
    at: Date,
    encryptedRefreshToken: Uint8Array | undefined,
  ): Promise<void> {
    await this.#docs.update(SESSIONS, familyId, {
      checkedAt: at,
      ...(encryptedRefreshToken === undefined
        ? {}
        : { encRefreshToken: encryptedRefreshToken }),
    });
  }

  /**
   * ### removeLink
   *
   * @see {@link SsoRepository.removeLink}
   */
  async removeLink(familyId: string): Promise<SsoLink | undefined> {
    const link = await this.#docs.get(SESSIONS, familyId);

    if (link === undefined) {
      return undefined;
    }

    await this.#docs.delete(SESSIONS, familyId);

    return toLink(link);
  }

  /**
   * ### subjectTakenByOther
   *
   * @see {@link SsoRepository.subjectTakenByOther}
   */
  async subjectTakenByOther(subject: string, userId: string): Promise<boolean> {
    return (await this.#docs.find(USERS, [["ssoSubject", subject]])).some(
      (user) => user.id !== userId,
    );
  }

  /**
   * ### bindSubject
   *
   * @see {@link SsoRepository.bindSubject}
   */
  async bindSubject(
    userId: string,
    subject: string,
  ): Promise<string | undefined> {
    return this.#docs.atomic(async (docs) => {
      const user = await docs.get(USERS, userId);

      if (
        user === undefined ||
        (await new FirestoreSsoRepository(docs).subjectTakenByOther(
          subject,
          userId,
        ))
      ) {
        return undefined;
      }

      const bound = optionalText(user, "ssoSubject") ?? subject;

      try {
        // A provider account belongs to one keymember account, as SQL's constraint keeps it
        await claimUnique(docs, "ssoSubject", bound, userId);
      } catch (error) {
        if (error instanceof DuplicateKeyError) {
          return undefined;
        }

        throw error;
      }

      await docs.update(USERS, userId, { ssoSubject: bound });

      return bound;
    });
  }

  /**
   * ### #ticketDocument
   *
   * Reads a ticket by id, in the shape a query returns.
   *
   * @param ticketId Ticket
   * @returns The ticket document, or `undefined`
   */
  async #ticketDocument(
    ticketId: string,
  ): Promise<{ id: string; data: DocumentData } | undefined> {
    const data = await this.#docs.get(TICKETS, ticketId);

    return data === undefined ? undefined : { id: ticketId, data };
  }
}

/**
 * ### toTicket
 *
 * Maps a ticket document to an {@link SsoTicketRecord}.
 *
 * @param id Document id, the ticket id
 * @param data Document fields
 * @returns The record
 */
function toTicket(id: string, data: DocumentData): SsoTicketRecord {
  return {
    id,
    secretHash: bytes(data, "secretHash"),
    // Only insertTicket writes kind, always as "login" or "link"
    kind: text(data, "kind") as SsoTicketRecord["kind"],
    userId: text(data, "userId"),
    familyId: optionalText(data, "familyId"),
    deviceId: optionalText(data, "deviceId"),
    deviceName: optionalText(data, "deviceName"),
    state: text(data, "state"),
    nonce: text(data, "nonce"),
    codeVerifier: text(data, "codeVerifier"),
    // This repository only writes the four ticket statuses
    status: text(data, "status") as SsoTicketRecord["status"],
    failure: optionalText(data, "failure"),
    subject: optionalText(data, "subject"),
    encryptedRefreshToken: optionalBytes(data, "encRefreshToken"),
    expiresAt: date(data, "expiresAt"),
    createdAt: date(data, "createdAt"),
  };
}

/**
 * ### toLink
 *
 * Maps a provider-link document to an {@link SsoLink}.
 *
 * @param data Document fields
 * @returns The link
 */
function toLink(data: DocumentData): SsoLink {
  return {
    subject: text(data, "subject"),
    encryptedRefreshToken: bytes(data, "encRefreshToken"),
    checkedAt: date(data, "checkedAt"),
  };
}
