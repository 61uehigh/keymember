import type {
  AuditEntry,
  AuditEvent,
  AuditRepository,
} from "../repositories/AuditRepository.js";
import { COLLECTIONS, documentId } from "./collections.js";
import type { Documents } from "./Documents.js";
import { date, integer, optionalText, text } from "./fields.js";

const AUDIT_EVENTS = COLLECTIONS.auditEvents;

/**
 * ### AUDIT_ID_SPACE
 *
 * Random part of an event id: ids are `milliseconds * AUDIT_ID_SPACE + random`, which grows with
 * time like SQL's `bigserial` while staying below `Number.MAX_SAFE_INTEGER` until the year 2255.
 */
const AUDIT_ID_SPACE = 1000;

/**
 * ### FirestoreAuditRepository
 *
 * {@link AuditRepository} on Firestore. Event ids come from the time of the event plus a random
 * part rather than from a shared counter, so audited transactions do not all contend on one
 * document; the newest events are still the highest ids.
 */
export class FirestoreAuditRepository implements AuditRepository {
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
   * ### record
   *
   * Picks another random part in the rare case the id is taken.
   *
   * @see {@link AuditRepository.record}
   */
  async record(entry: AuditEntry): Promise<void> {
    const at = new Date();

    for (;;) {
      const id =
        at.getTime() * AUDIT_ID_SPACE +
        Math.floor(Math.random() * AUDIT_ID_SPACE);

      if (
        await this.#docs.create(AUDIT_EVENTS, documentId.auditEvent(id), {
          id,
          orgId: entry.orgId,
          actorId: entry.actorId ?? null,
          action: entry.action,
          targetId: entry.targetId ?? null,
          detail: JSON.stringify(entry.detail ?? {}),
          ip: entry.ip,
          at,
        })
      ) {
        return;
      }
    }
  }

  /**
   * ### latest
   *
   * Reads the newest events through the `id` index. A server normally holds one organisation,
   * so the first page is usually all of one; when other organisations' events are mixed in, the
   * page grows until `limit` of this one's are found or there are no more.
   *
   * @see {@link AuditRepository.latest}
   */
  async latest(orgId: string, limit: number): Promise<Array<AuditEvent>> {
    let page = limit;
    let events = await this.#docs.findLatest(AUDIT_EVENTS, "id", page);

    while (
      events.length === page &&
      events.filter(({ data }) => data.orgId === orgId).length < limit
    ) {
      page *= 2;
      events = await this.#docs.findLatest(AUDIT_EVENTS, "id", page);
    }

    return events
      .filter(({ data }) => data.orgId === orgId)
      .slice(0, limit)
      .map(({ data }) => ({
        id: integer(data, "id"),
        actorId: optionalText(data, "actorId"),
        action: text(data, "action"),
        targetId: optionalText(data, "targetId"),
        // Only record writes this field, always from a JSON object
        detail: JSON.parse(text(data, "detail")) as Record<string, unknown>,
        ip: optionalText(data, "ip"),
        at: date(data, "at"),
      }));
  }
}
