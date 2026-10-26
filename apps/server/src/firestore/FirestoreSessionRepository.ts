import type {
  AuthenticatedSession,
  NewSession,
  RefreshableSession,
  SessionRepository,
} from "../repositories/SessionRepository.js";
import { COLLECTIONS, documentId } from "./collections.js";
import type { Documents, StoredDocument } from "./Documents.js";
import { date, flag, optionalBytes, optionalDate, text } from "./fields.js";
import { membershipOf } from "./membershipOf.js";
import { insertNew } from "./insertNew.js";

const SESSIONS = COLLECTIONS.sessions;

/**
 * ### FirestoreSessionRepository
 *
 * {@link SessionRepository} on Firestore. Sessions are keyed by the base64url access-token
 * hash and found by refresh hash, family or user through equality queries.
 */
export class FirestoreSessionRepository implements SessionRepository {
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
   * ### insert
   *
   * @see {@link SessionRepository.insert}
   */
  async insert(session: NewSession): Promise<void> {
    await insertNew(
      this.#docs,
      SESSIONS,
      documentId.session(session.accessHash),
      {
        accessHash: session.accessHash,
        refreshHash: session.refreshHash,
        familyId: session.familyId,
        userId: session.userId,
        deviceId: session.deviceId,
        deviceName: session.deviceName,
        accessExpiresAt: session.accessExpiresAt,
        refreshExpiresAt: session.refreshExpiresAt,
        rotatedAt: null,
        revokedAt: null,
        createdAt: new Date(),
      },
    );
  }

  /**
   * ### authenticate
   *
   * @see {@link SessionRepository.authenticate}
   */
  async authenticate(
    accessHash: Uint8Array,
    now: Date,
  ): Promise<AuthenticatedSession | undefined> {
    const session = await this.#docs.get(
      SESSIONS,
      documentId.session(accessHash),
    );

    if (
      session === undefined ||
      optionalDate(session, "revokedAt") !== undefined ||
      date(session, "accessExpiresAt") <= now
    ) {
      return undefined;
    }

    const userId = text(session, "userId");
    const familyId = text(session, "familyId");
    // Every request runs this; the user and membership reads do not depend on each other
    const [user, member] = await Promise.all([
      this.#docs.get(COLLECTIONS.users, userId),
      membershipOf(this.#docs, userId),
    ]);

    if (user === undefined || member === undefined) {
      return undefined;
    }

    return {
      userId,
      email: text(user, "email"),
      orgId: member.orgId,
      role: member.role,
      status: member.status,
      familyId,
      totpMissing:
        flag(member.organization, "requireTotp") &&
        optionalBytes(user, "totpSecret") === undefined,
      ssoMissing:
        flag(member.organization, "requireSso") &&
        (await this.#docs.get(COLLECTIONS.ssoSessions, familyId)) === undefined,
    };
  }

  /**
   * ### refreshTarget
   *
   * @see {@link SessionRepository.refreshTarget}
   */
  async refreshTarget(refreshHash: Uint8Array): Promise<
    | {
        familyId: string;
        userId: string;
        orgId: string;
        requireSso: boolean;
      }
    | undefined
  > {
    const session = await this.#byRefreshHash(refreshHash);

    if (session?.data.rotatedAt !== null || session.data.revokedAt !== null) {
      return undefined;
    }

    const userId = text(session.data, "userId");
    const member = await membershipOf(this.#docs, userId);

    return member === undefined
      ? undefined
      : {
          familyId: text(session.data, "familyId"),
          userId,
          orgId: member.orgId,
          requireSso: flag(member.organization, "requireSso"),
        };
  }

  /**
   * ### lockForRefresh
   *
   * @see {@link SessionRepository.lockForRefresh}
   */
  async lockForRefresh(
    refreshHash: Uint8Array,
  ): Promise<RefreshableSession | undefined> {
    const session = await this.#byRefreshHash(refreshHash);

    if (session === undefined) {
      return undefined;
    }

    const userId = text(session.data, "userId");
    const member = await membershipOf(this.#docs, userId);

    return member === undefined
      ? undefined
      : {
          familyId: text(session.data, "familyId"),
          userId,
          orgId: member.orgId,
          deviceId: text(session.data, "deviceId"),
          deviceName: text(session.data, "deviceName"),
          refreshExpiresAt: date(session.data, "refreshExpiresAt"),
          spent:
            optionalDate(session.data, "rotatedAt") !== undefined ||
            optionalDate(session.data, "revokedAt") !== undefined,
        };
  }

  /**
   * ### markRotated
   *
   * @see {@link SessionRepository.markRotated}
   */
  async markRotated(refreshHash: Uint8Array, at: Date): Promise<void> {
    for (const session of await this.#docs.find(SESSIONS, [
      ["refreshHash", refreshHash],
    ])) {
      await this.#docs.update(SESSIONS, session.id, {
        rotatedAt: at,
        revokedAt: at,
      });
    }
  }

  /**
   * ### revokeFamily
   *
   * @see {@link SessionRepository.revokeFamily}
   */
  async revokeFamily(familyId: string, at: Date): Promise<void> {
    await this.#revoke(
      await this.#docs.find(SESSIONS, [
        ["familyId", familyId],
        ["revokedAt", null],
      ]),
      at,
    );
  }

  /**
   * ### revokeOthers
   *
   * @see {@link SessionRepository.revokeOthers}
   */
  async revokeOthers(
    userId: string,
    keepFamilyId: string,
    at: Date,
  ): Promise<void> {
    await this.#revoke(
      (
        await this.#docs.find(SESSIONS, [
          ["userId", userId],
          ["revokedAt", null],
        ])
      ).filter((session) => session.data.familyId !== keepFamilyId),
      at,
    );
  }

  /**
   * ### revokeAll
   *
   * @see {@link SessionRepository.revokeAll}
   */
  async revokeAll(userId: string, at: Date): Promise<void> {
    await this.#revoke(
      await this.#docs.find(SESSIONS, [
        ["userId", userId],
        ["revokedAt", null],
      ]),
      at,
    );
  }

  /**
   * ### isFamilyActive
   *
   * @see {@link SessionRepository.isFamilyActive}
   */
  async isFamilyActive(familyId: string): Promise<boolean> {
    return (
      (
        await this.#docs.find(SESSIONS, [
          ["familyId", familyId],
          ["revokedAt", null],
        ])
      ).length > 0
    );
  }

  /**
   * ### knownDevice
   *
   * @see {@link SessionRepository.knownDevice}
   */
  async knownDevice(userId: string, deviceId: string): Promise<boolean> {
    return (
      (
        await this.#docs.find(SESSIONS, [
          ["userId", userId],
          ["deviceId", deviceId],
        ])
      ).length > 0
    );
  }

  /**
   * ### #byRefreshHash
   *
   * Finds the session a refresh token belongs to. Refresh hashes are unique.
   *
   * @param refreshHash Hash of the refresh token
   * @returns The session, or `undefined`
   */
  async #byRefreshHash(
    refreshHash: Uint8Array,
  ): Promise<StoredDocument | undefined> {
    const [session] = await this.#docs.find(SESSIONS, [
      ["refreshHash", refreshHash],
    ]);

    return session;
  }

  /**
   * ### purgeExpired
   *
   * @see {@link SessionRepository.purgeExpired}
   */
  async purgeExpired(now: Date, limit: number): Promise<number> {
    const expired = await this.#docs.findBefore(
      SESSIONS,
      "refreshExpiresAt",
      now,
      limit,
    );

    for (const session of expired) {
      await this.#docs.delete(SESSIONS, session.id);
    }

    return expired.length;
  }

  /**
   * ### #revoke
   *
   * Marks sessions revoked.
   *
   * @param sessions Sessions to revoke
   * @param at Revocation time
   */
  async #revoke(
    sessions: ReadonlyArray<StoredDocument>,
    at: Date,
  ): Promise<void> {
    for (const session of sessions) {
      await this.#docs.update(SESSIONS, session.id, { revokedAt: at });
    }
  }
}
