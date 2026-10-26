import type { MembershipRole } from "../domain/membership.js";
import type { InviteRepository } from "../repositories/InviteRepository.js";
import { COLLECTIONS, documentId } from "./collections.js";
import type { Documents } from "./Documents.js";
import { date, optionalDate, text } from "./fields.js";
import { insertNew } from "./insertNew.js";

const INVITES = COLLECTIONS.invites;

/**
 * ### FirestoreInviteRepository
 *
 * {@link InviteRepository} on Firestore. Invites are keyed by the base64url token hash.
 */
export class FirestoreInviteRepository implements InviteRepository {
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
   * ### lockValid
   *
   * @see {@link InviteRepository.lockValid}
   */
  async lockValid(
    tokenHash: Uint8Array,
    now: Date,
  ): Promise<
    { orgId: string; email: string; role: MembershipRole } | undefined
  > {
    const invite = await this.#docs.get(INVITES, documentId.invite(tokenHash));

    if (
      invite === undefined ||
      optionalDate(invite, "usedAt") !== undefined ||
      date(invite, "expiresAt") <= now
    ) {
      return undefined;
    }

    return {
      orgId: text(invite, "orgId"),
      email: text(invite, "email"),
      // Only insert writes this field, always with a MembershipRole
      role: text(invite, "role") as MembershipRole,
    };
  }

  /**
   * ### markUsed
   *
   * @see {@link InviteRepository.markUsed}
   */
  async markUsed(
    tokenHash: Uint8Array,
    at: Date,
    proof?: Uint8Array,
  ): Promise<void> {
    await this.#docs.update(INVITES, documentId.invite(tokenHash), {
      usedAt: at,
      proof: proof ?? null,
    });
  }

  /**
   * ### insert
   *
   * @see {@link InviteRepository.insert}
   */
  async insert(invite: {
    tokenHash: Uint8Array;
    orgId: string;
    email: string;
    role: MembershipRole;
    createdBy: string;
    expiresAt: Date;
    statement: Record<string, unknown>;
    signature: Uint8Array;
  }): Promise<void> {
    await insertNew(this.#docs, INVITES, documentId.invite(invite.tokenHash), {
      tokenHash: invite.tokenHash,
      orgId: invite.orgId,
      email: invite.email,
      role: invite.role,
      createdBy: invite.createdBy,
      expiresAt: invite.expiresAt,
      usedAt: null,
      proof: null,
      statement: JSON.stringify(invite.statement),
      signature: invite.signature,
    });
  }

  /**
   * ### expireAllBy
   *
   * @see {@link InviteRepository.expireAllBy}
   */
  async expireAllBy(userId: string, at: Date): Promise<void> {
    for (const invite of await this.#docs.find(INVITES, [
      ["createdBy", userId],
      ["usedAt", null],
    ])) {
      if (date(invite.data, "expiresAt") > at) {
        await this.#docs.update(INVITES, invite.id, { expiresAt: at });
      }
    }
  }
}
