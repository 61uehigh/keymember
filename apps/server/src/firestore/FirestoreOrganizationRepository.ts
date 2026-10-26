import type {
  OrganizationProfile,
  OrganizationRepository,
} from "../repositories/OrganizationRepository.js";
import { COLLECTIONS, documentId } from "./collections.js";
import type { Documents } from "./Documents.js";
import { bytes, flag, optionalBytes, optionalText, text } from "./fields.js";
import { insertNew } from "./insertNew.js";
import { claimUnique } from "./uniqueKeys.js";

const ORGANIZATIONS = COLLECTIONS.organizations;
const RECOVERY_KEY_ACCESS = COLLECTIONS.recoveryKeyAccess;

/**
 * ### FirestoreOrganizationRepository
 *
 * {@link OrganizationRepository} on Firestore. Organisations are documents keyed by id;
 * recovery-key copies are keyed by `orgId:adminId`.
 */
export class FirestoreOrganizationRepository implements OrganizationRepository {
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
   * ### hasRecoveryKey
   *
   * @see {@link OrganizationRepository.hasRecoveryKey}
   */
  async hasRecoveryKey(orgId: string): Promise<boolean> {
    const org = await this.#docs.get(ORGANIZATIONS, orgId);

    return org !== undefined && org.recoveryPublicKey !== null;
  }

  /**
   * ### isBootstrapped
   *
   * @see {@link OrganizationRepository.isBootstrapped}
   */
  async isBootstrapped(): Promise<boolean> {
    return (await this.#docs.find(ORGANIZATIONS, [])).length > 0;
  }

  /**
   * ### lockForBootstrap
   *
   * Reading the whole collection inside the transaction makes a concurrent bootstrap conflict
   * with this one, so Firestore retries the loser, which then finds the organisation.
   *
   * @see {@link OrganizationRepository.lockForBootstrap}
   */
  async lockForBootstrap(): Promise<boolean> {
    return this.isBootstrapped();
  }

  /**
   * ### insert
   *
   * @see {@link OrganizationRepository.insert}
   */
  async insert(orgId: string, name: string): Promise<void> {
    // One organisation per server, as the bootstrap lock keeps it on SQL
    await this.#docs.atomic(async (docs) => {
      await claimUnique(docs, "organization", "the", orgId);
      await insertNew(docs, ORGANIZATIONS, orgId, {
        id: orgId,
        name,
        createdAt: new Date(),
        requireTotp: false,
        requireSso: false,
        recoveryPublicKey: null,
        recoveryKeySignature: null,
        recoveryKeySigner: null,
      });
    });
  }

  /**
   * ### profile
   *
   * @see {@link OrganizationRepository.profile}
   */
  async profile(orgId: string): Promise<OrganizationProfile | undefined> {
    const org = await this.#docs.get(ORGANIZATIONS, orgId);

    if (org === undefined) {
      return undefined;
    }

    const publicKey = optionalBytes(org, "recoveryPublicKey");
    const signature = optionalBytes(org, "recoveryKeySignature");
    const signerId = optionalText(org, "recoveryKeySigner");

    return {
      id: orgId,
      name: text(org, "name"),
      requireTotp: flag(org, "requireTotp"),
      requireSso: flag(org, "requireSso"),
      recoveryKey:
        publicKey === undefined ||
        signature === undefined ||
        signerId === undefined
          ? undefined
          : { publicKey, signature, signerId },
    };
  }

  /**
   * ### lockRecoveryKey
   *
   * @see {@link OrganizationRepository.lockRecoveryKey}
   */
  async lockRecoveryKey(orgId: string): Promise<boolean | undefined> {
    const org = await this.#docs.get(ORGANIZATIONS, orgId);

    return org === undefined ? undefined : org.recoveryPublicKey !== null;
  }

  /**
   * ### setRecoveryKey
   *
   * @see {@link OrganizationRepository.setRecoveryKey}
   */
  async setRecoveryKey(
    orgId: string,
    key: { publicKey: Uint8Array; signature: Uint8Array; signerId: string },
  ): Promise<void> {
    await this.#docs.update(ORGANIZATIONS, orgId, {
      recoveryPublicKey: key.publicKey,
      recoveryKeySignature: key.signature,
      recoveryKeySigner: key.signerId,
    });
  }

  /**
   * ### recoveryKeyCopy
   *
   * @see {@link OrganizationRepository.recoveryKeyCopy}
   */
  async recoveryKeyCopy(
    orgId: string,
    adminId: string,
  ): Promise<Uint8Array | undefined> {
    const copy = await this.#docs.get(
      RECOVERY_KEY_ACCESS,
      documentId.recoveryKeyAccess(orgId, adminId),
    );

    return copy === undefined ? undefined : bytes(copy, "wrappedPrivateKey");
  }

  /**
   * ### putRecoveryKeyCopy
   *
   * @see {@link OrganizationRepository.putRecoveryKeyCopy}
   */
  async putRecoveryKeyCopy(
    orgId: string,
    adminId: string,
    wrappedPrivateKey: Uint8Array,
  ): Promise<void> {
    await this.#docs.set(
      RECOVERY_KEY_ACCESS,
      documentId.recoveryKeyAccess(orgId, adminId),
      {
        orgId,
        adminId,
        wrappedPrivateKey,
      },
    );
  }

  /**
   * ### updatePolicies
   *
   * @see {@link OrganizationRepository.updatePolicies}
   */
  async updatePolicies(
    orgId: string,
    policies: {
      requireTotp?: boolean | undefined;
      requireSso?: boolean | undefined;
    },
  ): Promise<void> {
    await this.#docs.update(ORGANIZATIONS, orgId, {
      ...(policies.requireTotp === undefined
        ? {}
        : { requireTotp: policies.requireTotp }),
      ...(policies.requireSso === undefined
        ? {}
        : { requireSso: policies.requireSso }),
    });
  }

  /**
   * ### removeRecoveryKeyCopies
   *
   * @see {@link OrganizationRepository.removeRecoveryKeyCopies}
   */
  async removeRecoveryKeyCopies(adminId: string): Promise<void> {
    for (const copy of await this.#docs.find(RECOVERY_KEY_ACCESS, [
      ["adminId", adminId],
    ])) {
      await this.#docs.delete(RECOVERY_KEY_ACCESS, copy.id);
    }
  }
}
