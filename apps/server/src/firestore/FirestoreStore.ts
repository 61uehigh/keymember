import type { Firestore } from "@google-cloud/firestore";

import type { Repositories } from "../repositories/Repositories.js";
import type { Store } from "../repositories/Store.js";
import type { Documents } from "./Documents.js";
import { FirestoreAuditRepository } from "./FirestoreAuditRepository.js";
import { FirestoreChangeFeedRepository } from "./FirestoreChangeFeedRepository.js";
import {
  DirectDocuments,
  runDocumentSnapshot,
  runDocumentTransaction,
} from "./FirestoreDocuments.js";
import { FirestoreGroupRepository } from "./FirestoreGroupRepository.js";
import { FirestoreInviteRepository } from "./FirestoreInviteRepository.js";
import { FirestoreItemRepository } from "./FirestoreItemRepository.js";
import { FirestoreLoginChallengeRepository } from "./FirestoreLoginChallengeRepository.js";
import { FirestoreMembershipRepository } from "./FirestoreMembershipRepository.js";
import { FirestoreOrganizationRepository } from "./FirestoreOrganizationRepository.js";
import { FirestoreRecoveryRepository } from "./FirestoreRecoveryRepository.js";
import { FirestoreSessionRepository } from "./FirestoreSessionRepository.js";
import { FirestoreShareRepository } from "./FirestoreShareRepository.js";
import { FirestoreSsoRepository } from "./FirestoreSsoRepository.js";
import { FirestoreUserRepository } from "./FirestoreUserRepository.js";
import { FirestoreVaultRepository } from "./FirestoreVaultRepository.js";

/**
 * ### firestoreRepositories
 *
 * The Firestore repositories, all working in the same documents.
 *
 * @param docs Documents inside a transaction or outside one
 * @returns The repositories
 */
export function firestoreRepositories(docs: Documents): Repositories {
  return {
    audit: new FirestoreAuditRepository(docs),
    changeFeed: new FirestoreChangeFeedRepository(docs),
    groups: new FirestoreGroupRepository(docs),
    invites: new FirestoreInviteRepository(docs),
    items: new FirestoreItemRepository(docs),
    loginChallenges: new FirestoreLoginChallengeRepository(docs),
    memberships: new FirestoreMembershipRepository(docs),
    organizations: new FirestoreOrganizationRepository(docs),
    recoveries: new FirestoreRecoveryRepository(docs),
    sessions: new FirestoreSessionRepository(docs),
    shares: new FirestoreShareRepository(docs),
    sso: new FirestoreSsoRepository(docs),
    users: new FirestoreUserRepository(docs),
    vaults: new FirestoreVaultRepository(docs),
  };
}

/**
 * ### FirestoreStore
 *
 * {@link Store} on Firestore, for running the server on Cloud Run without a database server.
 * The caller creates and terminates the Firestore client.
 */
export class FirestoreStore implements Store {
  readonly #db: Firestore;

  /**
   * ### constructor
   *
   * @param db Firestore client of the organisation's project
   */
  constructor(db: Firestore) {
    this.#db = db;
  }

  /**
   * ### repositories
   *
   * @see {@link Store.repositories}
   */
  repositories(): Repositories {
    return firestoreRepositories(new DirectDocuments(this.#db));
  }

  /**
   * ### transaction
   *
   * @see {@link Store.transaction}
   */
  transaction<T>(work: (repositories: Repositories) => Promise<T>): Promise<T> {
    return runDocumentTransaction(this.#db, (docs) =>
      work(firestoreRepositories(docs)),
    );
  }

  /**
   * ### snapshot
   *
   * @see {@link Store.snapshot}
   */
  snapshot<T>(work: (repositories: Repositories) => Promise<T>): Promise<T> {
    return runDocumentSnapshot(this.#db, (docs) =>
      work(firestoreRepositories(docs)),
    );
  }
}
