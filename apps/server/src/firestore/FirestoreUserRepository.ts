import type { KdfParams } from "@keymember/core";

import type {
  LoginAccount,
  NewUser,
  PublishedKeyset,
  UserRepository,
} from "../repositories/UserRepository.js";
import { COLLECTIONS } from "./collections.js";
import type { DocumentData, Documents } from "./Documents.js";
import {
  bytes,
  flag,
  integer,
  optionalBytes,
  optionalInteger,
  optionalText,
  text,
} from "./fields.js";
import { membershipOf } from "./membershipOf.js";
import { insertNew } from "./insertNew.js";
import { claimUnique, releaseUnique } from "./uniqueKeys.js";

const USERS = COLLECTIONS.users;

/**
 * ### FirestoreUserRepository
 *
 * {@link UserRepository} on Firestore. Users are keyed by id; uniqueness of email, account id
 * and SSO subject is checked by the callers, as with the SQL constraints' explicit checks.
 */
export class FirestoreUserRepository implements UserRepository {
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
   * ### signingPublicKey
   *
   * @see {@link UserRepository.signingPublicKey}
   */
  async signingPublicKey(userId: string): Promise<Uint8Array | undefined> {
    const user = await this.#docs.get(USERS, userId);

    return user === undefined ? undefined : bytes(user, "signingPublicKey");
  }

  /**
   * ### isRegistered
   *
   * @see {@link UserRepository.isRegistered}
   */
  async isRegistered(user: {
    id: string;
    email: string;
    accountId: string;
  }): Promise<boolean> {
    return (
      (await this.#docs.get(USERS, user.id)) !== undefined ||
      (await this.#docs.find(USERS, [["email", user.email]])).length > 0 ||
      (await this.#docs.find(USERS, [["accountId", user.accountId]])).length > 0
    );
  }

  /**
   * ### insert
   *
   * @see {@link UserRepository.insert}
   */
  async insert(user: NewUser): Promise<void> {
    // Email and account id are unique, as SQL's constraints keep them
    await this.#docs.atomic(async (docs) => {
      await claimUnique(docs, "email", user.email, user.id);
      await claimUnique(docs, "accountId", user.accountId, user.id);
      await insertNew(docs, USERS, user.id, {
        id: user.id,
        email: user.email,
        name: user.name,
        accountId: user.accountId,
        salt: user.salt,
        kdf: JSON.stringify(user.kdf),
        authVerifier: null,
        authPublicKey: user.loginPublicKey,
        ...keysetFields(user.keyset),
        totpSecret: null,
        totpPendingSecret: null,
        totpLastStep: null,
        ssoSubject: null,
        trustedRoots: null,
        trustedRootsSignature: null,
        createdAt: new Date(),
      });
    });
  }

  /**
   * ### prelogin
   *
   * @see {@link UserRepository.prelogin}
   */
  async prelogin(
    email: string,
  ): Promise<
    { salt: Uint8Array; kdf: KdfParams; legacy: boolean } | undefined
  > {
    const [user] = await this.#docs.find(USERS, [["email", email]]);

    return user === undefined
      ? undefined
      : {
          salt: bytes(user.data, "salt"),
          kdf: kdfOf(user.data),
          legacy: user.data.authPublicKey === null,
        };
  }

  /**
   * ### loginAccount
   *
   * @see {@link UserRepository.loginAccount}
   */
  async loginAccount(
    by: { email: string } | { id: string },
  ): Promise<LoginAccount | undefined> {
    const user =
      "email" in by
        ? (await this.#docs.find(USERS, [["email", by.email]]))[0]?.data
        : await this.#docs.get(USERS, by.id);

    if (user === undefined) {
      return undefined;
    }

    const id = text(user, "id");
    const member = await membershipOf(this.#docs, id);

    if (member === undefined) {
      return undefined;
    }

    return {
      id,
      email: text(user, "email"),
      name: text(user, "name"),
      authVerifier: optionalBytes(user, "authVerifier"),
      authPublicKey: optionalBytes(user, "authPublicKey"),
      totpSecret: optionalBytes(user, "totpSecret"),
      totpLastStep: optionalInteger(user, "totpLastStep"),
      ssoSubject: optionalText(user, "ssoSubject"),
      orgId: member.orgId,
      role: member.role,
      status: member.status,
      requireSso: flag(member.organization, "requireSso"),
      keyset: keysetOf(user),
    };
  }

  /**
   * ### claimTotpStep
   *
   * @see {@link UserRepository.claimTotpStep}
   */
  async claimTotpStep(userId: string, step: number): Promise<boolean> {
    // One transaction, so two requests with the same code cannot both claim it
    return this.#docs.atomic(async (docs) => {
      const user = await docs.get(USERS, userId);

      if (user === undefined) {
        return false;
      }

      const last = optionalInteger(user, "totpLastStep");

      if (last !== undefined && last >= step) {
        return false;
      }

      await docs.update(USERS, userId, { totpLastStep: step });

      return true;
    });
  }

  /**
   * ### adoptLoginKey
   *
   * @see {@link UserRepository.adoptLoginKey}
   */
  async adoptLoginKey(
    userId: string,
    loginPublicKey: Uint8Array,
  ): Promise<void> {
    // One transaction, so a concurrent login cannot install a different key in between
    await this.#docs.atomic(async (docs) => {
      const user = await docs.get(USERS, userId);

      if (
        user !== undefined &&
        optionalBytes(user, "authPublicKey") === undefined
      ) {
        await docs.update(USERS, userId, {
          authPublicKey: loginPublicKey,
          authVerifier: null,
        });
      }
    });
  }

  /**
   * ### credentialsForUpdate
   *
   * @see {@link UserRepository.credentialsForUpdate}
   */
  async credentialsForUpdate(userId: string): Promise<
    | {
        authVerifier: Uint8Array | undefined;
        authPublicKey: Uint8Array | undefined;
      }
    | undefined
  > {
    const user = await this.#docs.get(USERS, userId);

    return user === undefined
      ? undefined
      : {
          authVerifier: optionalBytes(user, "authVerifier"),
          authPublicKey: optionalBytes(user, "authPublicKey"),
        };
  }

  /**
   * ### changePassword
   *
   * @see {@link UserRepository.changePassword}
   */
  async changePassword(
    userId: string,
    change: {
      salt: Uint8Array;
      kdf: KdfParams;
      loginPublicKey: Uint8Array;
      encryptedAccountKey: Uint8Array;
    },
  ): Promise<void> {
    await this.#docs.update(USERS, userId, {
      salt: change.salt,
      kdf: JSON.stringify(change.kdf),
      authPublicKey: change.loginPublicKey,
      authVerifier: null,
      encAccountKey: change.encryptedAccountKey,
    });
  }

  /**
   * ### totpState
   *
   * @see {@link UserRepository.totpState}
   */
  async totpState(userId: string): Promise<
    | {
        pendingSecret: Uint8Array | undefined;
        secret: Uint8Array | undefined;
        lastStep: number | undefined;
      }
    | undefined
  > {
    const user = await this.#docs.get(USERS, userId);

    return user === undefined
      ? undefined
      : {
          pendingSecret: optionalBytes(user, "totpPendingSecret"),
          secret: optionalBytes(user, "totpSecret"),
          lastStep: optionalInteger(user, "totpLastStep"),
        };
  }

  /**
   * ### setPendingTotp
   *
   * @see {@link UserRepository.setPendingTotp}
   */
  async setPendingTotp(userId: string, secret: Uint8Array): Promise<void> {
    await this.#docs.update(USERS, userId, { totpPendingSecret: secret });
  }

  /**
   * ### confirmTotp
   *
   * @see {@link UserRepository.confirmTotp}
   */
  async confirmTotp(userId: string, step: number): Promise<void> {
    const user = await this.#docs.get(USERS, userId);

    if (user !== undefined) {
      await this.#docs.update(USERS, userId, {
        totpSecret: user.totpPendingSecret ?? null,
        totpPendingSecret: null,
        totpLastStep: step,
      });
    }
  }

  /**
   * ### accountIdTakenByOther
   *
   * @see {@link UserRepository.accountIdTakenByOther}
   */
  async accountIdTakenByOther(
    accountId: string,
    userId: string,
  ): Promise<boolean> {
    return (await this.#docs.find(USERS, [["accountId", accountId]])).some(
      (user) => user.id !== userId,
    );
  }

  /**
   * ### rekey
   *
   * @see {@link UserRepository.rekey}
   */
  async rekey(
    userId: string,
    rekey: Omit<NewUser, "email" | "id" | "name">,
  ): Promise<void> {
    await this.#docs.atomic(async (docs) => {
      const user = await docs.get(USERS, userId);

      if (user === undefined) {
        return;
      }

      const previous = text(user, "accountId");

      if (previous !== rekey.accountId) {
        await claimUnique(docs, "accountId", rekey.accountId, userId);
        await releaseUnique(docs, "accountId", previous, userId);
      }

      await docs.update(USERS, userId, {
        accountId: rekey.accountId,
        salt: rekey.salt,
        kdf: JSON.stringify(rekey.kdf),
        authPublicKey: rekey.loginPublicKey,
        authVerifier: null,
        ...keysetFields(rekey.keyset),
        trustedRoots: null,
        trustedRootsSignature: null,
        totpSecret: null,
        totpPendingSecret: null,
        totpLastStep: null,
      });
    });
  }

  /**
   * ### trustedRoots
   *
   * @see {@link UserRepository.trustedRoots}
   */
  async trustedRoots(
    userId: string,
  ): Promise<
    { statement: Record<string, unknown>; signature: Uint8Array } | undefined
  > {
    const user = await this.#docs.get(USERS, userId);
    const statement =
      user === undefined ? undefined : optionalText(user, "trustedRoots");
    const signature =
      user === undefined
        ? undefined
        : optionalBytes(user, "trustedRootsSignature");

    return statement === undefined || signature === undefined
      ? undefined
      : {
          // Only setTrustedRoots writes this field, always as a JSON object
          statement: JSON.parse(statement) as Record<string, unknown>,
          signature,
        };
  }

  /**
   * ### setTrustedRoots
   *
   * @see {@link UserRepository.setTrustedRoots}
   */
  async setTrustedRoots(
    userId: string,
    statement: Record<string, unknown>,
    signature: Uint8Array,
  ): Promise<void> {
    await this.#docs.update(USERS, userId, {
      trustedRoots: JSON.stringify(statement),
      trustedRootsSignature: signature,
    });
  }
}

/**
 * ### keysetFields
 *
 * The user fields that hold a published keyset.
 *
 * @param keyset Keyset to store
 * @returns Its fields
 */
function keysetFields(keyset: PublishedKeyset): DocumentData {
  return {
    encAccountKey: keyset.encryptedAccountKey,
    encPrivateKeys: keyset.encryptedPrivateKeys,
    encryptionPublicKey: keyset.encryptionPublicKey,
    signingPublicKey: keyset.signingPublicKey,
    keysetVersion: keyset.keysetVersion,
    selfSignature: keyset.selfSignature,
  };
}

/**
 * ### keysetOf
 *
 * Reads a user's published keyset.
 *
 * @param user User fields
 * @returns The keyset
 */
function keysetOf(user: DocumentData): PublishedKeyset {
  return {
    encryptedAccountKey: bytes(user, "encAccountKey"),
    encryptedPrivateKeys: bytes(user, "encPrivateKeys"),
    encryptionPublicKey: bytes(user, "encryptionPublicKey"),
    signingPublicKey: bytes(user, "signingPublicKey"),
    keysetVersion: integer(user, "keysetVersion"),
    selfSignature: bytes(user, "selfSignature"),
  };
}

/**
 * ### kdfOf
 *
 * Reads a user's KDF parameters, stored as JSON.
 *
 * @param user User fields
 * @returns The parameters
 */
function kdfOf(user: DocumentData): KdfParams {
  // Only this repository writes the field, always from a KdfParams
  return JSON.parse(text(user, "kdf")) as KdfParams;
}
