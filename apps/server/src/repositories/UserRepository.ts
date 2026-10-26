import type { KdfParams } from "@keymember/core";
import type { MembershipRole, MembershipStatus } from "../domain/membership.js";

/**
 * ### PublishedKeyset
 *
 * A user's encrypted keyset and the public keys they published with their self-signature.
 */
export interface PublishedKeyset {
  readonly encryptedAccountKey: Uint8Array;
  readonly encryptedPrivateKeys: Uint8Array;
  readonly encryptionPublicKey: Uint8Array;
  readonly signingPublicKey: Uint8Array;
  readonly keysetVersion: number;
  readonly selfSignature: Uint8Array;
}

/**
 * ### NewUser
 *
 * An account as sign-up creates it.
 */
export interface NewUser {
  readonly id: string;
  readonly email: string;
  readonly name: string;
  /** Public part of the Secret Key, unique per account */
  readonly accountId: string;
  readonly salt: Uint8Array;
  readonly kdf: KdfParams;
  /** Public key the client signs login challenges with */
  readonly loginPublicKey: Uint8Array;
  readonly keyset: PublishedKeyset;
}

/**
 * ### LoginAccount
 *
 * What finishing a login needs about a user: how they prove their password, their second
 * factor, their membership and policy, and the keyset to hand back.
 */
export interface LoginAccount {
  readonly id: string;
  readonly email: string;
  readonly name: string;
  /** Legacy password verifier, until the account switches to signed login */
  readonly authVerifier: Uint8Array | undefined;
  readonly authPublicKey: Uint8Array | undefined;
  readonly totpSecret: Uint8Array | undefined;
  /** Last TOTP step used, so a code cannot be replayed */
  readonly totpLastStep: number | undefined;
  readonly ssoSubject: string | undefined;
  readonly orgId: string;
  readonly role: MembershipRole;
  readonly status: MembershipStatus;
  readonly requireSso: boolean;
  readonly keyset: PublishedKeyset;
}

/**
 * ### UserRepository
 *
 * Storage of user accounts: credentials, published keys and the encrypted keyset.
 */
export interface UserRepository {
  /**
   * ### signingPublicKey
   *
   * A user's published Ed25519 key, for checking what they signed.
   *
   * @param userId User
   * @returns The key, or `undefined` for an unknown user
   */
  signingPublicKey(userId: string): Promise<Uint8Array | undefined>;

  /**
   * ### isRegistered
   *
   * Whether any of an account's unique values is taken.
   *
   * @param user Id, email and account id
   * @returns Whether one is
   */
  isRegistered(user: {
    id: string;
    email: string;
    accountId: string;
  }): Promise<boolean>;

  /**
   * ### insert
   *
   * Creates an account.
   *
   * @param user The account
   */
  insert(user: NewUser): Promise<void>;

  /**
   * ### prelogin
   *
   * What a client needs before it can derive its login key.
   *
   * @param email Email
   * @returns Salt, KDF parameters and whether the account still uses the legacy proof
   */
  prelogin(
    email: string,
  ): Promise<{ salt: Uint8Array; kdf: KdfParams; legacy: boolean } | undefined>;

  /**
   * ### loginAccount
   *
   * A user as login needs them.
   *
   * @param by Their email or id
   * @returns The account, or `undefined`
   */
  loginAccount(
    by: { email: string } | { id: string },
  ): Promise<LoginAccount | undefined>;

  /**
   * ### claimTotpStep
   *
   * Uses up a TOTP step, so two logins racing with the same code cannot both pass.
   *
   * @param userId User
   * @param step Step of the code
   * @returns Whether this call claimed it
   */
  claimTotpStep(userId: string, step: number): Promise<boolean>;

  /**
   * ### adoptLoginKey
   *
   * Switches a legacy account to signed login, dropping its old verifier.
   *
   * @param userId User
   * @param loginPublicKey Their new login key
   */
  adoptLoginKey(userId: string, loginPublicKey: Uint8Array): Promise<void>;

  /**
   * ### credentialsForUpdate
   *
   * Locks a user and returns how they prove their password.
   *
   * @param userId User
   * @returns The legacy verifier and the login key, either possibly unset
   */
  credentialsForUpdate(userId: string): Promise<
    | {
        authVerifier: Uint8Array | undefined;
        authPublicKey: Uint8Array | undefined;
      }
    | undefined
  >;

  /**
   * ### changePassword
   *
   * Stores the outcome of a password change: new KDF inputs, login key and wrapped account key.
   *
   * @param userId User
   * @param change New salt, KDF parameters, login key and encrypted account key
   */
  changePassword(
    userId: string,
    change: {
      salt: Uint8Array;
      kdf: KdfParams;
      loginPublicKey: Uint8Array;
      encryptedAccountKey: Uint8Array;
    },
  ): Promise<void>;

  /**
   * ### totpState
   *
   * A user's two-factor enrolment.
   *
   * @param userId User
   * @returns The pending and active secrets and the last step used
   */
  totpState(userId: string): Promise<
    | {
        pendingSecret: Uint8Array | undefined;
        secret: Uint8Array | undefined;
        lastStep: number | undefined;
      }
    | undefined
  >;

  /**
   * ### setPendingTotp
   *
   * Stores a secret waiting to be confirmed with a first code.
   *
   * @param userId User
   * @param secret The new secret
   */
  setPendingTotp(userId: string, secret: Uint8Array): Promise<void>;

  /**
   * ### confirmTotp
   *
   * Makes the pending secret the active one.
   *
   * @param userId User
   * @param step Step of the code that confirmed it
   */
  confirmTotp(userId: string, step: number): Promise<void>;

  /**
   * ### accountIdTakenByOther
   *
   * Whether another user already has an account id.
   *
   * @param accountId Account id from a new Secret Key
   * @param userId The user who may use it
   * @returns Whether someone else has it
   */
  accountIdTakenByOther(accountId: string, userId: string): Promise<boolean>;

  /**
   * ### rekey
   *
   * Replaces a user's credentials and keyset after a recovery, clearing two-factor login.
   *
   * @param userId User
   * @param rekey New account id, KDF inputs, login key and keyset
   */
  rekey(
    userId: string,
    rekey: Omit<NewUser, "email" | "id" | "name">,
  ): Promise<void>;

  /**
   * ### trustedRoots
   *
   * The organisation keys a user trusts, as they signed them, so their other devices can adopt
   * the roots without a fingerprint check. The server only stores them; the user's devices verify.
   *
   * @param userId User
   * @returns The signed statement, or `undefined` when the user has not stored one
   */
  trustedRoots(
    userId: string,
  ): Promise<
    { statement: Record<string, unknown>; signature: Uint8Array } | undefined
  >;

  /**
   * ### setTrustedRoots
   *
   * Stores a user's signed trusted roots, replacing earlier ones.
   *
   * @param userId User
   * @param statement Signed statement, as the client sent it
   * @param signature User's signature over it
   */
  setTrustedRoots(
    userId: string,
    statement: Record<string, unknown>,
    signature: Uint8Array,
  ): Promise<void>;
}
