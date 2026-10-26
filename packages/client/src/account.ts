import {
  createAccountKeyset,
  DEFAULT_KDF_PARAMS,
  deriveAccountSecrets,
  generateSalt,
  generateSecretKey,
  inviteProof,
  loginPublicKey,
  MalformedDataError,
  unlockAccountKeyset,
} from "@keymember/core";
import type {
  AccountSecrets,
  PublicKeyBundle,
  SecretKey,
  StoredAccountKeyset,
} from "@keymember/core";
import { z } from "zod";

import {
  encode,
  loginResponseSchema,
  parseResponse,
  preloginResponseSchema,
} from "./schemas.js";
import { challengeSignature } from "./loginChallenge.js";
import { Session } from "./Session.js";
import { resolveSso } from "./sso.js";
import type { SsoHandler } from "./sso.js";
import { send } from "./transport.js";
import type { Transport } from "./transport.js";

/**
 * ### NewAccount
 *
 * Credentials chosen at sign-up.
 */
export interface NewAccount {
  /**
   * ### email
   *
   * Login email.
   */
  readonly email: string;

  /**
   * ### name
   *
   * Display name.
   */
  readonly name: string;

  /**
   * ### password
   *
   * Account password. Never sent to the server.
   */
  readonly password: string;
}

/**
 * ### CreatedAccount
 *
 * Result of sign-up. The caller must show `secretKey` to the user and get it into the
 * Emergency Kit: nobody, including admins, can recover data without it.
 */
export interface CreatedAccount {
  /**
   * ### userId
   *
   * Identifier of the new user.
   */
  readonly userId: string;

  /**
   * ### secretKey
   *
   * The new account's Secret Key.
   */
  readonly secretKey: SecretKey;
}

/**
 * ### buildSignupPayload
 *
 * Generates every secret for a new account and builds the sign-up request body.
 *
 * @param account Credentials chosen by the user
 * @returns The created account and the request body to send
 */
async function buildSignupPayload(
  account: NewAccount,
  userId: string = crypto.randomUUID(),
  keysetVersion = 1,
): Promise<{
  created: CreatedAccount;
  payload: Record<string, unknown>;
  publicBundle: PublicKeyBundle;
}> {
  const secretKey = generateSecretKey();
  const salt = generateSalt();
  const secrets = await deriveAccountSecrets(
    account.password,
    secretKey,
    salt,
    DEFAULT_KDF_PARAMS,
  );
  const { stored } = createAccountKeyset(
    userId,
    secrets.accountUnlockKey,
    keysetVersion,
  );

  return {
    created: { userId, secretKey },
    publicBundle: stored.publicBundle,
    payload: {
      userId,
      email: account.email,
      name: account.name,
      accountId: secretKey.accountId,
      salt: encode(salt),
      kdf: DEFAULT_KDF_PARAMS,
      loginPublicKey: encode(loginPublicKey(secrets.loginSigningSeed)),
      keyset: {
        encryptedAccountKey: encode(stored.encryptedAccountKey),
        encryptedPrivateKeys: encode(stored.encryptedPrivateKeys),
        encryptionPublicKey: encode(stored.publicBundle.encryptionPublicKey),
        signingPublicKey: encode(stored.publicBundle.signingPublicKey),
        keysetVersion: stored.publicBundle.keysetVersion,
        selfSignature: encode(stored.selfSignature),
      },
    },
  };
}

/**
 * ### bootstrapOrganization
 *
 * Creates the server's single organisation with the caller as owner. Works only on an empty server.
 * The owner must then log in and call {@link Session.initializeOrganization} before using vaults.
 *
 * @param transport Transport to the server
 * @param orgName Organisation name
 * @param account Owner's credentials
 * @param bootstrapToken Token from the server's log or its `KEYMEMBER_BOOTSTRAP_TOKEN`, which
 *   the server asks for so that whoever reaches it first cannot claim it
 * @returns The owner's account, including the Secret Key to save
 */
export async function bootstrapOrganization(
  transport: Transport,
  orgName: string,
  account: NewAccount,
  bootstrapToken?: string,
): Promise<CreatedAccount> {
  const { created, payload } = await buildSignupPayload(account);

  await send(transport, {
    method: "POST",
    path: "/api/bootstrap",
    body: {
      orgName,
      signup: payload,
      ...(bootstrapToken === undefined ? {} : { bootstrapToken }),
    },
  });

  return created;
}

/**
 * ### signUp
 *
 * Accepts an invite. The account stays unusable for vaults until an admin certifies it. With
 * the secret from an invite link, it also sends proof that the new keys are the invitee's, so
 * the inviting admin's app certifies them without a fingerprint comparison.
 *
 * @param transport Transport to the server
 * @param inviteToken Token from the invite
 * @param account New member's credentials; the email must match the invite
 * @param linkSecret Secret from the invite link; omit when the token was typed in by hand
 * @returns The new account, including the Secret Key to save
 */
export async function signUp(
  transport: Transport,
  inviteToken: string,
  account: NewAccount,
  linkSecret?: Uint8Array,
): Promise<CreatedAccount> {
  const { created, payload, publicBundle } = await buildSignupPayload(account);

  await send(transport, {
    method: "POST",
    path: "/api/auth/signup",
    body: {
      ...payload,
      inviteToken,
      ...(linkSecret === undefined
        ? {}
        : { inviteProof: encode(inviteProof(linkSecret, publicBundle)) }),
    },
  });

  return created;
}

/**
 * ### LoginInput
 *
 * Everything needed to log in from a device.
 */
export interface LoginInput {
  /**
   * ### email
   *
   * Login email.
   */
  readonly email: string;

  /**
   * ### password
   *
   * Account password.
   */
  readonly password: string;

  /**
   * ### secretKey
   *
   * Secret Key held on this device.
   */
  readonly secretKey: SecretKey;

  /**
   * ### deviceId
   *
   * Stable identifier of this device.
   */
  readonly deviceId: string;

  /**
   * ### deviceName
   *
   * Human-readable device name shown in session lists and audit logs.
   */
  readonly deviceName: string;

  /**
   * ### totp
   *
   * Current two-factor code, when the account has two-factor enabled.
   */
  readonly totp?: string;

  /**
   * ### sso
   *
   * Takes part in the identity-provider check when the organisation requires it. Without it,
   * such a login throws `SsoRequiredError`.
   */
  readonly sso?: SsoHandler;

  /**
   * ### requestSso
   *
   * Passes the identity provider even when the organisation does not require it yet, e.g. to
   * prove the provider works before requiring it.
   *
   * @defaultValue `false`
   */
  readonly requestSso?: boolean;
}

/**
 * ### loginProof
 *
 * What proves the credentials at login: a signature over the server's challenge, so nothing
 * replayable crosses the wire. An account that has not switched over yet sends its legacy key
 * once, together with the new login public key that replaces it.
 *
 * @param prelogin Prelogin response with the challenge
 * @param secrets Derived account secrets
 * @param email Account email
 * @param deviceId Device signing in
 * @returns Request body fields
 */
export function loginProof(
  prelogin: z.infer<typeof preloginResponseSchema>,
  secrets: AccountSecrets,
  email: string,
  deviceId: string,
): Record<string, string> {
  if (prelogin.method === "legacy") {
    return {
      authKey: encode(secrets.authenticationKey),
      loginPublicKey: encode(loginPublicKey(secrets.loginSigningSeed)),
    };
  }

  return {
    challengeId: prelogin.challengeId,
    signature: challengeSignature(
      secrets.loginSigningSeed,
      prelogin,
      "login",
      email,
      deviceId,
    ),
  };
}

/**
 * ### logIn
 *
 * Derives the account secrets, authenticates, and unlocks the keyset.
 * Throws `KdfParametersRejectedError` when prelogin returns weakened parameters,
 * and an {@link ApiError} with code `totp_required` when a two-factor code is needed.
 *
 * @param transport Transport to the server
 * @param input Credentials and device
 * @returns An unlocked session
 */
export async function logIn(
  transport: Transport,
  input: LoginInput,
): Promise<Session> {
  const prelogin = parseResponse(
    preloginResponseSchema,
    await send(transport, {
      method: "POST",
      path: "/api/auth/prelogin",
      body: { email: input.email },
    }),
  );
  const secrets = await deriveAccountSecrets(
    input.password,
    input.secretKey,
    prelogin.salt,
    prelogin.kdf,
  );
  const response = parseResponse(
    loginResponseSchema,
    await resolveSso(
      transport,
      await send(transport, {
        method: "POST",
        path: "/api/auth/login",
        body: {
          email: input.email,
          ...loginProof(prelogin, secrets, input.email, input.deviceId),
          deviceId: input.deviceId,
          deviceName: input.deviceName,
          ...(input.totp === undefined ? {} : { totp: input.totp }),
          ...(input.requestSso === true ? { sso: true } : {}),
        },
      }),
      input.sso,
    ),
  );
  const stored: StoredAccountKeyset = {
    encryptedAccountKey: response.keyset.encryptedAccountKey,
    encryptedPrivateKeys: response.keyset.encryptedPrivateKeys,
    publicBundle: {
      userId: response.user.id,
      encryptionPublicKey: response.keyset.encryptionPublicKey,
      signingPublicKey: response.keyset.signingPublicKey,
      keysetVersion: response.keyset.keysetVersion,
    },
    selfSignature: response.keyset.selfSignature,
  };
  const keyset = unlockAccountKeyset(stored, secrets.accountUnlockKey);

  if (keyset.userId !== response.user.id) {
    throw new MalformedDataError("Server returned a keyset for another user");
  }

  return new Session(
    transport,
    response.user,
    keyset,
    response,
    input.secretKey,
    response.recoveryCancelled ?? false,
  );
}

/**
 * ### recoveryInfo
 *
 * Looks up who a recovery token is for, so the client can show it before re-enrolling.
 *
 * @param transport Transport to the server
 * @param recoveryToken Token an admin handed over
 * @returns The account and organisation the token recovers
 */
export async function recoveryInfo(
  transport: Transport,
  recoveryToken: string,
): Promise<{
  userId: string;
  email: string;
  orgName: string;
  nextKeysetVersion: number;
}> {
  return parseResponse(
    z.object({
      userId: z.string(),
      email: z.string(),
      orgName: z.string(),
      nextKeysetVersion: z.number().int(),
    }),
    await send(transport, {
      method: "POST",
      path: "/api/auth/recover/info",
      body: { token: recoveryToken },
    }),
  );
}

/**
 * ### recoverAccount
 *
 * Re-enrols an account with a recovery token: new password, new Secret Key and new keyset
 * under the same user id. Afterwards an admin must certify the new keys and complete the
 * recovery before the member's vaults come back. Personal data that only the lost keys could
 * open is gone, unless it lived in a vault the recovery key covers.
 *
 * @param transport Transport to the server
 * @param recoveryToken Token an admin handed over
 * @param password New account password
 * @returns The re-enrolled account, including the new Secret Key to save
 */
export async function recoverAccount(
  transport: Transport,
  recoveryToken: string,
  password: string,
): Promise<CreatedAccount & { email: string }> {
  const info = await recoveryInfo(transport, recoveryToken);
  const { created, payload } = await buildSignupPayload(
    { email: info.email, name: "", password },
    info.userId,
    info.nextKeysetVersion,
  );

  await send(transport, {
    method: "POST",
    path: "/api/auth/recover",
    body: {
      token: recoveryToken,
      accountId: payload.accountId,
      salt: payload.salt,
      kdf: payload.kdf,
      loginPublicKey: payload.loginPublicKey,
      keyset: payload.keyset,
    },
  });

  return { ...created, email: info.email };
}
