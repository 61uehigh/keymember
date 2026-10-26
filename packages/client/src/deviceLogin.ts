import { formatSecretKey, parseSecretKey } from "@keymember/core";

import { logIn } from "./account.js";
import type { Session } from "./Session.js";
import { SsoRequiredError } from "./sso.js";
import type { SsoHandler } from "./sso.js";
import { ApiError, fetchTransport } from "./transport.js";

const MESSAGES: Readonly<Record<string, string>> = {
  invalid_credentials: "The email, password or Secret Key is incorrect.",
  invalid_totp: "The two-factor code is incorrect or has already been used.",
  totp_enrollment_required:
    "Your organization requires two-factor authentication. Set it up in the Account menu first.",
  rate_limited: "Too many attempts. Wait a moment and try again.",
  not_confirmed:
    "Waiting for an admin to verify you. You'll be verified automatically the next time the admin who invited you opens keymember, and vaults shared with you will appear then.",
  revision_conflict: "Someone else changed this first. Refresh and try again.",
  unauthorized: "Your session has ended. Unlock again.",
  bootstrap_token_invalid:
    "The bootstrap token is missing or wrong. Check the server log or the KEYMEMBER_BOOTSTRAP_TOKEN setting.",
  membership_ended:
    "Your membership in this organization is suspended or being recovered. Contact an admin.",
  sso_required:
    "Your organization requires you to verify with your company account.",
  sso_revoked: "Your company account verification was revoked. Log in again.",
  sso_failed: "Couldn't verify your company account. Try again.",
  sso_expired: "Company account verification timed out. Try again.",
  sso_unavailable: "Company account login isn't set up on this server.",
  sso_not_linked: "This account isn't linked to a company account yet.",
  share_unavailable: "This share link has expired or can't be opened again.",
  share_denied: "The share link's access password is incorrect.",
};

/**
 * ### describeError
 *
 * Turns any failure into a message for the user. Server error codes get a Korean message;
 * anything else shows its own message, which the SDK writes to be user-presentable.
 *
 * @param error Caught value
 * @returns Message to display
 */
export function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    return MESSAGES[error.code] ?? error.message;
  }

  return error instanceof Error ? error.message : String(error);
}

/**
 * ### UnlockResult
 *
 * Outcome of an unlock attempt as an app shows it.
 */
export type UnlockResult =
  | { readonly ok: true; readonly recoveryCancelled: boolean }
  | { readonly ok: false; readonly code: string; readonly message: string };

/**
 * ### DeviceLogin
 *
 * A device login that worked, with what the device should remember, or why it failed.
 */
export type DeviceLogin =
  | {
      readonly ok: true;
      readonly session: Session;
      /** Normalised email to remember */
      readonly email: string;
      /** Formatted Secret Key to remember */
      readonly secretKey: string;
    }
  | Extract<UnlockResult, { ok: false }>;

/**
 * ### logInDevice
 *
 * Logs an app in on this device: picks the Secret Key the user typed or the one the device
 * remembers, normalises the email, opens the identity provider when the organisation asks
 * for it, and turns every failure into a code and a message for the user.
 *
 * @param device Server, device and the remembered Secret Key
 * @param input What the user typed
 * @param sso How the user reaches the identity provider: a function that opens its page at a
 * URL, or a full {@link SsoHandler} for apps that show their own prompt (the web vault)
 * @returns The session and what to remember, or a coded failure such as `totp_required`
 */
export async function logInDevice(
  device: {
    serverUrl: string | undefined;
    deviceId: string;
    deviceName: string;
    storedSecretKey?: string | undefined;
  },
  input: {
    email: string;
    password: string;
    secretKey?: string | undefined;
    totp?: string | undefined;
  },
  sso: ((url: string) => void | Promise<void>) | SsoHandler,
): Promise<DeviceLogin> {
  const { serverUrl } = device;
  const secretKey = parseSecretKey(
    input.secretKey ?? device.storedSecretKey ?? "",
  );

  if (serverUrl === undefined) {
    return {
      ok: false,
      code: "not_configured",
      message: "Set the server address first.",
    };
  }

  if (secretKey === undefined) {
    return {
      ok: false,
      code: "secret_key",
      message:
        "That Secret Key isn't in the right format. Check the value in your Emergency Kit.",
    };
  }

  try {
    const email = input.email.trim().toLowerCase();
    const totp = input.totp?.trim() ?? "";
    const session = await logIn(fetchTransport(serverUrl), {
      email,
      password: input.password,
      secretKey,
      deviceId: device.deviceId,
      deviceName: device.deviceName,
      ...(totp === "" ? {} : { totp }),
      sso:
        typeof sso === "function"
          ? {
              onChallenge: async ({ path }) => {
                await sso(new URL(path, serverUrl).toString());
              },
            }
          : sso,
    });

    return { ok: true, session, email, secretKey: formatSecretKey(secretKey) };
  } catch (error) {
    if (error instanceof ApiError) {
      return { ok: false, code: error.code, message: describeError(error) };
    }

    if (error instanceof SsoRequiredError) {
      return { ok: false, code: "sso_required", message: error.message };
    }

    return { ok: false, code: "error", message: describeError(error) };
  }
}

/**
 * ### confirmOwnerKey
 *
 * Fetches the owner's key again and returns it only when its fingerprint is the one the user
 * compared, so a server that serves a different key between showing and pinning gets nothing
 * pinned.
 *
 * @param session Unlocked session
 * @param userId Owner the user confirmed
 * @param fingerprint Fingerprint the user compared with the owner
 * @returns The owner's signing public key, to pin
 */
export async function confirmOwnerKey(
  session: Pick<Session, "ownerCandidates">,
  userId: string,
  fingerprint: string,
): Promise<Uint8Array> {
  const owner = (await session.ownerCandidates()).find(
    (candidate) => candidate.userId === userId,
  );

  if (owner?.fingerprint !== fingerprint) {
    throw new Error(
      "The owner's key changed after you compared it. Compare the fingerprint again.",
    );
  }

  return owner.signingPublicKey;
}
