import { assertPasskey, createPasskey } from "@keymember/client";
import type { WebAuthnContext } from "@keymember/client";
import { fromBase64Url, toBase64Url } from "@keymember/core";
import type { StoredPasskey } from "@keymember/core";

import type {
  PasskeyContentRequest,
  PasskeyDecision,
  PasskeyReply,
} from "../../shared/messages.js";
import type { PasskeyStore } from "../PasskeyStore.js";
import type { Vault } from "../Vault.js";
import { errorReply } from "./replies.js";

/**
 * ### assertionReply
 *
 * Signs a sign-in challenge with a stored passkey and wraps the result for the page.
 *
 * @param passkey Passkey to sign with
 * @param context Origin, relying party, challenge and whether the user was verified
 * @returns The credential reply
 */
export function assertionReply(
  passkey: StoredPasskey,
  context: WebAuthnContext,
): PasskeyReply {
  const assertion = assertPasskey(passkey, context);

  return {
    outcome: "credential",
    credential: {
      id: passkey.credentialId,
      rawId: passkey.credentialId,
      clientDataJSON: toBase64Url(assertion.clientDataJSON),
      authenticatorData: toBase64Url(assertion.authenticatorData),
      signature: toBase64Url(assertion.signature),
      userHandle: toBase64Url(assertion.userHandle),
    },
  };
}

/**
 * ### PasskeyCeremony
 *
 * Carries out what the user chose in the consent window: creates and stores a passkey, or signs
 * in with one, claiming user verification only when the password was entered during the request.
 */
export class PasskeyCeremony {
  readonly #vault: Pick<Vault, "unlockCount">;
  readonly #passkeys: Pick<
    PasskeyStore,
    "findPasskey" | "passkeyCandidates" | "storePasskey"
  >;

  /**
   * ### constructor
   *
   * @param vault How many times the user has unlocked
   * @param passkeys Stored passkeys
   */
  constructor(
    vault: Pick<Vault, "unlockCount">,
    passkeys: Pick<
      PasskeyStore,
      "findPasskey" | "passkeyCandidates" | "storePasskey"
    >,
  ) {
    this.#vault = vault;
    this.#passkeys = passkeys;
  }

  /**
   * ### complete
   *
   * Carries out the user's decision.
   *
   * @param request Original request
   * @param origin Requesting origin
   * @param rpId Validated relying party id
   * @param decision The user's choice
   * @param unlocksAtStart Unlock count when the request arrived
   * @returns The reply for the page script
   */
  async complete(
    request: PasskeyContentRequest,
    origin: string,
    rpId: string,
    decision: PasskeyDecision,
    unlocksAtStart: number,
  ): Promise<PasskeyReply> {
    if (decision.action === "fallback") {
      return { outcome: "fallback" };
    }

    if (decision.action === "cancel") {
      return errorReply("NotAllowedError", "The user cancelled the request.");
    }

    // The UV flag is claimed only when the password was entered during this ceremony
    const userVerified =
      ((await this.#vault.unlockCount()) ?? 0) > unlocksAtStart;

    if (request.options.userVerification === "required" && !userVerified) {
      return errorReply(
        "NotAllowedError",
        "User verification was required but not performed.",
      );
    }

    const challenge = fromBase64Url(request.options.challenge);

    if (challenge === undefined) {
      return errorReply("TypeError", "Malformed challenge.");
    }

    const context = { origin, rpId, challenge, userVerified };

    if (request.type === "passkey-create" && decision.action === "create") {
      return this.#create(request, decision, context);
    }

    if (request.type === "passkey-get" && decision.action === "use") {
      const allow = request.options.allowCredentials.map((entry) => entry.id);
      const passkey = await this.#passkeys.findPasskey(
        decision.itemId,
        decision.credentialId,
      );

      // The window can only choose among what this request allows, for this relying party
      if (
        passkey?.rpId !== rpId ||
        (allow.length > 0 && !allow.includes(passkey.credentialId))
      ) {
        return errorReply(
          "NotAllowedError",
          "That passkey cannot answer this request.",
        );
      }

      return assertionReply(passkey, context);
    }

    return errorReply(
      "NotAllowedError",
      "The choice does not match the request.",
    );
  }

  /**
   * ### #create
   *
   * Creates a passkey for a registration and stores it where the user chose.
   *
   * @param request Registration request
   * @param decision The user's choice of item or vault
   * @param context Origin, relying party, challenge and verification
   * @returns The reply for the page script
   */
  async #create(
    request: Extract<PasskeyContentRequest, { type: "passkey-create" }>,
    decision: Extract<PasskeyDecision, { action: "create" }>,
    context: WebAuthnContext,
  ): Promise<PasskeyReply> {
    const excluded = request.options.excludeCredentials.map(
      (entry) => entry.id,
    );

    if (
      excluded.length > 0 &&
      (await this.#passkeys.passkeyCandidates(context.rpId, excluded)).length >
        0
    ) {
      return errorReply(
        "InvalidStateError",
        "A keymember passkey for this account already exists.",
      );
    }

    const userId = fromBase64Url(request.options.user.id);

    if (userId === undefined) {
      return errorReply("TypeError", "Malformed user id.");
    }

    const { passkey, credential } = createPasskey(context, {
      id: userId,
      name: request.options.user.name,
      displayName: request.options.user.displayName,
    });

    await this.#passkeys.storePasskey(passkey, context.origin, {
      ...(decision.itemId === undefined ? {} : { itemId: decision.itemId }),
      ...(decision.vaultId === undefined ? {} : { vaultId: decision.vaultId }),
    });

    return {
      outcome: "credential",
      credential: {
        id: passkey.credentialId,
        rawId: passkey.credentialId,
        clientDataJSON: toBase64Url(credential.clientDataJSON),
        attestationObject: toBase64Url(credential.attestationObject),
        authenticatorData: toBase64Url(credential.authenticatorData),
        publicKey: toBase64Url(credential.publicKey),
        publicKeyAlgorithm: credential.publicKeyAlgorithm,
      },
    };
  }
}
