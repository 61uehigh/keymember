/**
 * Runs in the page's own JavaScript world (MAIN) at document start and routes WebAuthn calls
 * to keymember. Everything here is visible to and modifiable by the page, so it holds no
 * secret and makes no security decision: the background derives the origin from the browser
 * and checks the relying party id itself. Anything keymember declines goes to the browser's
 * native implementation.
 */

import { isRecord } from "../shared/records.js";

/**
 * ### ContentReply
 *
 * keymember's answer to one WebAuthn call, relayed by the content script.
 */
interface ContentReply {
  readonly source: "keymember-content";
  readonly id: string;
  readonly outcome: "credential" | "fallback" | "error";
  readonly credential?: Record<string, string | number | Array<string>>;
  readonly name?: string;
  readonly message?: string;
}

/**
 * ### isContentReply
 *
 * Whether a window message is a well-formed reply from keymember's content script. The page
 * can post anything; a malformed reply is ignored rather than trusted.
 *
 * @param data Message data
 * @returns Whether it is a reply
 */
function isContentReply(data: unknown): data is ContentReply {
  return (
    isRecord(data) &&
    data.source === "keymember-content" &&
    typeof data.id === "string" &&
    (data.outcome === "credential" ||
      data.outcome === "fallback" ||
      data.outcome === "error") &&
    (data.credential === undefined || isRecord(data.credential)) &&
    (data.name === undefined || typeof data.name === "string") &&
    (data.message === undefined || typeof data.message === "string")
  );
}

(() => {
  // Missing in insecure contexts, which the DOM types do not model
  const credentials = navigator.credentials as CredentialsContainer | undefined;

  if (credentials === undefined || typeof PublicKeyCredential === "undefined") {
    return;
  }

  const nativeCreate = credentials.create.bind(credentials);
  const nativeGet = credentials.get.bind(credentials);
  const waiting = new Map<string, (reply: ContentReply) => void>();

  window.addEventListener("message", (event: MessageEvent<unknown>) => {
    const data: unknown = event.data;

    if (event.source !== window || !isContentReply(data)) {
      return;
    }

    waiting.get(data.id)?.(data);
    waiting.delete(data.id);
  });

  const toB64 = (value: BufferSource): string => {
    const bytes =
      value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    let binary = "";

    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }

    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  };

  const fromB64 = (text: string): ArrayBuffer => {
    const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));

    return Uint8Array.from(binary, (char) => char.charCodeAt(0)).buffer;
  };

  const ask = (
    kind: "create" | "get" | "get-conditional",
    options: unknown,
    signal: AbortSignal | undefined,
  ): Promise<ContentReply> =>
    new Promise((resolve, reject) => {
      const id = crypto.randomUUID();

      waiting.set(id, resolve);
      signal?.addEventListener("abort", () => {
        waiting.delete(id);
        // An autofill request may be parked in keymember; tell it the page gave up
        window.postMessage(
          { source: "keymember-page", id, kind: "cancel" },
          window.location.origin,
        );
        reject(new DOMException("The operation was aborted.", "AbortError"));
      });
      window.postMessage(
        { source: "keymember-page", id, kind, options },
        window.location.origin,
      );
    });

  const text = (record: Record<string, unknown>, key: string): string => {
    const value = record[key];

    return typeof value === "string" ? value : "";
  };

  /**
   * Builds an object that passes `instanceof` checks: own properties shadow the prototype's
   * native getters, which would throw on a non-native object.
   */
  const credentialFrom = (
    credential: Record<string, unknown>,
    response: object,
    json: unknown,
  ): PublicKeyCredential =>
    Object.create(PublicKeyCredential.prototype, {
      id: { value: text(credential, "id"), enumerable: true },
      rawId: { value: fromB64(text(credential, "rawId")), enumerable: true },
      type: { value: "public-key", enumerable: true },
      authenticatorAttachment: { value: "platform", enumerable: true },
      response: { value: response, enumerable: true },
      getClientExtensionResults: { value: () => ({}) },
      toJSON: { value: () => json },
      // Built to look like the browser's own credential; pages only read these properties
    }) as PublicKeyCredential;

  credentials.create = async (
    options?: CredentialCreationOptions,
  ): Promise<Credential | null> => {
    const publicKey = options?.publicKey;

    if (publicKey === undefined) {
      return nativeCreate(options);
    }

    const reply = await ask(
      "create",
      {
        rp: {
          name: publicKey.rp.name,
          ...(publicKey.rp.id === undefined ? {} : { id: publicKey.rp.id }),
        },
        user: {
          id: toB64(publicKey.user.id),
          name: publicKey.user.name,
          displayName: publicKey.user.displayName,
        },
        challenge: toB64(publicKey.challenge),
        pubKeyCredParams: publicKey.pubKeyCredParams.map((param) => ({
          type: param.type,
          alg: param.alg,
        })),
        excludeCredentials: (publicKey.excludeCredentials ?? []).map(
          (entry) => ({ id: toB64(entry.id) }),
        ),
        ...(publicKey.authenticatorSelection?.userVerification === undefined
          ? {}
          : {
              userVerification:
                publicKey.authenticatorSelection.userVerification,
            }),
        ...(publicKey.timeout === undefined
          ? {}
          : { timeout: publicKey.timeout }),
      },
      options?.signal ?? undefined,
    );

    if (reply.outcome === "fallback") {
      return nativeCreate(options);
    }

    if (reply.outcome === "error" || reply.credential === undefined) {
      throw new DOMException(
        reply.message ?? "The operation failed.",
        reply.name ?? "NotAllowedError",
      );
    }

    const c = reply.credential;
    const response = Object.create(AuthenticatorAttestationResponse.prototype, {
      clientDataJSON: {
        value: fromB64(text(c, "clientDataJSON")),
        enumerable: true,
      },
      attestationObject: {
        value: fromB64(text(c, "attestationObject")),
        enumerable: true,
      },
      getTransports: { value: () => ["internal", "hybrid"] },
      getAuthenticatorData: {
        value: () => fromB64(text(c, "authenticatorData")),
      },
      getPublicKey: { value: () => fromB64(text(c, "publicKey")) },
      getPublicKeyAlgorithm: { value: () => c.publicKeyAlgorithm },
      // A plain object standing in for the browser's response type, which has no constructor
    }) as object;

    return credentialFrom(c, response, {
      id: c.id,
      rawId: c.rawId,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: c.clientDataJSON,
        attestationObject: c.attestationObject,
        authenticatorData: c.authenticatorData,
        transports: ["internal", "hybrid"],
        publicKey: c.publicKey,
        publicKeyAlgorithm: c.publicKeyAlgorithm,
      },
    });
  };

  credentials.get = async (
    options?: CredentialRequestOptions,
  ): Promise<Credential | null> => {
    const publicKey = options?.publicKey;

    if (publicKey === undefined) {
      return nativeGet(options);
    }

    // Autofill requests wait until the user picks a passkey in keymember's inline menu, or go
    // back to the browser when keymember has none for this site
    const reply = await ask(
      options?.mediation === "conditional" ? "get-conditional" : "get",
      {
        challenge: toB64(publicKey.challenge),
        allowCredentials: (publicKey.allowCredentials ?? []).map((entry) => ({
          id: toB64(entry.id),
        })),
        ...(publicKey.rpId === undefined ? {} : { rpId: publicKey.rpId }),
        ...(publicKey.userVerification === undefined
          ? {}
          : { userVerification: publicKey.userVerification }),
        ...(publicKey.timeout === undefined
          ? {}
          : { timeout: publicKey.timeout }),
      },
      options?.signal ?? undefined,
    );

    if (reply.outcome === "fallback") {
      return nativeGet(options);
    }

    if (reply.outcome === "error" || reply.credential === undefined) {
      throw new DOMException(
        reply.message ?? "The operation failed.",
        reply.name ?? "NotAllowedError",
      );
    }

    const c = reply.credential;
    const response = Object.create(AuthenticatorAssertionResponse.prototype, {
      clientDataJSON: {
        value: fromB64(text(c, "clientDataJSON")),
        enumerable: true,
      },
      authenticatorData: {
        value: fromB64(text(c, "authenticatorData")),
        enumerable: true,
      },
      signature: { value: fromB64(text(c, "signature")), enumerable: true },
      userHandle: { value: fromB64(text(c, "userHandle")), enumerable: true },
      // A plain object standing in for the browser's response type, which has no constructor
    }) as object;

    return credentialFrom(c, response, {
      id: c.id,
      rawId: c.rawId,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: c.clientDataJSON,
        authenticatorData: c.authenticatorData,
        signature: c.signature,
        userHandle: c.userHandle,
      },
    });
  };
})();
