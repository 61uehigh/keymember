import { signTrustedRoots, verifyTrustedRoots } from "@keymember/core";
import type { SigningKeyPair, TrustedRoots } from "@keymember/core";
import { z } from "zod";

import { b64, encode, parseResponse } from "../schemas.js";
import { ApiError } from "../transport.js";
import type { AuthorizedRequest } from "./AuthorizedApi.js";
import type { TrustContext } from "./TrustContext.js";

/**
 * ### trustedRootsSchema
 *
 * Trusted roots as the server returns them.
 */
const trustedRootsSchema = z.object({
  statement: z.object({
    userId: z.string(),
    orgId: z.string(),
    issuedAt: z.number().int(),
    roots: z.array(z.object({ userId: z.string(), signingPublicKey: b64 })),
  }),
  signature: b64,
});

/**
 * ### TrustedRootsStore
 *
 * Keeps the user's trusted roots on the server, signed with their own key, so every device of
 * the user can adopt them without a fingerprint check. A device trusts them only after
 * verifying that signature with the key from the user's own unlocked key set, which the server
 * cannot forge.
 */
export class TrustedRootsStore {
  readonly #request: AuthorizedRequest;
  readonly #trust: Pick<TrustContext, "fetchOrg" | "roots">;
  readonly #userId: string;
  readonly #signing: SigningKeyPair;

  /**
   * ### constructor
   *
   * @param request Authenticated requests to the server
   * @param trust The session's pinned roots and organisation
   * @param userId Logged-in user
   * @param signing The user's signing key pair
   */
  constructor(
    request: AuthorizedRequest,
    trust: Pick<TrustContext, "fetchOrg" | "roots">,
    userId: string,
    signing: SigningKeyPair,
  ) {
    this.#request = request;
    this.#trust = trust;
    this.#userId = userId;
    this.#signing = signing;
  }

  /**
   * ### save
   *
   * Signs the roots this session trusts and stores them for the user's other devices.
   */
  async save(): Promise<void> {
    const roots = this.#trust.roots();

    if (roots.size === 0) {
      throw new Error(
        "There are no trusted roots to save. Verify the owner's key first.",
      );
    }

    const org = await this.#trust.fetchOrg();
    const trusted: TrustedRoots = {
      userId: this.#userId,
      orgId: org.org.id,
      issuedAt: Math.floor(Date.now() / 1000),
      roots: [...roots].map(([userId, signingPublicKey]) => ({
        userId,
        signingPublicKey,
      })),
    };

    await this.#request({
      method: "PUT",
      path: "/api/account/trusted-roots",
      body: {
        statement: {
          ...trusted,
          roots: trusted.roots.map((root) => ({
            userId: root.userId,
            signingPublicKey: encode(root.signingPublicKey),
          })),
        },
        signature: encode(signTrustedRoots(this.#signing.privateKey, trusted)),
      },
    });
  }

  /**
   * ### load
   *
   * Reads the roots the user saved from another device.
   *
   * @returns The roots by user id, or `undefined` when none are saved or they do not carry this
   * user's signature for this organisation, in which case the device asks for a fingerprint
   */
  async load(): Promise<ReadonlyMap<string, Uint8Array> | undefined> {
    let response: unknown;

    try {
      response = await this.#request({
        method: "GET",
        path: "/api/account/trusted-roots",
      });
    } catch (error) {
      if (error instanceof ApiError && error.code === "not_found") {
        return undefined;
      }

      throw error;
    }

    const { statement, signature } = parseResponse(
      trustedRootsSchema,
      response,
    );
    const org = await this.#trust.fetchOrg();

    if (
      statement.userId !== this.#userId ||
      statement.orgId !== org.org.id ||
      !verifyTrustedRoots(this.#signing.publicKey, statement, signature)
    ) {
      return undefined;
    }

    return new Map(
      statement.roots.map((root) => [root.userId, root.signingPublicKey]),
    );
  }
}
