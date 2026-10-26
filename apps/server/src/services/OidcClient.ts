import { createHash, createPublicKey, verify } from "node:crypto";
import type { KeyObject, webcrypto } from "node:crypto";

import { fromBase64Url, utf8Decode } from "@keymember/core";
import { z } from "zod";

/**
 * ### OidcConfig
 *
 * The organisation's OpenID Connect identity provider, normally Google Workspace.
 */
export interface OidcConfig {
  /**
   * ### issuer
   *
   * Issuer URL, e.g. `https://accounts.google.com`. Must be https except on localhost.
   */
  readonly issuer: string;

  /**
   * ### clientId
   *
   * OAuth client id registered with the provider.
   */
  readonly clientId: string;

  /**
   * ### clientSecret
   *
   * OAuth client secret. Server-only; never logged or returned.
   */
  readonly clientSecret: string;

  /**
   * ### redirectUri
   *
   * The server's callback URL, `<public url>/api/auth/sso/callback`, registered with the provider.
   */
  readonly redirectUri: string;

  /**
   * ### hostedDomain
   *
   * Google Workspace domain every account must belong to (the `hd` claim). Leave unset only
   * for providers that serve a single organisation.
   */
  readonly hostedDomain?: string | undefined;
}

/**
 * ### VerifiedIdentity
 *
 * Claims of an ID token that passed every check.
 */
export interface VerifiedIdentity {
  /**
   * ### subject
   *
   * Provider's stable user id (`sub`); unlike the email, it is never reassigned.
   */
  readonly subject: string;

  /**
   * ### email
   *
   * Verified email, lower-cased.
   */
  readonly email: string;
}

/**
 * ### RefreshOutcome
 *
 * Result of asking the provider whether an account is still active: `active`, `revoked` when
 * the provider refused the grant (account suspended, deleted or access withdrawn), or
 * `unavailable` when the provider could not be asked.
 */
export type RefreshOutcome =
  | { readonly status: "active"; readonly refreshToken: string | undefined }
  | { readonly status: "revoked" }
  | { readonly status: "unavailable" };

/**
 * ### OidcError
 *
 * The provider's answer failed a check; the login must not proceed.
 */
export class OidcError extends Error {
  override readonly name = "OidcError";
}

const discoverySchema = z.object({
  issuer: z.string(),
  authorization_endpoint: z.url(),
  token_endpoint: z.url(),
  jwks_uri: z.url(),
  revocation_endpoint: z.url().optional(),
});

const tokenResponseSchema = z.object({
  id_token: z.string().optional(),
  refresh_token: z.string().optional(),
});

const jwksSchema = z.object({
  keys: z.array(z.looseObject({ kid: z.string().optional() })),
});

const headerSchema = z.object({
  alg: z.enum(["RS256", "ES256"]),
  kid: z.string().optional(),
});

const claimsSchema = z.object({
  iss: z.string(),
  aud: z.union([z.string(), z.array(z.string())]),
  azp: z.string().optional(),
  sub: z.string().min(1),
  exp: z.number(),
  iat: z.number(),
  nonce: z.string().optional(),
  email: z.string().optional(),
  email_verified: z.boolean().optional(),
  hd: z.string().optional(),
});

const CLOCK_SKEW_SECONDS = 60;

/**
 * ### pkceChallenge
 *
 * The S256 code challenge for a PKCE verifier.
 *
 * @param verifier Code verifier
 * @returns The base64url SHA-256 of the verifier
 */
export function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

/**
 * ### OidcClient
 *
 * Authorization-code flow with PKCE against one provider, ID token verification against the
 * provider's published keys, and refresh-token checks that tell whether the account is still
 * active. Discovery and keys are fetched lazily and cached; an unknown key id triggers one refetch.
 */
export class OidcClient {
  readonly #config: OidcConfig;
  readonly #fetch: typeof fetch;
  #discovery: Promise<z.infer<typeof discoverySchema>> | undefined;
  #keys = new Map<string, KeyObject>();

  /**
   * ### constructor
   *
   * @param config Provider configuration
   * @param fetchImpl Fetch to use, injectable for tests
   */
  constructor(config: OidcConfig, fetchImpl: typeof fetch = fetch) {
    const issuer = new URL(config.issuer);
    const local =
      issuer.hostname === "localhost" || issuer.hostname === "127.0.0.1";

    if (issuer.protocol !== "https:" && !local) {
      throw new Error("The OIDC issuer must use https");
    }

    // Without hd, any Google account with a matching verified email would do, consumer ones included
    if (
      issuer.origin === "https://accounts.google.com" &&
      (config.hostedDomain === undefined || config.hostedDomain === "")
    ) {
      throw new Error(
        "Google sign-in needs the Workspace domain (KEYMEMBER_OIDC_HOSTED_DOMAIN)",
      );
    }

    this.#config = config;
    this.#fetch = fetchImpl;
  }

  /**
   * ### authorizationUrl
   *
   * Builds the provider URL the user's browser is sent to. Offline access is requested so the
   * server can keep checking the account on every keymember token refresh.
   *
   * @param input Per-request values bound into the flow
   * @returns The URL to redirect to
   */
  async authorizationUrl(input: {
    state: string;
    nonce: string;
    codeVerifier: string;
    loginHint: string;
  }): Promise<string> {
    const discovery = await this.#discover();
    const url = new URL(discovery.authorization_endpoint);
    const google = discovery.issuer === "https://accounts.google.com";

    url.search = new URLSearchParams({
      response_type: "code",
      client_id: this.#config.clientId,
      redirect_uri: this.#config.redirectUri,
      scope: google ? "openid email" : "openid email offline_access",
      state: input.state,
      nonce: input.nonce,
      code_challenge: pkceChallenge(input.codeVerifier),
      code_challenge_method: "S256",
      login_hint: input.loginHint,
      // Google issues a refresh token only with offline access and a fresh consent
      ...(google ? { access_type: "offline", prompt: "consent" } : {}),
      ...(this.#config.hostedDomain === undefined
        ? {}
        : { hd: this.#config.hostedDomain }),
    }).toString();

    return url.toString();
  }

  /**
   * ### exchangeCode
   *
   * Redeems an authorization code and verifies the ID token that comes with it.
   *
   * @param code Code from the callback
   * @param codeVerifier PKCE verifier of the flow
   * @param nonce Nonce the ID token must carry
   * @returns The verified identity and the refresh token for later checks
   */
  async exchangeCode(
    code: string,
    codeVerifier: string,
    nonce: string,
  ): Promise<{ identity: VerifiedIdentity; refreshToken: string }> {
    const response = await this.#token({
      grant_type: "authorization_code",
      code,
      code_verifier: codeVerifier,
      redirect_uri: this.#config.redirectUri,
    });

    if (!response.ok) {
      throw new OidcError(
        `Token endpoint refused the code (${String(response.status)})`,
      );
    }

    const body = tokenResponseSchema.parse(await response.json());

    if (body.id_token === undefined) {
      throw new OidcError("The provider returned no ID token");
    }

    if (body.refresh_token === undefined) {
      throw new OidcError(
        "The provider granted no offline access; keymember cannot re-check the account later",
      );
    }

    return {
      identity: await this.verifyIdToken(body.id_token, nonce),
      refreshToken: body.refresh_token,
    };
  }

  /**
   * ### checkAccount
   *
   * Uses a stored refresh token to ask the provider whether the account is still active.
   *
   * @param refreshToken Provider refresh token
   * @returns Whether the account is active, revoked, or the provider was unreachable
   */
  async checkAccount(refreshToken: string): Promise<RefreshOutcome> {
    let response: Response;

    try {
      response = await this.#token({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      });
    } catch {
      // Network failure: the caller decides how long it tolerates not knowing
      return { status: "unavailable" };
    }

    if (response.ok) {
      const body = tokenResponseSchema.safeParse(await response.json());

      return {
        status: "active",
        refreshToken: body.success ? body.data.refresh_token : undefined,
      };
    }

    const error = z
      .object({ error: z.string() })
      .safeParse(await response.json().catch(() => undefined));

    return error.success && error.data.error === "invalid_grant"
      ? { status: "revoked" }
      : { status: "unavailable" };
  }

  /**
   * ### revoke
   *
   * Asks the provider to revoke a refresh token. Best effort: logout must not fail because the
   * provider is unreachable or has no revocation endpoint.
   *
   * @param refreshToken Provider refresh token
   */
  async revoke(refreshToken: string): Promise<void> {
    try {
      const endpoint = (await this.#discover()).revocation_endpoint;

      if (endpoint !== undefined) {
        await this.#fetch(endpoint, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            token: refreshToken,
            token_type_hint: "refresh_token",
            client_id: this.#config.clientId,
            client_secret: this.#config.clientSecret,
          }).toString(),
        });
      }
    } catch {
      // The token stays usable at the provider until it expires; keymember has forgotten it either way
    }
  }

  /**
   * ### verifyIdToken
   *
   * Verifies an ID token's signature against the provider's keys and checks issuer, audience,
   * expiry, nonce, verified email and hosted domain.
   *
   * @param token Compact JWT
   * @param nonce Expected nonce
   * @returns The verified identity
   */
  async verifyIdToken(token: string, nonce: string): Promise<VerifiedIdentity> {
    const parts = token.split(".");
    const [headerPart = "", payloadPart = "", signaturePart = ""] = parts;
    const decode = (part: string): unknown => {
      const bytes = fromBase64Url(part);

      if (bytes === undefined) {
        throw new OidcError("Malformed ID token");
      }

      try {
        return JSON.parse(utf8Decode(bytes));
      } catch (error) {
        throw new OidcError("Malformed ID token", { cause: error });
      }
    };

    if (parts.length !== 3) {
      throw new OidcError("Malformed ID token");
    }

    const header = headerSchema.safeParse(decode(headerPart));
    const claims = claimsSchema.safeParse(decode(payloadPart));
    const signature = fromBase64Url(signaturePart);

    if (!header.success || !claims.success || signature === undefined) {
      throw new OidcError("Malformed ID token");
    }

    const key = await this.#key(header.data.kid);
    const signed = Buffer.from(`${headerPart}.${payloadPart}`);
    const valid =
      header.data.alg === "RS256"
        ? key.asymmetricKeyType === "rsa" &&
          verify("sha256", signed, key, signature)
        : key.asymmetricKeyType === "ec" &&
          verify(
            "sha256",
            signed,
            { key, dsaEncoding: "ieee-p1363" },
            signature,
          );

    if (!valid) {
      throw new OidcError("ID token signature does not verify");
    }

    const c = claims.data;
    const discovery = await this.#discover();
    const audiences = typeof c.aud === "string" ? [c.aud] : c.aud;
    const now = Date.now() / 1000;

    if (
      c.iss !== discovery.issuer ||
      !audiences.includes(this.#config.clientId) ||
      (audiences.length > 1 && c.azp !== this.#config.clientId) ||
      c.exp + CLOCK_SKEW_SECONDS < now ||
      c.iat - CLOCK_SKEW_SECONDS > now ||
      c.nonce !== nonce
    ) {
      throw new OidcError("ID token is not meant for this login");
    }

    if (c.email === undefined || c.email_verified !== true) {
      throw new OidcError("The provider did not vouch for an email address");
    }

    if (
      this.#config.hostedDomain !== undefined &&
      c.hd !== this.#config.hostedDomain
    ) {
      throw new OidcError("The account is outside the organisation's domain");
    }

    return { subject: c.sub, email: c.email.toLowerCase() };
  }

  /**
   * ### #discover
   *
   * Fetches and caches the provider's discovery document; a failed fetch is retried next time.
   *
   * @returns The discovery document
   */
  async #discover(): Promise<z.infer<typeof discoverySchema>> {
    this.#discovery ??= (async () => {
      const response = await this.#fetch(
        `${this.#config.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`,
      );

      if (!response.ok) {
        throw new OidcError("Could not read the provider's configuration");
      }

      const document = discoverySchema.parse(await response.json());

      if (
        document.issuer.replace(/\/$/, "") !==
        this.#config.issuer.replace(/\/$/, "")
      ) {
        throw new OidcError("Provider configuration names another issuer");
      }

      return document;
    })().catch((error: unknown) => {
      this.#discovery = undefined;

      throw error;
    });

    return this.#discovery;
  }

  /**
   * ### #key
   *
   * Finds a signing key by id, refetching the key set once when the id is unknown (rotation).
   *
   * @param kid Key id from the token header
   * @returns The public key
   */
  async #key(kid: string | undefined): Promise<KeyObject> {
    const cached = this.#keys.get(kid ?? "");

    if (cached !== undefined) {
      return cached;
    }

    const response = await this.#fetch((await this.#discover()).jwks_uri);

    if (!response.ok) {
      throw new OidcError("Could not read the provider's signing keys");
    }

    const keys = new Map<string, KeyObject>();

    for (const jwk of jwksSchema.parse(await response.json()).keys) {
      try {
        // The key set is validated as JSON objects; createPublicKey checks the key material itself
        keys.set(
          jwk.kid ?? "",
          createPublicKey({ key: jwk as webcrypto.JsonWebKey, format: "jwk" }),
        );
      } catch {
        // Keys of types this server does not use are skipped, not fatal
      }
    }

    this.#keys = keys;

    const key = keys.get(kid ?? "");

    if (key === undefined) {
      throw new OidcError("ID token was signed with an unknown key");
    }

    return key;
  }

  /**
   * ### #token
   *
   * Calls the token endpoint with client credentials.
   *
   * @param params Grant parameters
   * @returns The raw response
   */
  async #token(params: Record<string, string>): Promise<Response> {
    return this.#fetch((await this.#discover()).token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        ...params,
        client_id: this.#config.clientId,
        client_secret: this.#config.clientSecret,
      }).toString(),
    });
  }
}
