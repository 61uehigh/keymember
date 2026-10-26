import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";

/**
 * ### IdpAccount
 *
 * An account at the fake identity provider.
 */
export interface IdpAccount {
  readonly sub: string;
  readonly email: string;
  readonly hd?: string;
  readonly emailVerified?: boolean;
}

/**
 * ### FakeIdp
 *
 * A minimal OpenID Connect provider served through an injected `fetch`: discovery, JWKS, and a
 * token endpoint for the authorization-code (with PKCE) and refresh-token grants. Tests play
 * the browser by calling {@link FakeIdp.authorize}, and can suspend accounts or take the
 * provider down.
 */
export class FakeIdp {
  readonly issuer = "http://localhost:4499";
  readonly clientId = "keymember-test";
  readonly clientSecret = "test-client-secret";
  readonly #keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
  readonly #kid = randomUUID();
  readonly #codes = new Map<
    string,
    { account: IdpAccount; nonce: string; challenge: string }
  >();
  readonly #refreshTokens = new Map<string, IdpAccount>();
  readonly #suspended = new Set<string>();

  /**
   * ### down
   *
   * When set, the token endpoint answers 503.
   */
  down = false;

  /**
   * ### signWith
   *
   * Key that signs ID tokens; replace it to simulate a forged token.
   */
  signWith = this.#keys.privateKey;

  /**
   * ### config
   *
   * The server's SSO configuration for this provider.
   *
   * @param hostedDomain Workspace domain to require
   * @returns The configuration
   */
  config(hostedDomain?: string) {
    return {
      issuer: this.issuer,
      clientId: this.clientId,
      clientSecret: this.clientSecret,
      redirectUri: "http://keymember.test/api/auth/sso/callback",
      ...(hostedDomain === undefined ? {} : { hostedDomain }),
    };
  }

  /**
   * ### authorize
   *
   * Plays the user signing in at the authorization URL: returns the code the provider would
   * send back to the redirect URI.
   *
   * @param authorizationUrl URL the server redirected to
   * @param account Account the user signs in with
   * @returns State and code for the callback
   */
  authorize(
    authorizationUrl: string,
    account: IdpAccount,
  ): { state: string; code: string } {
    const params = new URL(authorizationUrl).searchParams;
    const code = randomUUID();

    if (params.get("code_challenge_method") !== "S256") {
      throw new Error("PKCE S256 expected");
    }

    this.#codes.set(code, {
      account,
      nonce: params.get("nonce") ?? "",
      challenge: params.get("code_challenge") ?? "",
    });

    return { state: params.get("state") ?? "", code };
  }

  /**
   * ### suspend
   *
   * Suspends an account: its refresh tokens stop working.
   *
   * @param sub Account subject
   */
  suspend(sub: string): void {
    this.#suspended.add(sub);
  }

  /**
   * ### fetch
   *
   * The provider's HTTP surface.
   *
   * @param input Request URL
   * @param init Request options
   * @returns The response
   */
  readonly fetch: typeof fetch = (input, init) =>
    Promise.resolve(this.#respond(input, init));

  /**
   * ### #respond
   *
   * Answers one request.
   *
   * @param input Request URL
   * @param init Request options
   * @returns The response
   */
  #respond(
    input: Parameters<typeof fetch>[0],
    init: RequestInit | undefined,
  ): Response {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const json = (body: unknown, status = 200): Response =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      });

    if (url.pathname === "/.well-known/openid-configuration") {
      return json({
        issuer: this.issuer,
        authorization_endpoint: `${this.issuer}/authorize`,
        token_endpoint: `${this.issuer}/token`,
        jwks_uri: `${this.issuer}/jwks`,
      });
    }

    if (url.pathname === "/jwks") {
      return json({
        keys: [
          {
            ...this.#keys.publicKey.export({ format: "jwk" }),
            kid: this.#kid,
            alg: "RS256",
            use: "sig",
          },
        ],
      });
    }

    if (url.pathname !== "/token") {
      return json({ error: "not_found" }, 404);
    }

    if (this.down) {
      return json({ error: "temporarily_unavailable" }, 503);
    }

    // The server sends its token requests as a urlencoded string
    const form = new URLSearchParams(
      typeof init?.body === "string" ? init.body : "",
    );

    if (
      form.get("client_id") !== this.clientId ||
      form.get("client_secret") !== this.clientSecret
    ) {
      return json({ error: "invalid_client" }, 401);
    }

    if (form.get("grant_type") === "refresh_token") {
      const account = this.#refreshTokens.get(form.get("refresh_token") ?? "");

      return account === undefined || this.#suspended.has(account.sub)
        ? json({ error: "invalid_grant" }, 400)
        : json({ access_token: "x", token_type: "Bearer" });
    }

    const grant = this.#codes.get(form.get("code") ?? "");

    this.#codes.delete(form.get("code") ?? "");

    const challenge = createHash("sha256")
      .update(form.get("code_verifier") ?? "")
      .digest("base64url");

    if (grant?.challenge !== challenge) {
      return json({ error: "invalid_grant" }, 400);
    }

    const refreshToken = randomUUID();

    this.#refreshTokens.set(refreshToken, grant.account);

    return json({
      access_token: "x",
      token_type: "Bearer",
      refresh_token: refreshToken,
      id_token: this.#idToken(grant.account, grant.nonce),
    });
  }

  /**
   * ### #idToken
   *
   * Signs an RS256 ID token.
   *
   * @param account Account
   * @param nonce Nonce from the authorization request
   * @returns The compact JWT
   */
  #idToken(account: IdpAccount, nonce: string): string {
    const now = Math.floor(Date.now() / 1000);
    const encode = (value: unknown): string =>
      Buffer.from(JSON.stringify(value)).toString("base64url");
    const signed = `${encode({ alg: "RS256", kid: this.#kid, typ: "JWT" })}.${encode(
      {
        iss: this.issuer,
        aud: this.clientId,
        sub: account.sub,
        email: account.email,
        email_verified: account.emailVerified ?? true,
        ...(account.hd === undefined ? {} : { hd: account.hd }),
        nonce,
        iat: now,
        exp: now + 3600,
      },
    )}`;

    return `${signed}.${sign("sha256", Buffer.from(signed), this.signWith).toString("base64url")}`;
  }
}
