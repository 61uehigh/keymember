import fastifyStatic from "@fastify/static";
import Fastify from "fastify";
import type { FastifyInstance, FastifyRequest } from "fastify";

import { symmetricKeyFromBytes, utf8Encode } from "@keymember/core";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import type { AppContext } from "./http/AppContext.js";
import { DomainError } from "./domain/DomainError.js";
import type { ErrorKind } from "./domain/DomainError.js";
import { DuplicateKeyError } from "./repositories/DuplicateKeyError.js";
import type { Store } from "./repositories/Store.js";
import { registerAccountRoutes } from "./routes/accountRoutes.js";
import { registerAuthRoutes } from "./routes/authRoutes.js";
import { registerGroupRoutes } from "./routes/groupRoutes.js";
import { registerItemRoutes } from "./routes/itemRoutes.js";
import { registerOrgRoutes } from "./routes/orgRoutes.js";
import { registerRecoveryRoutes } from "./routes/recoveryRoutes.js";
import { registerShareRoutes } from "./routes/shareRoutes.js";
import { registerSsoRoutes } from "./routes/ssoRoutes.js";
import { registerSyncRoutes } from "./routes/syncRoutes.js";
import { registerVaultRoutes } from "./routes/vaultRoutes.js";
import { createAuthLimits } from "./services/auth/AuthLimits.js";
import { OidcClient } from "./services/OidcClient.js";
import type { OidcConfig } from "./services/OidcClient.js";

/**
 * ### STATUS_OF_KIND
 *
 * The HTTP status each kind of domain failure is reported with.
 */
const STATUS_OF_KIND: Readonly<Record<ErrorKind, number>> = {
  invalid: 400,
  unauthenticated: 401,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  gone: 410,
  rate_limited: 429,
  unavailable: 503,
};

/**
 * ### serializeRequest
 *
 * How a request appears in the log: without query values, which carry SSO codes, tickets and
 * other one-time secrets.
 *
 * @param request Request being logged
 * @returns The fields to log
 */
function serializeRequest(request: FastifyRequest): Record<string, unknown> {
  return {
    method: request.method,
    url: redactQuery(request.url),
    remoteAddress: request.ip,
  };
}

/**
 * ### redactQuery
 *
 * A URL with every query value replaced, keeping the names for debugging.
 *
 * @param url Path and query of a request
 * @returns The URL without query values
 */
export function redactQuery(url: string): string {
  const start = url.indexOf("?");

  if (start === -1) {
    return url;
  }

  const names = url
    .slice(start + 1)
    .split("&")
    .map((pair) => `${pair.split("=")[0] ?? ""}=[redacted]`);

  return `${url.slice(0, start)}?${names.join("&")}`;
}

/**
 * ### warnOnUntrustedProxy
 *
 * Logs once when requests carry `X-Forwarded-For` but the server does not read it: behind a
 * proxy every client then shares the proxy's address, in audit records and in the per-address
 * login limit.
 *
 * @param app Application to watch
 */
function warnOnUntrustedProxy(app: FastifyInstance): void {
  let warned = false;

  app.addHook("onRequest", (request, _reply, done) => {
    if (!warned && request.headers["x-forwarded-for"] !== undefined) {
      warned = true;
      request.log.warn(
        "Requests carry X-Forwarded-For but KEYMEMBER_TRUST_PROXY is not set; every client is seen as the proxy's address",
      );
    }

    done();
  });
}

/**
 * ### AppOptions
 *
 * Inputs for {@link buildApp}.
 */
export interface AppOptions {
  /**
   * ### store
   *
   * Where the server keeps its data, ready to use. The app does not own it; the caller closes
   * whatever is behind it.
   */
  readonly store: Store;

  /**
   * ### serverSecret
   *
   * At least 32 random bytes, kept stable across restarts.
   */
  readonly serverSecret: Uint8Array;

  /**
   * ### now
   *
   * Clock override for tests.
   *
   * @defaultValue `() => new Date()` — the system clock
   */
  readonly now?: () => Date;

  /**
   * ### trustProxy
   *
   * How to read the client IP from `X-Forwarded-For`: a number of proxy hops to trust, counted
   * from the server, or `true` to take the first address. `1` suits one proxy that appends the
   * address it saw (Cloud Run, Caddy); `true` lets a client choose the IP recorded in audit
   * events, so use it only behind a proxy that replaces the header.
   *
   * @defaultValue `false` — the header is ignored
   */
  readonly trustProxy?: boolean | number;

  /**
   * ### webRoot
   *
   * Directory of the built web app (`apps/web/dist`). When set, the server also serves the
   * web vault from `/` under a strict Content Security Policy.
   */
  readonly webRoot?: string;

  /**
   * ### logger
   *
   * Whether Fastify logs requests. Request bodies are never logged.
   *
   * @defaultValue `false`
   */
  readonly logger?: boolean;

  /**
   * ### sso
   *
   * The organisation's OpenID Connect provider (Google Workspace). Without it, the "require
   * SSO" policy cannot be switched on.
   */
  readonly sso?: OidcConfig | undefined;

  /**
   * ### ssoFetch
   *
   * Fetch used to talk to the identity provider, for tests.
   *
   * @defaultValue the global `fetch`
   */
  readonly ssoFetch?: typeof fetch;

  /**
   * ### bootstrapToken
   *
   * Token the first owner must present to create the organisation, so whoever reaches a fresh
   * server first cannot claim it. The server entry point always sets one.
   *
   * @defaultValue `undefined` — anyone may bootstrap, for tests
   */
  readonly bootstrapToken?: string | undefined;
}

/**
 * ### buildApp
 *
 * Builds the HTTP application with every route registered. The returned instance is not
 * listening yet; call `listen` for a server or `inject` in tests.
 *
 * @param options Database, secret and runtime options
 * @returns The configured Fastify instance
 */
export function buildApp(options: AppOptions): FastifyInstance {
  if (options.serverSecret.length < 32) {
    throw new Error("serverSecret must be at least 32 bytes");
  }

  const hops = options.trustProxy;
  const app = Fastify({
    logger:
      options.logger === true
        ? { serializers: { req: serializeRequest } }
        : false,
    // A hop count trusts that many addresses from the end of X-Forwarded-For
    trustProxy:
      typeof hops === "number"
        ? (_address: string, hop: number) => hop < hops
        : (hops ?? false),
    bodyLimit: 2 * 1024 * 1024,
  });
  const context: AppContext = {
    store: options.store,
    serverSecret: options.serverSecret,
    limits: createAuthLimits(),
    sso:
      options.sso === undefined
        ? undefined
        : new OidcClient(options.sso, options.ssoFetch),
    ssoTokenKey: symmetricKeyFromBytes(
      new Uint8Array(16),
      hkdf(
        sha256,
        options.serverSecret,
        undefined,
        utf8Encode("keymember/sso-refresh-token/v1"),
        32,
      ),
    ),
    now: options.now ?? (() => new Date()),
  };

  if (hops === undefined || hops === false) {
    warnOnUntrustedProxy(app);
  }

  app.setErrorHandler((error, request, reply) => {
    if (error instanceof DomainError) {
      return reply
        .status(STATUS_OF_KIND[error.kind])
        .send({ error: error.code, message: error.message, ...error.detail });
    }

    // A unique key the request reused, found by the store rather than by the route
    if (error instanceof DuplicateKeyError) {
      return reply
        .status(409)
        .send({ error: "conflict", message: error.message });
    }

    // Fastify's own client errors (malformed JSON, oversized body) carry a 4xx statusCode
    const statusCode = (error as { statusCode?: unknown }).statusCode;

    if (
      typeof statusCode === "number" &&
      statusCode >= 400 &&
      statusCode < 500
    ) {
      return reply
        .status(statusCode)
        .send({ error: "bad_request", message: "Malformed request" });
    }

    request.log.error(error);

    return reply
      .status(500)
      .send({ error: "internal", message: "Internal server error" });
  });

  app.addHook("onSend", async (request, reply, payload) => {
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("Cross-Origin-Opener-Policy", "same-origin");

    // Only meaningful over https; browsers ignore it on plain http
    if (request.protocol === "https") {
      reply.header(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains",
      );
    }

    // Hashed asset files never change; everything else, above all API responses, must not be cached
    if (!request.url.startsWith("/assets/")) {
      reply.header("Cache-Control", "no-store");
    }

    // The web vault holds decrypted secrets, so it allows no inline or third-party script and no framing
    reply.header(
      "Content-Security-Policy",
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; " +
        "connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    );

    return payload;
  });

  if (options.webRoot !== undefined) {
    void app.register(fastifyStatic, {
      root: options.webRoot,
      index: ["index.html"],
      cacheControl: false,
    });
  }

  app.get("/api/health", () => ({ ok: true }));

  // Lets a fresh web client decide between the bootstrap and login screens
  app.get("/api/status", async () => {
    return {
      bootstrapped: await options.store
        .repositories()
        .organizations.isBootstrapped(),
    };
  });

  registerAuthRoutes(app, context, { bootstrapToken: options.bootstrapToken });
  registerAccountRoutes(app, context);
  registerOrgRoutes(app, context);
  registerGroupRoutes(app, context);
  registerSsoRoutes(app, context);
  registerShareRoutes(app, context);
  registerVaultRoutes(app, context);
  registerItemRoutes(app, context);
  registerSyncRoutes(app, context);
  registerRecoveryRoutes(app, context);

  return app;
}
