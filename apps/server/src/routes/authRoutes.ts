import { SALT_LENGTH, SECRET_KEY_ALPHABET } from "@keymember/core";
import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { requireActor } from "../http/AppContext.js";
import type { AppContext } from "../http/AppContext.js";
import { clientIp } from "../http/clientIp.js";
import { b64, bytes, identifier, parseBody } from "../http/codec.js";
import { Enrollment } from "../services/auth/Enrollment.js";
import { LoginRenewal } from "../services/auth/LoginRenewal.js";
import { PasswordLogin } from "../services/auth/PasswordLogin.js";
import type { LoginProof } from "../services/loginChallenge.js";

const kdfSchema = z.object({
  algorithm: z.literal("argon2id"),
  memoryKiB: z.number().int(),
  iterations: z.number().int(),
  parallelism: z.number().int(),
});

const keysetSchema = z.object({
  encryptedAccountKey: bytes(undefined, 4096),
  encryptedPrivateKeys: bytes(undefined, 4096),
  encryptionPublicKey: bytes(32),
  signingPublicKey: bytes(32),
  keysetVersion: z.number().int().min(1),
  selfSignature: bytes(64),
});

const email = z.email().transform((value) => value.toLowerCase());

const signupSchema = z.object({
  userId: identifier,
  email,
  name: z.string().min(1).max(100),
  accountId: z.string().regex(new RegExp(`^[${SECRET_KEY_ALPHABET}]{6}$`)),
  salt: bytes(SALT_LENGTH),
  kdf: kdfSchema,
  loginPublicKey: bytes(32),
  keyset: keysetSchema,
});

/**
 * ### AuthRouteOptions
 *
 * How the authentication routes are set up.
 */
export interface AuthRouteOptions {
  /**
   * ### bootstrapToken
   *
   * Token the first owner must present to create the organisation; `undefined` lets anyone.
   */
  readonly bootstrapToken: string | undefined;
}

/**
 * ### registerAuthRoutes
 *
 * Registers organisation bootstrap, prelogin, sign-up, login, token refresh and logout;
 * {@link Enrollment}, {@link PasswordLogin} and {@link LoginRenewal} hold the rules.
 *
 * @param app Fastify instance to register on
 * @param context Shared dependencies
 * @param options Bootstrap token
 */
export function registerAuthRoutes(
  app: FastifyInstance,
  context: AppContext,
  options: AuthRouteOptions,
): void {
  const enrollment = new Enrollment(context, options.bootstrapToken);
  const passwordLogin = new PasswordLogin(context, (error) => {
    app.log.error(error, "Recording a failed login failed");
  });
  const renewal = new LoginRenewal(context);

  app.post("/api/bootstrap", async (request, reply) => {
    const input = parseBody(
      z.object({
        orgName: z.string().min(1).max(100),
        signup: signupSchema,
        bootstrapToken: z.string().min(1).max(200).optional(),
      }),
      request.body,
    );
    const orgId = await enrollment.bootstrap(
      input.orgName,
      input.signup,
      input.bootstrapToken,
      clientIp(request),
    );

    return reply.status(201).send({ orgId });
  });

  app.post("/api/auth/prelogin", async (request) => {
    const input = parseBody(z.object({ email }), request.body);
    const result = await passwordLogin.prelogin(input.email, clientIp(request));

    return {
      salt: b64(result.salt),
      kdf: result.kdf,
      challengeId: result.challengeId,
      challenge: b64(result.challenge),
      method: result.method,
    };
  });

  app.post("/api/auth/signup", async (request, reply) => {
    const input = parseBody(
      signupSchema.extend({
        inviteToken: z.string().min(1).max(200),
        // Proof from the invite link's secret that these keys are the invitee's; absent when
        // the invitee typed the token in, in which case the admin compares fingerprints
        inviteProof: bytes(32).optional(),
      }),
      request.body,
    );

    await enrollment.signUp(
      input,
      { token: input.inviteToken, proof: input.inviteProof },
      clientIp(request),
    );

    return reply.status(201).send({ userId: input.userId });
  });

  app.post("/api/auth/login", async (request) => {
    const input = parseBody(
      z.object({
        email,
        challengeId: identifier.optional(),
        signature: bytes(64).optional(),
        authKey: bytes(32).optional(),
        loginPublicKey: bytes(32).optional(),
        deviceId: identifier,
        deviceName: z.string().min(1).max(100),
        totp: z
          .string()
          .regex(/^\d{6}$/)
          .optional(),
        sso: z.boolean().optional(),
      }),
      request.body,
    );
    const proof: LoginProof | undefined =
      input.challengeId !== undefined && input.signature !== undefined
        ? { challengeId: input.challengeId, signature: input.signature }
        : input.authKey === undefined
          ? undefined
          : { authKey: input.authKey };

    return passwordLogin.login(
      {
        email: input.email,
        proof,
        loginPublicKey: input.loginPublicKey,
        deviceId: input.deviceId,
        deviceName: input.deviceName,
        totp: input.totp,
        sso: input.sso === true,
      },
      clientIp(request),
    );
  });

  app.post("/api/auth/refresh", async (request) => {
    const { refreshToken } = parseBody(
      z.object({ refreshToken: z.string().min(1).max(200) }),
      request.body,
    );

    return renewal.refresh(refreshToken, clientIp(request));
  });

  app.post("/api/auth/logout", async (request, reply) => {
    const actor = await requireActor(context, request, {
      confirmed: false,
      allowWithoutTotp: true,
      allowWithoutSso: true,
    });

    await renewal.logout(actor.familyId);

    return reply.status(204).send();
  });
}
