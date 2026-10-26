import {
  assertKdfParams,
  KdfParametersRejectedError,
  SALT_LENGTH,
  verifyTrustedRoots,
} from "@keymember/core";
import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { callerOf, requireActor } from "../http/AppContext.js";
import type { AppContext } from "../http/AppContext.js";
import { b64, bytes, identifier, parseBody } from "../http/codec.js";
import { DomainError } from "../domain/DomainError.js";
import { checkLoginProof } from "../services/loginChallenge.js";
import type { LoginProof } from "../services/loginChallenge.js";
import { TwoFactorEnrollment } from "../services/account/TwoFactorEnrollment.js";
import { toBase32, totpUri } from "../services/totp.js";
import { clientIp } from "../http/clientIp.js";

/**
 * ### registerAccountRoutes
 *
 * Registers routes a user runs on their own account: two-factor enrolment, password change and
 * the trusted roots their devices share.
 *
 * @param app Fastify instance to register on
 * @param context Shared dependencies
 */
export function registerAccountRoutes(
  app: FastifyInstance,
  context: AppContext,
): void {
  const twoFactor = new TwoFactorEnrollment(
    context,
    context.limits.totpReplace,
  );

  app.get("/api/account/trusted-roots", async (request) => {
    const actor = await requireActor(context, request, {
      // Devices pin their roots before an admin certifies the member, to verify that admin
      confirmed: false,
      allowWithoutTotp: true,
    });
    const stored = await context.store
      .repositories()
      .users.trustedRoots(actor.userId);

    if (stored === undefined) {
      throw new DomainError(
        "not_found",
        "not_found",
        "No trusted roots stored",
      );
    }

    return { statement: stored.statement, signature: b64(stored.signature) };
  });

  app.put("/api/account/trusted-roots", async (request, reply) => {
    const actor = await requireActor(context, request, {
      // Devices pin their roots before an admin certifies the member, to verify that admin
      confirmed: false,
      allowWithoutTotp: true,
    });
    const input = parseBody(
      z.object({
        statement: z.object({
          userId: identifier,
          orgId: identifier,
          issuedAt: z.number().int().min(0),
          roots: z
            .array(
              z.object({ userId: identifier, signingPublicKey: bytes(32) }),
            )
            .min(1)
            .max(10),
        }),
        signature: bytes(64),
      }),
      request.body,
    );
    const signingKey = await context.store
      .repositories()
      .users.signingPublicKey(actor.userId);

    // Devices verify these themselves; this only turns away a faulty client early
    if (
      signingKey === undefined ||
      input.statement.userId !== actor.userId ||
      input.statement.orgId !== actor.orgId ||
      !verifyTrustedRoots(signingKey, input.statement, input.signature)
    ) {
      throw new DomainError(
        "invalid",
        "bad_request",
        "Trusted roots are not signed by this account",
      );
    }

    await context.store.repositories().users.setTrustedRoots(
      actor.userId,
      {
        ...input.statement,
        roots: input.statement.roots.map((root) => ({
          userId: root.userId,
          signingPublicKey: b64(root.signingPublicKey),
        })),
      },
      input.signature,
    );

    return reply.status(204).send();
  });

  app.post("/api/account/totp/setup", async (request) => {
    const actor = await requireActor(context, request, {
      confirmed: false,
      allowWithoutTotp: true,
    });
    const secret = await twoFactor.start(callerOf(actor, request));

    return { secret: toBase32(secret), uri: totpUri(secret, actor.email) };
  });

  app.post("/api/account/totp/confirm", async (request, reply) => {
    const actor = await requireActor(context, request, {
      confirmed: false,
      allowWithoutTotp: true,
    });
    const { code, currentCode } = parseBody(
      z.object({
        code: z.string().regex(/^\d{6}$/),
        // Replacing an existing authenticator needs a code from it, not just a session token
        currentCode: z
          .string()
          .regex(/^\d{6}$/)
          .optional(),
      }),
      request.body,
    );

    await twoFactor.confirm(
      callerOf(actor, request),
      actor.familyId,
      code,
      currentCode,
    );

    return reply.status(204).send();
  });

  app.post("/api/account/password", async (request, reply) => {
    const actor = await requireActor(context, request, { confirmed: false });
    const input = parseBody(
      z.object({
        // Proof of the current password: a signed challenge, or the legacy key for old accounts
        currentChallengeId: identifier.optional(),
        currentSignature: bytes(64).optional(),
        currentAuthKey: bytes(32).optional(),
        salt: bytes(SALT_LENGTH),
        kdf: z.object({
          algorithm: z.literal("argon2id"),
          memoryKiB: z.number().int(),
          iterations: z.number().int(),
          parallelism: z.number().int(),
        }),
        loginPublicKey: bytes(32),
        encryptedAccountKey: bytes(undefined, 4096),
      }),
      request.body,
    );

    try {
      assertKdfParams(input.kdf);
    } catch (error) {
      if (error instanceof KdfParametersRejectedError) {
        throw new DomainError("invalid", "bad_request", error.message);
      }

      throw error;
    }

    await context.store.transaction(async (repos) => {
      const { audit, loginChallenges, sessions, users } = repos;
      const user = await users.credentialsForUpdate(actor.userId);
      const proof: LoginProof | undefined =
        input.currentChallengeId !== undefined &&
        input.currentSignature !== undefined
          ? {
              challengeId: input.currentChallengeId,
              signature: input.currentSignature,
            }
          : input.currentAuthKey === undefined
            ? undefined
            : { authKey: input.currentAuthKey };

      if (
        user === undefined ||
        proof === undefined ||
        !(await checkLoginProof(
          loginChallenges,
          user,
          proof,
          { email: actor.email, deviceId: "", purpose: "change-password" },
          context.now(),
        ))
      ) {
        throw new DomainError(
          "unauthenticated",
          "invalid_credentials",
          "Current password is incorrect",
        );
      }

      await users.changePassword(actor.userId, input);

      // Other devices still hold the old unlock path; force them to log in again with the new password
      await sessions.revokeOthers(actor.userId, actor.familyId, context.now());
      await audit.record({
        orgId: actor.orgId,
        actorId: actor.userId,
        action: "account.password_changed",
        ip: clientIp(request),
      });
    });

    return reply.status(204).send();
  });
}
