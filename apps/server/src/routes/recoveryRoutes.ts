import { SALT_LENGTH, SECRET_KEY_ALPHABET } from "@keymember/core";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";

import { callerOf, requireActor } from "../http/AppContext.js";
import type { AppContext } from "../http/AppContext.js";
import { clientIp } from "../http/clientIp.js";
import { b64, bytes, identifier, parseBody } from "../http/codec.js";
import { RecoveryEnrolment } from "../services/recovery/RecoveryEnrolment.js";
import { RecoveryRequests } from "../services/recovery/RecoveryRequests.js";
import { RecoveryRestoration } from "../services/recovery/RecoveryRestoration.js";
import type { Caller } from "../domain/Caller.js";

const recoveryParams = z.object({ recoveryId: identifier });

/**
 * ### registerRecoveryRoutes
 *
 * Registers the HTTP side of account recovery. The workflow lives in the recovery services, one
 * per party: {@link RecoveryRequests} for the requesting and approving admins,
 * {@link RecoveryRestoration} for the completing admin, {@link RecoveryEnrolment} for the member.
 *
 * @param app Fastify instance to register on
 * @param context Shared dependencies
 */
export function registerRecoveryRoutes(
  app: FastifyInstance,
  context: AppContext,
): void {
  const requests = new RecoveryRequests(context);
  const restoration = new RecoveryRestoration(context);
  const enrolment = new RecoveryEnrolment(context);

  /**
   * ### admin
   *
   * The admin making a request, as the service needs them.
   *
   * @param request Incoming request
   * @returns The acting admin
   */
  const admin = async (request: FastifyRequest): Promise<Caller> =>
    callerOf(await requireActor(context, request, { admin: true }), request);

  app.get("/api/org/recoveries", async (request) => {
    const actor = await admin(request);

    return {
      recoveries: (await requests.list(actor.orgId)).map((recovery) => ({
        id: recovery.id,
        userId: recovery.userId,
        email: recovery.email,
        status: recovery.status,
        requestedBy: recovery.requestedBy,
        approvedBy: recovery.approvedBy ?? null,
        createdAt: recovery.createdAt.toISOString(),
        vaults: recovery.snapshot.vaults,
        groups: recovery.snapshot.groups,
        requestSignature:
          recovery.requestSignature === undefined
            ? null
            : b64(recovery.requestSignature),
      })),
    };
  });

  app.post("/api/org/recoveries", async (request, reply) => {
    const actor = await admin(request);
    const input = parseBody(
      z.object({
        userId: identifier,
        id: identifier,
        keysetVersion: z.number().int().min(1),
        // The requester's signature over {orgId, recoveryId, userId, requestedBy, keysetVersion};
        // the completing admin checks it
        signature: bytes(64),
      }),
      request.body,
    );

    await requests.request(actor, {
      recoveryId: input.id,
      userId: input.userId,
      keysetVersion: input.keysetVersion,
      signature: input.signature,
    });

    return reply.status(201).send({ id: input.id });
  });

  app.post("/api/org/recoveries/:recoveryId/approve", async (request) => {
    const actor = await admin(request);
    const { recoveryId } = parseBody(recoveryParams, request.params);
    const { token, expiresAt } = await requests.approve(actor, recoveryId);

    return { recoveryToken: token, expiresAt: expiresAt.toISOString() };
  });

  app.post("/api/org/recoveries/:recoveryId/cancel", async (request, reply) => {
    const actor = await admin(request);
    const { recoveryId } = parseBody(recoveryParams, request.params);

    await requests.cancel(actor, recoveryId);

    return reply.status(204).send();
  });

  app.get("/api/org/recoveries/:recoveryId/vault-keys", async (request) => {
    const actor = await admin(request);
    const { recoveryId } = parseBody(recoveryParams, request.params);
    const { recovery, vaults, groups } = await restoration.keysToRestore(
      actor.orgId,
      recoveryId,
    );

    return {
      userId: recovery.userId,
      requestedBy: recovery.requestedBy,
      requestSignature:
        recovery.requestSignature === undefined
          ? null
          : b64(recovery.requestSignature),
      groups: groups.map((group) => ({
        groupId: group.groupId,
        keysetVersion: group.keysetVersion,
        encryptionPublicKey: b64(group.encryptionPublicKey),
        recoveryWrappedKey: b64(group.recoveryWrappedKey),
      })),
      vaults: vaults.map((copy) => ({
        vaultId: copy.vaultId,
        keyGeneration: copy.keyGeneration,
        permission: copy.permission,
        recoveryWrappedKey: b64(copy.wrappedKey),
      })),
    };
  });

  app.post(
    "/api/org/recoveries/:recoveryId/complete",
    async (request, reply) => {
      const actor = await admin(request);
      const { recoveryId } = parseBody(recoveryParams, request.params);
      const restored = parseBody(
        z.object({
          access: z
            .array(
              z.object({
                vaultId: identifier,
                wrappedKey: bytes(undefined, 4096),
                grantSignature: bytes(64),
                keyGeneration: z.number().int().min(1),
              }),
            )
            .max(1000),
          groups: z
            .array(
              z.object({
                groupId: identifier,
                wrappedPrivateKey: bytes(undefined, 4096),
                keysetVersion: z.number().int().min(1),
                membershipSignature: bytes(64),
              }),
            )
            .max(1000)
            .default([]),
        }),
        request.body,
      );

      await restoration.complete(actor, recoveryId, restored);

      return reply.status(204).send();
    },
  );

  app.post("/api/auth/recover/info", async (request) => {
    const { token } = parseBody(
      z.object({ token: z.string().min(1).max(200) }),
      request.body,
    );
    const recovery = await enrolment.approvedByToken(token);

    return {
      userId: recovery.userId,
      email: recovery.email,
      orgName: recovery.orgName,
      nextKeysetVersion: recovery.keysetVersion + 1,
    };
  });

  app.post("/api/auth/recover", async (request, reply) => {
    const { token, ...rekey } = parseBody(
      z.object({
        token: z.string().min(1).max(200),
        accountId: z
          .string()
          .regex(new RegExp(`^[${SECRET_KEY_ALPHABET}]{6}$`)),
        salt: bytes(SALT_LENGTH),
        kdf: z.object({
          algorithm: z.literal("argon2id"),
          memoryKiB: z.number().int(),
          iterations: z.number().int(),
          parallelism: z.number().int(),
        }),
        loginPublicKey: bytes(32),
        keyset: z.object({
          encryptedAccountKey: bytes(undefined, 4096),
          encryptedPrivateKeys: bytes(undefined, 4096),
          encryptionPublicKey: bytes(32),
          signingPublicKey: bytes(32),
          keysetVersion: z.number().int().min(2),
          selfSignature: bytes(64),
        }),
      }),
      request.body,
    );

    await enrolment.rekey(token, rekey, clientIp(request));

    return reply.status(204).send();
  });
}
