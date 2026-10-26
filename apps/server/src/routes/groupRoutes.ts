import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { callerOf, requireActor } from "../http/AppContext.js";
import type { AppContext } from "../http/AppContext.js";
import { b64, bytes, identifier, parseBody } from "../http/codec.js";
import { GroupAdministration } from "../services/groups/GroupAdministration.js";
import { GroupRotation } from "../services/groups/GroupRotation.js";

const certificateSchema = z.object({
  orgId: identifier,
  groupId: identifier,
  name: z.string().min(1).max(200),
  encryptionPublicKey: bytes(32),
  keysetVersion: z.number().int().min(1),
  issuerId: identifier,
  issuedAt: z.number().int().min(0),
});

const memberCopySchema = z.object({
  userId: identifier,
  wrappedPrivateKey: bytes(undefined, 4096),
  membershipSignature: bytes(64),
});

const signedKeySchema = {
  certificate: certificateSchema,
  signature: bytes(64),
  members: z.array(memberCopySchema).max(1000),
  recoveryWrappedKey: bytes(undefined, 4096).optional(),
};

/**
 * ### GROUP_ROTATION_BODY_LIMIT
 *
 * Largest group rotation accepted: it re-wraps every vault key the group carries at once.
 */
const GROUP_ROTATION_BODY_LIMIT = 16 * 1024 * 1024;

/**
 * ### registerGroupRoutes
 *
 * Registers groups; {@link GroupAdministration} and {@link GroupRotation} hold the rules.
 *
 * @param app Fastify instance to register on
 * @param context Shared dependencies
 */
export function registerGroupRoutes(
  app: FastifyInstance,
  context: AppContext,
): void {
  const administration = new GroupAdministration(context);
  const rotation = new GroupRotation(context);

  app.get("/api/org/groups", async (request) => {
    const actor = await requireActor(context, request);
    const groups = await context.store
      .repositories()
      .groups.listLive(actor.orgId);

    return {
      groups: groups.map((group) => ({
        id: group.id,
        name: group.name,
        encryptionPublicKey: b64(group.encryptionPublicKey),
        keysetVersion: group.keysetVersion,
        certificate: group.certificate,
        certificateSignature: b64(group.certificateSignature),
        members: group.members,
      })),
    };
  });

  app.post("/api/org/groups", async (request, reply) => {
    const caller = callerOf(
      await requireActor(context, request, { admin: true }),
      request,
    );
    const input = parseBody(z.object(signedKeySchema), request.body);

    await administration.create(
      caller,
      {
        certificate: input.certificate,
        signature: input.signature,
        recoveryWrappedKey: input.recoveryWrappedKey,
      },
      input.members,
    );

    return reply.status(201).send({ id: input.certificate.groupId });
  });

  app.put(
    "/api/org/groups/:groupId/members/:userId",
    async (request, reply) => {
      const caller = callerOf(
        await requireActor(context, request, { admin: true }),
        request,
      );
      const { groupId, userId } = parseBody(
        z.object({ groupId: identifier, userId: identifier }),
        request.params,
      );
      const input = parseBody(
        memberCopySchema
          .omit({ userId: true })
          .extend({ keysetVersion: z.number().int().min(1) }),
        request.body,
      );

      await administration.addMember(
        caller,
        groupId,
        { ...input, userId },
        input.keysetVersion,
      );

      return reply.status(204).send();
    },
  );

  app.get("/api/org/groups/:groupId/keys", async (request) => {
    const caller = callerOf(
      await requireActor(context, request, { admin: true }),
      request,
    );
    const { groupId } = parseBody(
      z.object({ groupId: identifier }),
      request.params,
    );
    const material = await administration.keyMaterial(caller, groupId);
    const { group } = material;

    return {
      groupId,
      keysetVersion: group.keysetVersion,
      encryptionPublicKey: b64(group.encryptionPublicKey),
      recoveryWrappedKey:
        group.recoveryWrappedKey === undefined
          ? null
          : b64(group.recoveryWrappedKey),
      memberWrappedKey:
        material.memberWrappedKey === undefined
          ? null
          : b64(material.memberWrappedKey),
      members: material.memberships.map((membership) => ({
        userId: membership.userId,
        wrappedPrivateKey: b64(membership.wrappedPrivateKey),
        grantedBy: membership.grantedBy ?? null,
        membershipSignature:
          membership.signature === undefined ? null : b64(membership.signature),
      })),
      access: material.access.map((grant) => ({
        vaultId: grant.vaultId,
        wrappedKey: b64(grant.wrappedKey),
        keyGeneration: grant.keyGeneration,
        permission: grant.permission,
      })),
    };
  });

  app.post(
    "/api/org/groups/:groupId/rotate",
    { bodyLimit: GROUP_ROTATION_BODY_LIMIT },
    async (request, reply) => {
      const caller = callerOf(
        await requireActor(context, request, { admin: true }),
        request,
      );
      const { groupId } = parseBody(
        z.object({ groupId: identifier }),
        request.params,
      );
      const input = parseBody(
        z.object({
          ...signedKeySchema,
          access: z
            .array(
              z.object({
                vaultId: identifier,
                wrappedKey: bytes(undefined, 4096),
                grantSignature: bytes(64),
                keyGeneration: z.number().int().min(1),
              }),
            )
            .max(10_000),
        }),
        request.body,
      );

      await rotation.rotate(
        caller,
        groupId,
        {
          certificate: input.certificate,
          signature: input.signature,
          recoveryWrappedKey: input.recoveryWrappedKey,
        },
        input.members,
        input.access,
      );

      return reply.status(204).send();
    },
  );

  app.delete("/api/org/groups/:groupId", async (request, reply) => {
    const caller = callerOf(
      await requireActor(context, request, { admin: true }),
      request,
    );
    const { groupId } = parseBody(
      z.object({ groupId: identifier }),
      request.params,
    );

    await administration.delete(caller, groupId);

    return reply.status(204).send();
  });
}
