import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { callerOf, requireActor } from "../http/AppContext.js";
import type { AppContext } from "../http/AppContext.js";
import { b64, bytes, identifier, parseBody } from "../http/codec.js";
import { VaultAccessControl } from "../services/vaults/VaultAccessControl.js";
import { VaultRotation } from "../services/vaults/VaultRotation.js";

const permissionSchema = z.enum(["view", "edit", "manage"]);

const principalTypeSchema = z.enum(["user", "group"]).default("user");

const grantSchema = z.object({
  principalType: principalTypeSchema,
  principalId: identifier,
  groupKeysetVersion: z.number().int().min(1).optional(),
  wrappedKey: bytes(undefined, 4096),
  grantSignature: bytes(64),
  permission: permissionSchema,
});

/**
 * ### ROTATION_BODY_LIMIT
 *
 * Largest rotation request accepted: a rotation re-sends every live item of the vault at once,
 * so it is far larger than other requests. 64 MiB covers thousands of ordinary items; on
 * Firestore a transaction also caps how much one rotation can write (about 10 MiB).
 */
const ROTATION_BODY_LIMIT = 64 * 1024 * 1024;

/**
 * ### registerVaultRoutes
 *
 * Registers vault creation, access management and key rotation; {@link VaultAccessControl}
 * and {@link VaultRotation} hold the rules.
 *
 * @param app Fastify instance to register on
 * @param context Shared dependencies
 */
export function registerVaultRoutes(
  app: FastifyInstance,
  context: AppContext,
): void {
  const accessControl = new VaultAccessControl(context);
  const rotation = new VaultRotation(context);

  app.post("/api/vaults", async (request, reply) => {
    const caller = callerOf(await requireActor(context, request), request);
    const input = parseBody(
      z.object({
        id: identifier,
        kind: z.enum(["personal", "shared"]),
        encryptedName: bytes(undefined, 4096),
        access: z.array(grantSchema).min(1).max(500),
        recoveryWrappedKey: bytes(undefined, 4096).optional(),
      }),
      request.body,
    );

    await accessControl.create(caller, {
      ...input,
      recoveryWrappedKey: input.recoveryWrappedKey,
    });

    return reply.status(201).send({ id: input.id });
  });

  app.put(
    "/api/vaults/:vaultId/access/:principalId",
    async (request, reply) => {
      const caller = callerOf(await requireActor(context, request), request);
      const { vaultId, principalId } = parseBody(
        z.object({ vaultId: identifier, principalId: identifier }),
        request.params,
      );
      const { keyGeneration, ...grant } = parseBody(
        grantSchema
          .omit({ principalId: true })
          .extend({ keyGeneration: z.number().int().min(1) }),
        request.body,
      );

      await accessControl.grant(
        caller,
        vaultId,
        { ...grant, principalId },
        keyGeneration,
      );

      return reply.status(204).send();
    },
  );

  app.delete(
    "/api/vaults/:vaultId/access/:principalId",
    async (request, reply) => {
      const caller = callerOf(await requireActor(context, request), request);
      const { vaultId, principalId } = parseBody(
        z.object({ vaultId: identifier, principalId: identifier }),
        request.params,
      );

      await accessControl.revoke(caller, vaultId, principalId);

      return reply.status(204).send();
    },
  );

  app.get("/api/vaults/:vaultId/access", async (request) => {
    const caller = callerOf(await requireActor(context, request), request);
    const { vaultId } = parseBody(
      z.object({ vaultId: identifier }),
      request.params,
    );
    const grants = await accessControl.access(caller, vaultId);

    return {
      access: grants.map((grant) => ({
        principalType: grant.principalType,
        principalId: grant.principalId,
        permission: grant.permission,
        wrappedKey: b64(grant.wrappedKey),
        keyGeneration: grant.keyGeneration,
        grantedBy: grant.grantedBy ?? null,
        grantSignature:
          grant.grantSignature === undefined ? null : b64(grant.grantSignature),
      })),
    };
  });

  app.post(
    "/api/vaults/:vaultId/rotate",
    { bodyLimit: ROTATION_BODY_LIMIT },
    async (request, reply) => {
      const caller = callerOf(await requireActor(context, request), request);
      const { vaultId } = parseBody(
        z.object({ vaultId: identifier }),
        request.params,
      );
      const input = parseBody(
        z.object({
          keyGeneration: z.number().int().min(2),
          encryptedName: bytes(undefined, 4096),
          access: z.array(grantSchema).min(1).max(500),
          recoveryWrappedKey: bytes(undefined, 4096).optional(),
          items: z
            .array(
              z.object({
                id: identifier,
                baseRevision: z.number().int().min(1),
                encryptedItemKey: bytes(undefined, 4096),
                encryptedOverview: bytes(undefined, 64 * 1024),
                encryptedDetails: bytes(undefined, 512 * 1024),
              }),
            )
            .max(10_000),
        }),
        request.body,
      );

      await rotation.rotate(caller, vaultId, {
        ...input,
        recoveryWrappedKey: input.recoveryWrappedKey,
      });

      return reply.status(204).send();
    },
  );
}
