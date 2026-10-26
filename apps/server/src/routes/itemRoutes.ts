import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { callerOf, requireActor } from "../http/AppContext.js";
import type { AppContext } from "../http/AppContext.js";
import { bytes, identifier, parseBody } from "../http/codec.js";
import { ItemWriting } from "../services/items/ItemWriting.js";

const encryptedFields = {
  encryptedItemKey: bytes(undefined, 4096),
  encryptedOverview: bytes(undefined, 64 * 1024),
  encryptedDetails: bytes(undefined, 512 * 1024),
};

/**
 * ### registerItemRoutes
 *
 * Registers item create, update and delete; {@link ItemWriting} holds the rules.
 *
 * @param app Fastify instance to register on
 * @param context Shared dependencies
 */
export function registerItemRoutes(
  app: FastifyInstance,
  context: AppContext,
): void {
  const items = new ItemWriting(context);

  app.post("/api/items", async (request, reply) => {
    const caller = callerOf(await requireActor(context, request), request);
    const item = parseBody(
      z.object({ id: identifier, vaultId: identifier, ...encryptedFields }),
      request.body,
    );
    const revision = await items.create(caller, item);

    return reply.status(201).send({ id: item.id, revision });
  });

  app.put("/api/items/:itemId", async (request) => {
    const caller = callerOf(await requireActor(context, request), request);
    const { itemId } = parseBody(
      z.object({ itemId: identifier }),
      request.params,
    );
    const { baseRevision, ...item } = parseBody(
      z.object({
        baseRevision: z.number().int().min(1),
        vaultId: identifier,
        ...encryptedFields,
      }),
      request.body,
    );
    const revision = await items.update(
      caller,
      { ...item, id: itemId },
      baseRevision,
    );

    return { id: itemId, revision };
  });

  app.delete("/api/items/:itemId", async (request, reply) => {
    const caller = callerOf(await requireActor(context, request), request);
    const { itemId } = parseBody(
      z.object({ itemId: identifier }),
      request.params,
    );
    const { baseRevision } = parseBody(
      z.object({ baseRevision: z.coerce.number().int().min(1) }),
      request.query,
    );

    await items.delete(caller, itemId, baseRevision);

    return reply.status(204).send();
  });
}
