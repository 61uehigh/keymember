import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { requireActor } from "../http/AppContext.js";
import type { AppContext } from "../http/AppContext.js";
import { b64, parseBody } from "../http/codec.js";
import type { AccessPath } from "../repositories/VaultRepository.js";

/**
 * ### registerSyncRoutes
 *
 * Registers incremental sync and the audit log.
 *
 * Sync returns every vault the caller can access on every call (the list is small), so a
 * client drops vaults that disappear from it. Items are returned only when changed after
 * `since`, except for vaults whose access entry (or the caller's group membership behind it)
 * changed after `since`: those are sent in full, because the caller may never have seen their
 * older items. Each vault lists every path the caller reaches it by, directly or through groups,
 * together with the caller's wrapped group keys.
 *
 * @param app Fastify instance to register on
 * @param context Shared dependencies
 */
export function registerSyncRoutes(
  app: FastifyInstance,
  context: AppContext,
): void {
  app.get("/api/sync", async (request) => {
    const actor = await requireActor(context, request);
    const { since } = parseBody(
      z.object({ since: z.coerce.number().int().min(0).default(0) }),
      request.query,
    );

    // One read-only snapshot, so the revision and the rows describe the same state
    return context.store.snapshot(async (repos) => {
      const { changeFeed, groups, items, vaults } = repos;
      // One path per grant: the caller's own and one per live group they belong to
      const [revision, paths, heldGroups] = await Promise.all([
        changeFeed.latestRevision(),
        vaults.accessPaths(actor.userId),
        groups.keysHeldBy(actor.userId),
      ]);
      // A store restored from an older backup counts from a lower revision than the client has
      // seen; the client's cursor then means nothing, so it is sent everything and told so
      const reset = since > revision;
      const from = reset ? 0 : since;
      const byVault = new Map<string, Array<AccessPath>>();

      for (const path of paths) {
        byVault.set(path.vaultId, [...(byVault.get(path.vaultId) ?? []), path]);
      }

      const vaultIds = [...byVault.keys()];
      const newlyVisible = paths
        .filter((path) => path.accessRevision > from)
        .map((path) => path.vaultId);
      const changes = await items.changesForSync(vaultIds, from, newlyVisible);

      return {
        revision,
        reset,
        vaults: [...byVault.values()].flatMap((vaultPaths) => {
          const [first] = vaultPaths;

          return first === undefined
            ? []
            : [
                {
                  id: first.vaultId,
                  kind: first.kind,
                  encryptedName: b64(first.encryptedName),
                  keyGeneration: first.keyGeneration,
                  rotationDue: first.rotationDue,
                  access: vaultPaths.map((path) => ({
                    principalType: path.principalType,
                    principalId: path.principalId,
                    wrappedKey: b64(path.wrappedKey),
                    keyGeneration: path.accessGeneration,
                    permission: path.permission,
                    grantedBy: path.grantedBy ?? null,
                    grantSignature:
                      path.grantSignature === undefined
                        ? null
                        : b64(path.grantSignature),
                  })),
                },
              ];
        }),
        groups: heldGroups.map((group) => ({
          id: group.id,
          name: group.name,
          encryptionPublicKey: b64(group.encryptionPublicKey),
          keysetVersion: group.keysetVersion,
          certificate: group.certificate,
          certificateSignature: b64(group.certificateSignature),
          wrappedPrivateKey: b64(group.wrappedPrivateKey),
          memberKeysetVersion: group.memberKeysetVersion,
        })),
        items: changes.flatMap((item) =>
          item.deleted
            ? []
            : [
                {
                  id: item.id,
                  vaultId: item.vaultId,
                  revision: item.revision,
                  encryptedItemKey: b64(item.encryptedItemKey),
                  encryptedOverview: b64(item.encryptedOverview),
                  encryptedDetails: b64(item.encryptedDetails),
                },
              ],
        ),
        deletedItemIds: changes
          .filter((item) => item.deleted)
          .map((item) => item.id),
      };
    });
  });

  app.get("/api/audit", async (request) => {
    const actor = await requireActor(context, request, { admin: true });
    const { limit } = parseBody(
      z.object({
        limit: z.coerce.number().int().min(1).max(1000).default(100),
      }),
      request.query,
    );
    const events = await context.store
      .repositories()
      .audit.latest(actor.orgId, limit);

    return {
      events: events.map((event) => ({
        id: event.id,
        actorId: event.actorId ?? null,
        action: event.action,
        targetId: event.targetId ?? null,
        detail: event.detail,
        ip: event.ip ?? null,
        at: event.at.toISOString(),
      })),
    };
  });
}
