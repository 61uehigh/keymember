import { constantTimeEqual, shareAccessHash } from "@keymember/core";
import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { requireActor } from "../http/AppContext.js";
import type { AppContext } from "../http/AppContext.js";
import { b64, bytes, identifier, parseBody } from "../http/codec.js";
import { DomainError } from "../domain/DomainError.js";
import { RateLimiter } from "../services/RateLimiter.js";
import { clientIp } from "../http/clientIp.js";
import type { ShareLinkRecord } from "../repositories/ShareRepository.js";
import { requireVaultPermission } from "../services/vaultAccess.js";

/**
 * ### SHARE_MAX_LIFETIME_MS
 *
 * Longest a share link can stay open: 30 days.
 */
export const SHARE_MAX_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * ### SHARE_MAX_FAILED_ATTEMPTS
 *
 * Wrong passphrases (or forged proofs) after which a link closes for good.
 */
export const SHARE_MAX_FAILED_ATTEMPTS = 10;

const SHARE_MIN_LIFETIME_MS = 5 * 60 * 1000;
const SHARE_MAX_CIPHERTEXT_BYTES = 64 * 1024;

/**
 * ### ShareStatus
 *
 * Whether a link still opens: `active`, or why not.
 */
export type ShareStatus = "active" | "expired" | "used_up" | "revoked";

/**
 * ### shareStatus
 *
 * Works out a link's status.
 *
 * @param share Share link
 * @param now Current time
 * @returns The status
 */
function shareStatus(share: ShareLinkRecord, now: Date): ShareStatus {
  if (share.revokedAt !== undefined) {
    return "revoked";
  }

  if (share.views >= share.maxViews) {
    return "used_up";
  }

  return share.expiresAt <= now ? "expired" : "active";
}

/**
 * ### registerShareRoutes
 *
 * Registers share links: a member seals a snapshot of one item under a key that exists only in
 * the link's URL fragment, and anyone holding the link (and its passphrase, if set) can open it
 * until it expires or runs out of views. The server sees neither the key nor the contents; it
 * hands out the ciphertext only to callers who prove they hold the link, which also keeps link
 * previews and guessed ids from using up views.
 *
 * @param app Fastify instance to register on
 * @param context Shared dependencies
 */
export function registerShareRoutes(
  app: FastifyInstance,
  context: AppContext,
): void {
  // Opening is unauthenticated, so attempts are limited per client address across all links
  const openLimiter = new RateLimiter(30, 15 * 60 * 1000);

  app.post("/api/shares", async (request, reply) => {
    const actor = await requireActor(context, request);
    const input = parseBody(
      z.object({
        id: identifier,
        vaultId: identifier,
        itemId: identifier,
        ciphertext: bytes(undefined, SHARE_MAX_CIPHERTEXT_BYTES),
        accessHash: bytes(32),
        passphrase: z.boolean(),
        // A lifetime rather than a timestamp, so the sender's clock does not matter
        lifetimeSeconds: z.number().int().min(1),
        maxViews: z.number().int().min(1).max(100),
      }),
      request.body,
    );
    const now = context.now();
    const lifetime = input.lifetimeSeconds * 1000;
    const expiresAt = new Date(now.getTime() + lifetime);

    if (lifetime < SHARE_MIN_LIFETIME_MS || lifetime > SHARE_MAX_LIFETIME_MS) {
      throw new DomainError(
        "invalid",
        "bad_request",
        "A share link must stay open between 5 minutes and 30 days",
      );
    }

    await context.store.transaction(async (repos) => {
      // Anyone who can read the item can already copy it; sharing it is recorded in the audit log
      const { items, shares } = repos;

      await requireVaultPermission(
        repos.vaults,
        input.vaultId,
        actor.userId,
        "view",
      );

      if (!(await items.isLiveIn(input.itemId, input.vaultId))) {
        throw new DomainError("not_found", "not_found", "No such item");
      }

      if (await shares.exists(input.id)) {
        throw new DomainError(
          "conflict",
          "conflict",
          "Share id already exists",
        );
      }

      await shares.insert(
        {
          id: input.id,
          orgId: actor.orgId,
          vaultId: input.vaultId,
          itemId: input.itemId,
          createdBy: actor.userId,
          ciphertext: input.ciphertext,
          accessHash: input.accessHash,
          passphrase: input.passphrase,
          expiresAt,
          maxViews: input.maxViews,
        },
        now,
      );
      await repos.audit.record({
        orgId: actor.orgId,
        actorId: actor.userId,
        action: "share.created",
        targetId: input.itemId,
        detail: {
          shareId: input.id,
          vaultId: input.vaultId,
          maxViews: input.maxViews,
          expiresAt: expiresAt.toISOString(),
          passphrase: input.passphrase,
        },
        ip: clientIp(request),
      });
    });

    return reply.status(201).send({ id: input.id });
  });

  app.get("/api/shares", async (request) => {
    const actor = await requireActor(context, request);
    const query = parseBody(
      z.object({
        itemId: identifier.optional(),
        all: z.enum(["true", "false"]).optional(),
      }),
      request.query,
    );
    const everyone = query.all === "true";

    if (everyone && actor.role === "member") {
      throw new DomainError("forbidden", "forbidden", "Admin role required");
    }

    const links = await context.store.repositories().shares.list({
      orgId: actor.orgId,
      createdBy: everyone ? undefined : actor.userId,
      itemId: query.itemId,
    });
    const now = context.now();

    return {
      shares: links.map((share) => ({
        id: share.id,
        vaultId: share.vaultId,
        itemId: share.itemId,
        createdBy: share.createdBy,
        createdAt: share.createdAt.toISOString(),
        expiresAt: share.expiresAt.toISOString(),
        maxViews: share.maxViews,
        views: share.views,
        passphrase: share.passphrase,
        lastOpenedAt: share.lastOpenedAt?.toISOString() ?? null,
        status: shareStatus(share, now),
      })),
    };
  });

  app.delete("/api/shares/:shareId", async (request, reply) => {
    const actor = await requireActor(context, request);
    const { shareId } = parseBody(
      z.object({ shareId: identifier }),
      request.params,
    );

    await context.store.transaction(async (repos) => {
      const { shares } = repos;
      const share = await shares.lock(shareId, actor.orgId);

      if (
        share === undefined ||
        (share.createdBy !== actor.userId && actor.role === "member")
      ) {
        throw new DomainError("not_found", "not_found", "No such share link");
      }

      await shares.revoke(shareId, context.now());
      await repos.audit.record({
        orgId: actor.orgId,
        actorId: actor.userId,
        action: "share.revoked",
        targetId: share.itemId,
        detail: { shareId },
        ip: clientIp(request),
      });
    });

    return reply.status(204).send();
  });

  app.post("/api/shares/:shareId/open", async (request) => {
    const { shareId } = parseBody(
      z.object({ shareId: identifier }),
      request.params,
    );
    const { accessProof } = parseBody(
      z.object({ accessProof: bytes(32) }),
      request.body,
    );
    const ip = clientIp(request);
    const now = context.now();
    const unavailable = new DomainError(
      "gone",
      "share_unavailable",
      "This link has expired, was used up, or was revoked",
    );

    if (openLimiter.isBlocked(ip, now.getTime())) {
      throw new DomainError(
        "rate_limited",
        "rate_limited",
        "Too many attempts; try again later",
      );
    }

    const outcome = await context.store.transaction(async (repos) => {
      const { shares } = repos;
      const share = await shares.lock(shareId);

      if (share === undefined) {
        return { kind: "unavailable" as const };
      }

      const { ciphertext } = share;

      if (ciphertext === undefined || shareStatus(share, now) !== "active") {
        return { kind: "unavailable" as const };
      }

      if (!constantTimeEqual(shareAccessHash(accessProof), share.accessHash)) {
        // Without a passphrase a wrong proof means a forged link, not a guess at something short;
        // counting those would let anyone who saw a link id close it
        if (!share.passphrase) {
          return { kind: "denied" as const, left: SHARE_MAX_FAILED_ATTEMPTS };
        }

        const failed = share.failedAttempts + 1;

        // Too many wrong passphrases: the link closes rather than wait to be guessed
        await shares.recordFailedAttempt(
          shareId,
          failed,
          SHARE_MAX_FAILED_ATTEMPTS,
          now,
        );

        return {
          kind: "denied" as const,
          left: SHARE_MAX_FAILED_ATTEMPTS - failed,
        };
      }

      const views = share.views + 1;

      await shares.recordView(shareId, views, now);
      await repos.audit.record({
        orgId: share.orgId,
        actorId: undefined,
        action: "share.opened",
        targetId: share.itemId,
        detail: { shareId, views },
        ip,
      });

      return {
        kind: "opened" as const,
        body: {
          ciphertext: b64(ciphertext),
          expiresAt: share.expiresAt.toISOString(),
          viewsLeft: share.maxViews - views,
        },
      };
    });

    if (outcome.kind === "opened") {
      return outcome.body;
    }

    openLimiter.recordFailure(ip, now.getTime());

    if (outcome.kind === "unavailable") {
      throw unavailable;
    }

    throw new DomainError(
      "forbidden",
      "share_denied",
      outcome.left > 0
        ? "Wrong passphrase"
        : "Wrong passphrase; the link is now closed",
      { attemptsLeft: Math.max(outcome.left, 0) },
    );
  });
}
