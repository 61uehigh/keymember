import { constantTimeEqual } from "@keymember/core";
import type { FastifyInstance, FastifyReply } from "fastify";
import { z } from "zod";

import { requireActor } from "../http/AppContext.js";
import type { AppContext } from "../http/AppContext.js";
import { identifier, parseBody } from "../http/codec.js";
import { DomainError } from "../domain/DomainError.js";
import { OidcError } from "../services/OidcClient.js";
import { createSsoTicket, sealRefreshToken } from "../services/sso.js";
import { hashToken } from "../services/tokens.js";
import { clientIp } from "../http/clientIp.js";
import { completeLogin } from "../services/auth/completeLogin.js";

/**
 * ### escapeHtml
 *
 * Escapes text for an HTML body.
 *
 * @param text Text, possibly user-chosen (device names)
 * @returns Escaped text
 */
function escapeHtml(text: string): string {
  return text.replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ] ?? char,
  );
}

/**
 * ### resultPage
 *
 * The page the browser lands on after the identity provider. It carries no script and no
 * secret: the waiting client collects the result itself with the ticket secret.
 *
 * @param reply Reply to send
 * @param status HTTP status
 * @param message What to tell the user
 * @returns The sent reply
 */
function resultPage(
  reply: FastifyReply,
  status: number,
  message: string,
): FastifyReply {
  return reply
    .status(status)
    .type("text/html; charset=utf-8")
    .header("Content-Security-Policy", "default-src 'none'")
    .send(
      `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>keymember</title><body><p>${message}</p></body></html>`,
    );
}

/**
 * ### registerSsoRoutes
 *
 * Registers the identity-provider check that sits on top of password + Secret Key login.
 * A login (or an existing session asking to be linked) gets a ticket; the browser goes through
 * `/start` to the provider and back to `/callback`, which verifies the ID token and binds the
 * provider account to the keymember user; the client then collects the result from `/finish`.
 * SSO never unlocks anything: the vault keys still come only from password + Secret Key.
 *
 * @param app Fastify instance to register on
 * @param context Shared dependencies
 */
export function registerSsoRoutes(
  app: FastifyInstance,
  context: AppContext,
): void {
  app.get("/api/auth/sso/start", async (request, reply) => {
    const { ticket, confirm } = parseBody(
      z.object({ ticket: identifier, confirm: z.literal("1").optional() }),
      request.query,
    );
    const row = await context.store
      .repositories()
      .sso.pendingTicket({ id: ticket }, context.now());

    if (row === undefined || context.sso === undefined) {
      return resultPage(
        reply,
        410,
        "This login request has expired. Log in again from keymember.",
      );
    }

    // A phisher who already has the password can start a login and send its link to the victim;
    // this page says what the victim would be confirming before Google is involved
    if (confirm === undefined) {
      const device =
        row.kind === "login"
          ? (row.deviceName ?? "Unknown device")
          : "A device that is already logged in";

      return reply
        .status(200)
        .type("text/html; charset=utf-8")
        .send(
          `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>keymember</title><body>` +
            `<h1>Verify your company account</h1>` +
            `<p>Continuing the keymember login for <strong>${escapeHtml(row.email)}</strong>.</p>` +
            `<p>Device: ${escapeHtml(device)}<br>Requested at: ${escapeHtml(row.createdAt.toISOString())}</p>` +
            `<p><strong>Don't continue unless you just started this login yourself.</strong> If someone sent you this link, your password may have leaked; tell an admin.</p>` +
            `<p><a href="/api/auth/sso/start?ticket=${encodeURIComponent(ticket)}&amp;confirm=1">I started this login. Continue</a></p>` +
            `</body></html>`,
        );
    }

    return reply.redirect(
      await context.sso.authorizationUrl({
        state: row.state,
        nonce: row.nonce,
        codeVerifier: row.codeVerifier,
        loginHint: row.email,
      }),
    );
  });

  app.get("/api/auth/sso/callback", async (request, reply) => {
    const query = parseBody(
      z.object({
        state: z.string().max(200),
        code: z.string().max(4096).optional(),
        error: z.string().max(200).optional(),
      }),
      request.query,
    );
    const repositories = context.store.repositories();
    const ticket = await repositories.sso.pendingTicket(
      { state: query.state },
      context.now(),
    );

    if (ticket === undefined || context.sso === undefined) {
      return resultPage(
        reply,
        410,
        "This login request has expired. Log in again from keymember.",
      );
    }

    const fail = async (reason: string): Promise<FastifyReply> => {
      await repositories.sso.failTicket(ticket.id, reason);
      await repositories.audit.record({
        orgId: ticket.orgId,
        actorId: ticket.userId,
        action: "auth.sso_failed",
        detail: { reason },
        ip: clientIp(request),
      });

      return resultPage(
        reply,
        403,
        `Company account verification failed: ${reason === "email_mismatch" ? "this Google account doesn't match your keymember account." : "try again."}`,
      );
    };

    if (query.error !== undefined || query.code === undefined) {
      return fail("provider_error");
    }

    let result: Awaited<ReturnType<typeof context.sso.exchangeCode>>;

    try {
      result = await context.sso.exchangeCode(
        query.code,
        ticket.codeVerifier,
        ticket.nonce,
      );
    } catch (error) {
      if (error instanceof OidcError) {
        request.log.warn({ reason: error.message }, "SSO check failed");

        return fail("invalid_token");
      }

      throw error;
    }

    const { identity, refreshToken } = result;

    if (identity.email !== ticket.email) {
      return fail("email_mismatch");
    }

    // The provider account is bound on first use; a reassigned email cannot take over later
    if (
      ticket.boundSubject !== undefined &&
      ticket.boundSubject !== identity.subject
    ) {
      return fail("subject_mismatch");
    }

    if (
      await repositories.sso.subjectTakenByOther(
        identity.subject,
        ticket.userId,
      )
    ) {
      return fail("subject_in_use");
    }

    await repositories.sso.verifyTicket(
      ticket.id,
      identity.subject,
      sealRefreshToken(context, refreshToken, identity.subject),
    );
    await repositories.audit.record({
      orgId: ticket.orgId,
      actorId: ticket.userId,
      action: "auth.sso_verified",
      detail: { kind: ticket.kind },
      ip: clientIp(request),
    });

    return resultPage(
      reply,
      200,
      "Your company account is verified. Close this window and return to keymember.",
    );
  });

  app.post("/api/auth/sso/finish", async (request, reply) => {
    const input = parseBody(
      z.object({
        ticketId: identifier,
        ticketSecret: z.string().min(1).max(200),
      }),
      request.body,
    );
    const ticket = await context.store
      .repositories()
      .sso.ticket(input.ticketId);

    if (
      ticket === undefined ||
      !constantTimeEqual(hashToken(input.ticketSecret), ticket.secretHash)
    ) {
      throw new DomainError("not_found", "not_found", "No such SSO ticket");
    }

    if (ticket.status === "failed") {
      throw new DomainError(
        "unauthenticated",
        "sso_failed",
        `The identity provider check failed (${ticket.failure ?? "unknown"})`,
      );
    }

    if (ticket.status === "used") {
      throw new DomainError(
        "conflict",
        "conflict",
        "This SSO ticket was already used",
      );
    }

    // A verified ticket must be collected in time too, or it would stay redeemable indefinitely
    if (ticket.expiresAt <= context.now()) {
      throw new DomainError("gone", "sso_expired", "The SSO check expired");
    }

    if (ticket.status === "pending") {
      return reply.status(202).send({ status: "pending" });
    }

    const subject = ticket.subject ?? "";
    const encryptedRefreshToken =
      ticket.encryptedRefreshToken ?? new Uint8Array();
    return context.store.transaction(async (repos) => {
      const repositories = repos;

      if (!(await repositories.sso.claimTicket(ticket.id))) {
        throw new DomainError(
          "conflict",
          "conflict",
          "This SSO ticket was already used",
        );
      }

      // Another ticket may have bound a different provider account since this one was checked
      if (
        (await repositories.sso.bindSubject(ticket.userId, subject)) !== subject
      ) {
        throw new DomainError(
          "unauthenticated",
          "sso_failed",
          "The identity provider account does not match this keymember account",
        );
      }

      if (ticket.kind === "link") {
        const familyId = ticket.familyId ?? "";

        if (!(await repositories.sessions.isFamilyActive(familyId))) {
          throw new DomainError(
            "unauthenticated",
            "unauthorized",
            "That login has ended",
          );
        }

        await repositories.sso.putLink(familyId, ticket.userId, {
          subject,
          encryptedRefreshToken,
          checkedAt: context.now(),
        });

        return { status: "linked" };
      }

      const user = await repositories.users.loginAccount({
        id: ticket.userId,
      });

      // The membership may have been suspended while the user was at the provider
      if (user === undefined || user.status === "suspended") {
        throw new DomainError(
          "forbidden",
          "membership_ended",
          "Membership is suspended",
        );
      }

      return completeLogin(
        repositories,
        context,
        clientIp(request),
        user,
        {
          deviceId: ticket.deviceId ?? "",
          deviceName: ticket.deviceName ?? "",
        },
        { subject, encryptedRefreshToken },
      );
    });
  });

  app.post("/api/auth/sso/link", async (request) => {
    const actor = await requireActor(context, request, {
      confirmed: false,
      allowWithoutTotp: true,
      allowWithoutSso: true,
    });

    return createSsoTicket(context.store.repositories().sso, context, {
      kind: "link",
      userId: actor.userId,
      familyId: actor.familyId,
    });
  });
}
