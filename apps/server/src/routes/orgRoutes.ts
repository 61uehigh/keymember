import type { MemberInvite } from "@keymember/core";
import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { callerOf, requireActor } from "../http/AppContext.js";
import type { AppContext } from "../http/AppContext.js";
import { b64, bytes, identifier, parseBody } from "../http/codec.js";
import { DomainError } from "../domain/DomainError.js";
import { Invitations } from "../services/org/Invitations.js";
import { MemberCertification } from "../services/org/MemberCertification.js";
import { Offboarding } from "../services/org/Offboarding.js";
import { OrgSettings } from "../services/org/OrgSettings.js";

/**
 * ### registerOrgRoutes
 *
 * Registers organisation routes: member directory, invites, member confirmation and suspension,
 * the recovery key and policies; the services under `services/org` hold the rules.
 *
 * @param app Fastify instance to register on
 * @param context Shared dependencies
 */
export function registerOrgRoutes(
  app: FastifyInstance,
  context: AppContext,
): void {
  const invitations = new Invitations(context);
  const certification = new MemberCertification(context);
  const offboarding = new Offboarding(context);
  const settings = new OrgSettings(context, context.sso !== undefined);

  app.get("/api/org", async (request) => {
    // Unconfirmed members need the directory too: it is where they find the admin keys to pin
    const actor = await requireActor(context, request, {
      confirmed: false,
      allowWithoutTotp: true,
    });
    const { memberships, organizations, sso } = context.store.repositories();
    const org = await organizations.profile(actor.orgId);

    if (org === undefined) {
      throw new DomainError("not_found", "not_found", "No organisation");
    }

    const recoveryCopy = await organizations.recoveryKeyCopy(
      actor.orgId,
      actor.userId,
    );
    const ssoLinked = (await sso.link(actor.familyId)) !== undefined;
    const members = await memberships.directory(actor.orgId);

    return {
      org: { id: org.id, name: org.name },
      policies: {
        requireTotp: org.requireTotp,
        requireSso: org.requireSso,
        ssoAvailable: context.sso !== undefined,
        ssoLinked,
      },
      recoveryKey:
        org.recoveryKey === undefined
          ? null
          : {
              publicKey: b64(org.recoveryKey.publicKey),
              signature: b64(org.recoveryKey.signature),
              signerId: org.recoveryKey.signerId,
              wrappedPrivateKey:
                recoveryCopy === undefined ? null : b64(recoveryCopy),
            },
      members: members.map((member) => ({
        userId: member.userId,
        email: member.email,
        name: member.name,
        role: member.role,
        status: member.status,
        publicBundle: {
          userId: member.userId,
          encryptionPublicKey: b64(member.encryptionPublicKey),
          signingPublicKey: b64(member.signingPublicKey),
          keysetVersion: member.keysetVersion,
        },
        selfSignature: b64(member.selfSignature),
        certificate: member.certificate ?? null,
        certificateSignature:
          member.certificateSignature === undefined
            ? null
            : b64(member.certificateSignature),
        invite:
          member.invite === undefined
            ? null
            : {
                statement: member.invite.statement,
                signature: b64(member.invite.signature),
                proof:
                  member.invite.proof === undefined
                    ? null
                    : b64(member.invite.proof),
              },
      })),
    };
  });

  app.post("/api/org/invites", async (request, reply) => {
    const caller = callerOf(
      await requireActor(context, request, { admin: true }),
      request,
    );
    const input = parseBody(
      z.object({
        email: z.email().transform((value) => value.toLowerCase()),
        role: z.enum(["admin", "member"]),
        // The admin's signed statement of email and role; certification relies on it, not on the server
        statement: z.object({
          orgId: identifier,
          email: z.string(),
          role: z.enum(["admin", "member"]),
          issuerId: identifier,
          issuedAt: z.number().int().min(0),
          nonce: z.string().min(16).max(64).optional(),
        }),
        signature: bytes(64),
      }),
      request.body,
    );
    const { nonce, ...fields } = input.statement;
    const statement: MemberInvite =
      nonce === undefined ? fields : { ...fields, nonce };
    const issued = await invitations.invite(caller, {
      email: input.email,
      role: input.role,
      statement,
      signature: input.signature,
    });

    return reply.status(201).send({
      inviteToken: issued.token,
      expiresAt: issued.expiresAt.toISOString(),
    });
  });

  app.post("/api/org/members/:userId/confirm", async (request, reply) => {
    const { userId } = parseBody(
      z.object({ userId: identifier }),
      request.params,
    );
    const input = parseBody(
      z.object({
        certificate: z.object({
          orgId: z.string(),
          userId: identifier,
          email: z.string(),
          encryptionPublicKey: bytes(32),
          signingPublicKey: bytes(32),
          keysetVersion: z.number().int().min(1),
          role: z.enum(["owner", "admin", "member"]),
          issuerId: identifier,
          issuedAt: z.number().int().min(0),
        }),
        signature: bytes(64),
        recoveryKeyWrap: bytes(undefined, 4096).optional(),
      }),
      request.body,
    );

    // The owner certifies their own keys once, right after bootstrap; everyone else needs a confirmed admin
    const actor = await requireActor(context, request, {
      confirmed: input.certificate.issuerId !== userId,
      admin: true,
    });

    await certification.certify(callerOf(actor, request), userId, {
      certificate: input.certificate,
      signature: input.signature,
      recoveryKeyWrap: input.recoveryKeyWrap,
    });

    return reply.status(204).send();
  });

  app.post("/api/org/members/:userId/suspend", async (request, reply) => {
    const caller = callerOf(
      await requireActor(context, request, { admin: true }),
      request,
    );
    const { userId } = parseBody(
      z.object({ userId: identifier }),
      request.params,
    );

    return reply.status(200).send(await offboarding.suspend(caller, userId));
  });

  app.post("/api/org/recovery-key", async (request, reply) => {
    const caller = callerOf(
      await requireActor(context, request, { admin: true }),
      request,
    );
    const input = parseBody(
      z.object({
        publicKey: bytes(32),
        signature: bytes(64),
        wrappedPrivateKey: bytes(undefined, 4096),
      }),
      request.body,
    );

    await settings.setRecoveryKey(caller, input);

    return reply.status(204).send();
  });

  app.put("/api/org/policies", async (request, reply) => {
    const actor = await requireActor(context, request, { admin: true });
    const input = parseBody(
      z.object({
        requireTotp: z.boolean().optional(),
        requireSso: z.boolean().optional(),
      }),
      request.body,
    );

    await settings.updatePolicies(
      callerOf(actor, request),
      actor.familyId,
      input,
    );

    return reply.status(204).send();
  });
}
