import { describeError, inviteLinkUrl } from "@keymember/client";
import type { Session } from "@keymember/client";

import type { CommandDeps } from "./CommandDeps.js";
import { findMember } from "../lookups.js";

/**
 * ### OrgCommands
 *
 * Commands that run the organisation: the member directory, certifying and inviting members,
 * offboarding, the audit log and login policies. Everything but `members` is for admins.
 */
export class OrgCommands {
  readonly #deps: CommandDeps;

  /**
   * ### constructor
   *
   * @param deps Terminal and session access
   */
  constructor(deps: CommandDeps) {
    this.#deps = deps;
  }

  /**
   * ### members
   *
   * Lists members with whether their keys are verified from this device's trust root. For an
   * admin, first certifies the members who joined through the admin's invite links.
   */
  async members(): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      if (session.user.role !== "member") {
        await this.#certifyInvited(session);
      }

      for (const member of await session.directory()) {
        const trust =
          member.certificate === undefined ? "UNVERIFIED" : "verified";

        // Unverified fingerprints stay hidden so an admin compares with the member instead of copying
        const fingerprint =
          member.certificate === undefined ? "-" : member.fingerprint;

        this.#deps.io.print(
          `${member.email}\t${member.role}\t${member.status}\t${trust}\t${fingerprint}`,
        );
      }
    });
  }

  /**
   * ### #certifyInvited
   *
   * Certifies the members who joined by this admin's links, and says who still needs a
   * fingerprint comparison. A failure is reported without stopping the member listing.
   *
   * @param session Admin's session
   */
  async #certifyInvited(session: Session): Promise<void> {
    try {
      const result = await session.orgAdmin().certifyInvited();

      for (const email of result.certified) {
        this.#deps.io.print(`Certified ${email}, who joined by your link`);
      }

      for (const email of result.needsFingerprint) {
        this.#deps.io.print(
          `! ${email} joined by link but needs a fingerprint check: keymember certify ${email} --fingerprint <theirs>`,
        );
      }

      for (const failure of result.failed) {
        this.#deps.io.print(
          `! Could not certify ${failure.email}: ${failure.reason}`,
        );
      }
    } catch (error) {
      this.#deps.io.print(
        `! Could not certify invited members: ${describeError(error)}`,
      );
    }
  }

  /**
   * ### certify
   *
   * Certifies a member after the admin compared fingerprints with them.
   *
   * @param email Member's email
   * @param fingerprint Fingerprint the member read out
   */
  async certify(email: string, fingerprint: string): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      const member = findMember(await session.directory(), email);

      await session.orgAdmin().certify(member.userId, fingerprint);
      this.#deps.io.print(`Certified ${email}`);
    });
  }

  /**
   * ### invite
   *
   * Creates an invite and prints the link to send.
   *
   * @param email Invitee's email
   * @param role Role to grant
   */
  async invite(email: string, role: "admin" | "member"): Promise<void> {
    await this.#deps.sessions.withSession(async (session, config) => {
      const { expiresAt, link } = await session.orgAdmin().invite(email, role);
      const url = inviteLinkUrl(config.serverUrl, link);

      this.#deps.io.print(`Invite link for ${email} (expires ${expiresAt}):`);
      this.#deps.io.print(url);
      this.#deps.io.print(
        `Send it to ${email} by email or chat, not through keymember. They open it in a browser, or run \`keymember signup --link '<link>' --name <name>\`; the next time you list members, they are certified.`,
      );
    });
  }

  /**
   * ### offboard
   *
   * Offboards a member who left: suspends them, rotates their groups' keys and the keys of the
   * vaults this admin manages, and lists vaults whose managers still have to rotate them.
   *
   * @param email Member's email
   */
  async offboard(email: string): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      const directory = await session.directory();
      const member = findMember(directory, email);
      const report = await session.orgAdmin().offboard(member.userId);
      const emailOf = (userId: string): string =>
        directory.find((candidate) => candidate.userId === userId)?.email ??
        userId;

      this.#deps.io.print(
        `Suspended ${email}; rotated ${String(report.groupsRotated.length)} group key(s) and ${String(report.vaultsRotated.length)} vault key(s)`,
      );

      for (const pending of report.vaultsPending) {
        this.#deps.io.print(
          pending.managerIds.length === 0
            ? `! vault ${pending.vaultId}: no other manager is left; nobody can rotate it`
            : `! vault ${pending.vaultId}: ask ${pending.managerIds.map(emailOf).join(", ")} to rotate it`,
        );
      }
    });
  }

  /**
   * ### audit
   *
   * Prints recent audit events.
   *
   * @param limit Number of events
   */
  async audit(limit: number): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      for (const event of await session.orgAdmin().auditLog(limit)) {
        this.#deps.io.print(
          `${event.at}\t${event.action}\t${event.actorId ?? "-"}\t${event.targetId ?? "-"}`,
        );
      }
    });
  }

  /**
   * ### setPolicy
   *
   * Turns the organisation's login policies on or off. Policies left `undefined` stay as they are.
   *
   * @param policies Whether two-factor login and company-account SSO are required
   */
  async setPolicy(policies: {
    requireTotp?: boolean | undefined;
    requireSso?: boolean | undefined;
  }): Promise<void> {
    await this.#deps.sessions.withSession(
      async (session) => {
        if (policies.requireTotp !== undefined) {
          await session.orgAdmin().setRequireTotp(policies.requireTotp);
          this.#deps.io.print(
            `Two-factor login is now ${policies.requireTotp ? "required" : "optional"}`,
          );
        }

        if (policies.requireSso !== undefined) {
          await session.orgAdmin().setRequireSso(policies.requireSso);
          this.#deps.io.print(
            `Signing in with the company account is now ${policies.requireSso ? "required" : "optional"}`,
          );
        }
      },
      // Requiring SSO needs proof that it works for this admin, so this login goes through it
      { requestSso: policies.requireSso === true },
    );
  }
}
