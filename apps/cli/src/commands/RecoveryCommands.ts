import type { CommandDeps } from "./CommandDeps.js";
import { findMember } from "../lookups.js";

/**
 * ### RecoveryCommands
 *
 * Admin side of an account recovery: request, approve with a second admin, complete and
 * cancel. The member side is `AccountCommands.recover`.
 */
export class RecoveryCommands {
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
   * ### list
   *
   * Lists recent account recoveries.
   */
  async list(): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      for (const recovery of await session.recovery().list()) {
        this.#deps.io.print(
          `${recovery.id}\t${recovery.status}\t${recovery.email}\t${recovery.createdAt}`,
        );
      }
    });
  }

  /**
   * ### request
   *
   * Starts a recovery for a member; a second admin must approve it.
   *
   * @param email Member to recover
   */
  async request(email: string): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      const member = findMember(await session.directory(), email);

      this.#deps.io.print(await session.recovery().request(member.userId));
      this.#deps.io.print("Ask a different admin to approve it.");
    });
  }

  /**
   * ### approve
   *
   * Approves a recovery and prints the one-time token for the member.
   *
   * @param recoveryId Recovery to approve
   */
  async approve(recoveryId: string): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      const { recoveryToken, expiresAt } = await session
        .recovery()
        .approve(recoveryId);

      this.#deps.io.print(`Recovery token (expires ${expiresAt}):`);
      this.#deps.io.print(recoveryToken);
      this.#deps.io.print(
        "Hand it to the member in person; they run `keymember recover --token …`.",
      );
    });
  }

  /**
   * ### complete
   *
   * Restores the member's vault access after they re-enrolled and were certified again.
   *
   * @param recoveryId Recovery to complete
   */
  async complete(recoveryId: string): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      const restored = await session.recovery().complete(recoveryId);

      this.#deps.io.print(
        `Recovery completed; ${String(restored.vaults)} vault(s) and ${String(restored.groups)} group(s) restored`,
      );
    });
  }

  /**
   * ### cancel
   *
   * Cancels a recovery.
   *
   * @param recoveryId Recovery to cancel
   */
  async cancel(recoveryId: string): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      await session.recovery().cancel(recoveryId);
      this.#deps.io.print("Recovery cancelled");
    });
  }
}
