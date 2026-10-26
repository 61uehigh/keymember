import type { Io } from "../Io.js";
import type { SessionRunner } from "../SessionRunner.js";

/**
 * ### CommandDeps
 *
 * What a command set needs to run commands against an unlocked vault.
 */
export interface CommandDeps {
  /**
   * ### io
   *
   * Terminal interaction.
   */
  readonly io: Io;

  /**
   * ### sessions
   *
   * Opens a session for one command and closes it afterwards.
   */
  readonly sessions: Pick<SessionRunner, "withSession">;
}
