import { readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { z } from "zod";

import type { BiometricPrompt, SecretBox } from "./platform.js";

/**
 * ### BIOMETRIC_PASSWORD_MAX_AGE_MS
 *
 * Touch ID unlocks only within this long after the password was last entered: 14 days.
 */
export const BIOMETRIC_PASSWORD_MAX_AGE_MS = 14 * 24 * 60 * 60 * 1000;

const sealedSchema = z.object({
  passwordAt: z.number(),
  snapshot: z.unknown(),
});

/**
 * ### Snapshottable
 *
 * The one thing Touch ID unlock needs from a session: its snapshot.
 */
export interface Snapshottable {
  toSnapshot(): unknown;
}

/**
 * ### BiometricOpening
 *
 * A sealed session that Touch ID opened, or why it could not be used.
 * `password_required` means the snapshot is gone; the user must unlock with the password.
 */
export type BiometricOpening =
  | {
      readonly ok: true;
      readonly snapshot: unknown;
      readonly passwordAt: number;
    }
  | {
      readonly ok: false;
      readonly code: "unavailable" | "cancelled" | "password_required";
      readonly message: string;
    };

/**
 * ### BiometricUnlock
 *
 * Touch ID unlock: a session snapshot sealed with the OS secret box in `unlock.bin`, opened
 * only after Touch ID passes and only within {@link BIOMETRIC_PASSWORD_MAX_AGE_MS} of the last
 * password. A snapshot that is too old or no longer opens is deleted.
 */
export class BiometricUnlock {
  readonly #path: string;
  readonly #secretBox: SecretBox | undefined;
  readonly #prompt: BiometricPrompt | undefined;

  /**
   * ### constructor
   *
   * @param dataDir Directory holding the sealed snapshot
   * @param secretBox OS secret box, if there is one
   * @param prompt Touch ID, if the computer has it
   */
  constructor(
    dataDir: string,
    secretBox: SecretBox | undefined,
    prompt: BiometricPrompt | undefined,
  ) {
    this.#path = join(dataDir, "unlock.bin");
    this.#secretBox = secretBox;
    this.#prompt = prompt;
  }

  /**
   * ### available
   *
   * Whether this computer can offer Touch ID unlock at all.
   */
  get available(): boolean {
    return this.#prompt !== undefined && this.#secretBox !== undefined;
  }

  /**
   * ### isEnabled
   *
   * Whether a sealed snapshot exists.
   *
   * @returns Whether Touch ID unlock is on
   */
  async isEnabled(): Promise<boolean> {
    if (this.#secretBox === undefined) {
      return false;
    }

    try {
      await readFile(this.#path);

      return true;
    } catch {
      // No snapshot file: Touch ID unlock is off
      return false;
    }
  }

  /**
   * ### seal
   *
   * Stores the session's snapshot sealed by the OS secret box. Called on enabling and again
   * whenever the session's tokens change, so the snapshot stays usable.
   *
   * @param session Session to snapshot
   * @param passwordAt When the password was last entered
   */
  async seal(session: Snapshottable, passwordAt: number): Promise<void> {
    if (this.#secretBox === undefined) {
      throw new Error("Touch ID unlock is not available on this computer");
    }

    const temporary = `${this.#path}.tmp`;

    // Written aside and renamed, so a crash mid-write never leaves a half snapshot behind
    await writeFile(
      temporary,
      this.#secretBox.encrypt(
        JSON.stringify({ passwordAt, snapshot: session.toSnapshot() }),
      ),
      { mode: 0o600 },
    );
    await rename(temporary, this.#path);
  }

  /**
   * ### forget
   *
   * Deletes the sealed snapshot.
   */
  async forget(): Promise<void> {
    await rm(this.#path, { force: true });
  }

  /**
   * ### open
   *
   * Asks for Touch ID and opens the sealed snapshot.
   *
   * @returns The snapshot and when the password was last entered, or why not
   */
  async open(): Promise<BiometricOpening> {
    if (this.#prompt === undefined || this.#secretBox === undefined) {
      return {
        ok: false,
        code: "unavailable",
        message: "Touch ID isn't available.",
      };
    }

    if (!(await this.#prompt("unlock keymember"))) {
      return {
        ok: false,
        code: "cancelled",
        message: "Touch ID was cancelled.",
      };
    }

    let sealed: z.infer<typeof sealedSchema>;

    try {
      sealed = sealedSchema.parse(
        JSON.parse(this.#secretBox.decrypt(await readFile(this.#path))),
      );
    } catch {
      // A snapshot that no longer opens is useless from now on
      await this.forget();

      return {
        ok: false,
        code: "password_required",
        message: "Unlock with your password.",
      };
    }

    if (Date.now() - sealed.passwordAt > BIOMETRIC_PASSWORD_MAX_AGE_MS) {
      await this.forget();

      return {
        ok: false,
        code: "password_required",
        message:
          "For security, unlock with your password once every two weeks.",
      };
    }

    return {
      ok: true,
      snapshot: sealed.snapshot,
      passwordAt: sealed.passwordAt,
    };
  }
}
