import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import { parseSecretKey } from "@keymember/core";
import type { SecretKey } from "@keymember/core";

/**
 * ### CliConfig
 *
 * State the CLI keeps between runs. The file holds the Secret Key, so it is written with
 * mode 0600; it never holds the password, tokens or any decrypted vault data.
 */
export interface CliConfig {
  /**
   * ### serverUrl
   *
   * Server origin.
   */
  readonly serverUrl: string;

  /**
   * ### email
   *
   * Account email on this device.
   */
  readonly email?: string;

  /**
   * ### secretKey
   *
   * Formatted Secret Key of the account on this device.
   */
  readonly secretKey?: string;

  /**
   * ### deviceId
   *
   * Stable id of this device, generated on first use.
   */
  readonly deviceId: string;

  /**
   * ### roots
   *
   * Pinned issuer signing keys (base64url) keyed by user id. Pinned once, after the user
   * compared the owner's fingerprint out of band; never updated from server data.
   */
  readonly roots: Readonly<Record<string, string>>;
}

/**
 * ### defaultConfigPath
 *
 * Location of the config file: `$KEYMEMBER_CONFIG`, else `~/.config/keymember/config.json`.
 *
 * @returns The config file path
 */
export function defaultConfigPath(): string {
  return (
    process.env.KEYMEMBER_CONFIG ??
    join(homedir(), ".config", "keymember", "config.json")
  );
}

/**
 * ### loadConfig
 *
 * Reads the config file. Returns `undefined` when the CLI has not been initialised yet.
 *
 * @param path Config file path
 * @returns The stored config, or `undefined` when the file does not exist
 */
export async function loadConfig(path: string): Promise<CliConfig | undefined> {
  try {
    // The file is only ever written by saveConfig, so its shape is our own
    return JSON.parse(await readFile(path, "utf8")) as CliConfig;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }

    throw error;
  }
}

/**
 * ### saveConfig
 *
 * Writes the config file with owner-only permissions, creating its directory if needed.
 *
 * @param path Config file path
 * @param config Config to store
 */
export async function saveConfig(
  path: string,
  config: CliConfig,
): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(config, null, 2)}\n`, {
    mode: 0o600,
  });

  // writeFile keeps the mode of an existing file, so tighten it explicitly
  await chmod(path, 0o600);
}

/**
 * ### secretKeyOf
 *
 * Parses the stored Secret Key. Throws when the device has no account yet.
 *
 * @param config Stored config
 * @returns The Secret Key
 */
export function secretKeyOf(config: CliConfig): SecretKey {
  const key =
    config.secretKey === undefined
      ? undefined
      : parseSecretKey(config.secretKey);

  if (key === undefined) {
    throw new Error(
      "No account on this device yet; run `keymember signup` or `keymember add-device`",
    );
  }

  return key;
}
