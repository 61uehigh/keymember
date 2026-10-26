import { copyFile, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { decodeRoots, mergeRoots } from "@keymember/client";
import { z } from "zod";

import type { SecretBox } from "./platform.js";

const configSchema = z.object({
  deviceId: z.string(),
  serverUrl: z.string().optional(),
  email: z.string().optional(),
  // Secret Key, encrypted with the OS secret box where available
  secretKey: z.object({ sealed: z.boolean(), value: z.string() }).optional(),
  roots: z.record(z.string(), z.string()),
});

type Config = z.infer<typeof configSchema>;

/**
 * ### DeviceConfig
 *
 * What this computer remembers about its keymember account.
 */
export interface DeviceConfig {
  /** Random id this computer logs in with, kept across servers */
  readonly deviceId: string;
  /** Server origin, until the user sets one */
  readonly serverUrl: string | undefined;
  /** Email of the last successful login */
  readonly email: string | undefined;
  /** Owner signing keys the user pinned, by user id; empty until pinned */
  readonly roots: ReadonlyMap<string, Uint8Array>;
}

/**
 * ### DeviceConfigStore
 *
 * The desktop app's `config.json`, readable only by the user: the device id, the server, the
 * pinned owner keys, and the Secret Key sealed with the OS secret box. It never stores the
 * Secret Key in the clear while a secret box exists. A sealed key the box will not open is kept
 * (the user may only have refused the Keychain once) but not asked for again until a login
 * stores it afresh.
 */
export class DeviceConfigStore {
  readonly #path: string;
  readonly #secretBox: SecretBox | undefined;
  #config: Config | undefined;
  // Set when the secret box refused the stored Secret Key, so the Keychain is not asked again
  #unreadable = false;

  /**
   * ### constructor
   *
   * @param dataDir Directory holding `config.json`
   * @param secretBox OS secret box for the Secret Key, if there is one
   */
  constructor(dataDir: string, secretBox: SecretBox | undefined) {
    this.#path = join(dataDir, "config.json");
    this.#secretBox = secretBox;
  }

  /**
   * ### current
   *
   * The configuration, created with a fresh device id on first run.
   *
   * @returns The configuration
   */
  async current(): Promise<DeviceConfig> {
    const config = await this.#load();

    return {
      deviceId: config.deviceId,
      serverUrl: config.serverUrl,
      email: config.email,
      roots: decodeRoots(config.roots),
    };
  }

  /**
   * ### switchServer
   *
   * Points the device at a server. Moving to another server forgets everything but the device
   * id: the email, Secret Key and pinned owner keys belong to the old organisation.
   *
   * @param origin Server origin
   * @returns Whether the server changed
   */
  async switchServer(origin: string): Promise<boolean> {
    const config = await this.#load();

    if (config.serverUrl === origin) {
      return false;
    }

    await this.#save({
      deviceId: config.deviceId,
      serverUrl: origin,
      roots: {},
    });

    return true;
  }

  /**
   * ### rememberLogin
   *
   * Keeps the email and the Secret Key of a login that worked. When the secret box refuses,
   * the Secret Key is never stored in the clear: an earlier sealed copy stays, and otherwise the
   * user types it at every unlock.
   *
   * @param email Normalised email
   * @param secretKey Formatted Secret Key
   */
  async rememberLogin(email: string, secretKey: string): Promise<void> {
    const { secretKey: previous, ...rest } = await this.#load();
    const sealed = this.#seal(secretKey);
    // A refused Keychain keeps whatever was stored before rather than losing it
    const stored = sealed ?? previous;

    if (sealed !== undefined) {
      this.#unreadable = false;
    }

    await this.#save({
      ...rest,
      email,
      ...(stored === undefined ? {} : { secretKey: stored }),
    });
  }

  /**
   * ### pinRoots
   *
   * Adds organisation signing keys this computer trusts.
   *
   * @param roots Signing keys by user id
   */
  async pinRoots(roots: ReadonlyMap<string, Uint8Array>): Promise<void> {
    const config = await this.#load();

    await this.#save({ ...config, roots: mergeRoots(config.roots, roots) });
  }

  /**
   * ### hasSecretKey
   *
   * Whether a Secret Key is remembered and was not refused, without touching the Keychain, so
   * showing the window never prompts for it.
   *
   * @returns Whether an unlock can skip asking for the Secret Key
   */
  async hasSecretKey(): Promise<boolean> {
    return (await this.#load()).secretKey !== undefined && !this.#unreadable;
  }

  /**
   * ### secretKey
   *
   * The remembered Secret Key. When the secret box will not open it (the user refused the
   * Keychain, or a rebuilt app is no longer trusted), the key is reported missing for the rest
   * of this run, so the window asks for it and the next login seals it anew. The stored copy is
   * kept: a single refusal must not cost the user their remembered key.
   *
   * @returns Formatted Secret Key, if remembered and readable
   */
  async secretKey(): Promise<string | undefined> {
    const stored = (await this.#load()).secretKey;

    if (stored === undefined || this.#unreadable) {
      return undefined;
    }

    if (!stored.sealed) {
      return stored.value;
    }

    try {
      const opened = this.#secretBox?.decrypt(
        new Uint8Array(Buffer.from(stored.value, "base64")),
      );

      if (opened !== undefined) {
        return opened;
      }
    } catch {
      // Refused or unreadable; reported below as missing, and not retried during this run
    }

    this.#unreadable = true;

    return undefined;
  }

  /**
   * ### #seal
   *
   * Encrypts the Secret Key for the file when the OS secret box is available.
   *
   * @param secretKey Formatted Secret Key
   * @returns Stored form, or `undefined` when the secret box refused
   */
  #seal(secretKey: string): { sealed: boolean; value: string } | undefined {
    const box = this.#secretBox;

    if (box === undefined) {
      return { sealed: false, value: secretKey };
    }

    try {
      return {
        sealed: true,
        value: Buffer.from(box.encrypt(secretKey)).toString("base64"),
      };
    } catch {
      // Keychain access was denied
      return undefined;
    }
  }

  /**
   * ### #load
   *
   * Reads the file once, creating a fresh configuration on first run.
   *
   * @returns The configuration
   */
  async #load(): Promise<Config> {
    if (this.#config !== undefined) {
      return this.#config;
    }

    let text: string | undefined;

    try {
      text = await readFile(this.#path, "utf8");
    } catch (error) {
      // Node's fs errors carry a `code`; only "no such file" means a first run
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
    }

    if (text === undefined) {
      this.#config = { deviceId: crypto.randomUUID(), roots: {} };

      return this.#config;
    }

    const parsed = configSchema.safeParse(parseJson(text));

    if (parsed.success) {
      this.#config = parsed.data;

      return this.#config;
    }

    // Keep the damaged file for inspection rather than losing the pinned owner keys silently
    const kept = `${this.#path}.damaged-${String(Date.now())}`;

    await copyFile(this.#path, kept);
    console.warn(
      `keymember: config.json could not be read and was set aside as ${kept}; starting fresh`,
    );
    this.#config = { deviceId: crypto.randomUUID(), roots: {} };

    return this.#config;
  }

  /**
   * ### #save
   *
   * Writes the configuration, readable only by the user.
   *
   * @param config New configuration
   */
  async #save(config: Config): Promise<void> {
    const temporary = `${this.#path}.tmp`;

    this.#config = config;
    // Written aside and renamed, so a crash mid-write never leaves a truncated config
    await writeFile(temporary, JSON.stringify(config, null, 2), {
      mode: 0o600,
    });
    await rename(temporary, this.#path);
  }
}

/**
 * ### parseJson
 *
 * Parses JSON, treating malformed text like any other invalid config.
 *
 * @param text File contents
 * @returns The parsed value, or `undefined` when the text is not JSON
 */
function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    // Malformed JSON fails the schema check like any other damage
    return undefined;
  }
}
