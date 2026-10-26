import { ApiError, logIn } from "@keymember/client";
import type { DeviceTrust, Session, Transport } from "@keymember/client";

import { loadConfig, secretKeyOf } from "./CliConfig.js";
import type { CliConfig } from "./CliConfig.js";
import type { CliDependencies } from "./CliDependencies.js";

/**
 * ### SessionWork
 *
 * Work a command does while the vault is unlocked.
 */
export type SessionWork = (
  session: Session,
  config: CliConfig,
) => Promise<void>;

/**
 * ### SessionRunner
 *
 * Loads this device's config and logs in for one command. A session never outlives the
 * command that opened it, so no unlocked state stays behind in the process.
 */
export class SessionRunner {
  readonly #deps: Pick<
    CliDependencies,
    "io" | "configPath" | "transportFor" | "openUrl"
  >;
  readonly #trust: Pick<DeviceTrust, "apply">;

  /**
   * ### constructor
   *
   * @param deps Terminal, config location, transport factory and URL opener
   * @param trust The organisation keys this device trusts
   */
  constructor(
    deps: Pick<
      CliDependencies,
      "io" | "configPath" | "transportFor" | "openUrl"
    >,
    trust: Pick<DeviceTrust, "apply">,
  ) {
    this.#deps = deps;
    this.#trust = trust;
  }

  /**
   * ### requireConfig
   *
   * Loads the config or tells the user to run `init`.
   *
   * @returns The stored config
   */
  async requireConfig(): Promise<CliConfig> {
    const config = await loadConfig(this.#deps.configPath);

    if (config === undefined) {
      throw new Error("Run `keymember init <server-url>` first");
    }

    return config;
  }

  /**
   * ### transport
   *
   * Transport for the configured server.
   *
   * @param config Stored config
   * @returns The transport
   */
  transport(config: CliConfig): Transport {
    return this.#deps.transportFor(config.serverUrl);
  }

  /**
   * ### logIn
   *
   * Logs in with the stored account, asking for a two-factor code when the server requires one.
   *
   * @param config Stored config with an account
   * @param password Account password
   * @param requestSso Whether to confirm the company account even when the policy does not ask
   * @returns The unlocked session
   */
  async logIn(
    config: CliConfig,
    password: string,
    requestSso = false,
  ): Promise<Session> {
    const input = {
      email: config.email ?? "",
      password,
      secretKey: secretKeyOf(config),
      deviceId: config.deviceId,
      deviceName: "keymember CLI",
      requestSso,
      sso: {
        onChallenge: ({ path }: { path: string }) => {
          const url = new URL(path, config.serverUrl).toString();

          this.#deps.io.print(
            `Confirm your company account in the browser (waiting): ${url}`,
          );
          this.#deps.openUrl?.(url);
        },
      },
    };

    try {
      return await logIn(this.transport(config), input);
    } catch (error) {
      if (error instanceof ApiError && error.code === "totp_required") {
        return logIn(this.transport(config), {
          ...input,
          totp: await this.#deps.io.ask("Two-factor code: "),
        });
      }

      throw error;
    }
  }

  /**
   * ### withSession
   *
   * Asks for the password, logs in with this device's pinned roots, runs `work`, and always
   * logs out afterwards. A failed logout is only warned about: it must not hide what `work` did
   * or threw, and the server ends an abandoned login on its own.
   *
   * @param work Work to do while unlocked
   * @param options Whether the login must go through the company account
   */
  async withSession(
    work: SessionWork,
    options: { requestSso?: boolean } = {},
  ): Promise<void> {
    const config = await this.requireConfig();
    const session = await this.logIn(
      config,
      await this.#deps.io.askSecret("Password: "),
      options.requestSso ?? false,
    );

    await this.#trust.apply(session);

    try {
      await work(session, config);
    } finally {
      await session.logOut().catch((error: unknown) => {
        this.#deps.io.warn(
          `Could not log out (${error instanceof Error ? error.message : String(error)}); the login expires on its own`,
        );
      });
    }
  }
}
