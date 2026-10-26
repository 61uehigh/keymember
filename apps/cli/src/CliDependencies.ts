import type { Transport } from "@keymember/client";

import type { Io } from "./Io.js";

/**
 * ### CliDependencies
 *
 * Everything the CLI touches outside its own logic, injectable for tests.
 */
export interface CliDependencies {
  /**
   * ### io
   *
   * Terminal interaction.
   */
  readonly io: Io;

  /**
   * ### configPath
   *
   * Config file location.
   */
  readonly configPath: string;

  /**
   * ### transportFor
   *
   * Builds a transport for a server URL.
   */
  readonly transportFor: (serverUrl: string) => Transport;

  /**
   * ### kitDirectory
   *
   * Directory the Emergency Kit PDF is written to.
   */
  readonly kitDirectory: string;

  /**
   * ### openUrl
   *
   * Opens a URL in the user's browser, for the identity-provider sign-in. The URL is always
   * printed too, so this may do nothing.
   */
  readonly openUrl?: (url: string) => void;
}
