import { decodeRoots, mergeRoots } from "@keymember/client";
import type { DeviceRoots } from "@keymember/client";

import { loadConfig, saveConfig } from "./CliConfig.js";

/**
 * ### cliDeviceRoots
 *
 * The CLI's pinned organisation keys, kept in its config file. Reads and writes the file each
 * time, since commands save other settings to it in between.
 *
 * @param configPath Config file location
 * @returns The pinned keys as {@link DeviceRoots}
 */
export function cliDeviceRoots(configPath: string): DeviceRoots {
  return {
    current: async () => {
      const config = await loadConfig(configPath);

      return config === undefined ? new Map() : decodeRoots(config.roots);
    },
    pin: async (roots) => {
      const config = await loadConfig(configPath);

      if (config === undefined) {
        throw new Error("Run `keymember init <server-url>` first");
      }

      await saveConfig(configPath, {
        ...config,
        roots: mergeRoots(config.roots, roots),
      });
    },
  };
}
