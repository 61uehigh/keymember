import type { DeviceRoots } from "@keymember/client";

import type { DeviceConfigStore } from "./DeviceConfigStore.js";

/**
 * ### configDeviceRoots
 *
 * The desktop app's pinned organisation keys, kept in its config file.
 *
 * @param config The app's config
 * @returns The pinned keys as {@link DeviceRoots}
 */
export function configDeviceRoots(
  config: Pick<DeviceConfigStore, "current" | "pinRoots">,
): DeviceRoots {
  return {
    current: async () => (await config.current()).roots,
    pin: (roots) => config.pinRoots(roots),
  };
}
