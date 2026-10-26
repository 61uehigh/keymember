import { decodeRoots } from "@keymember/client";
import type { DeviceRoots } from "@keymember/client";
import { toBase64Url } from "@keymember/core";

import { loadDevice, saveDevice } from "./storage.js";

/**
 * ### extensionDeviceRoots
 *
 * The extension's pinned organisation keys, kept with the rest of the device settings.
 */
export const extensionDeviceRoots: DeviceRoots = {
  current: async () => decodeRoots((await loadDevice()).roots),
  pin: async (roots) => {
    const device = await loadDevice();

    await saveDevice({
      ...device,
      roots: {
        ...device.roots,
        ...Object.fromEntries(
          [...roots].map(([userId, key]) => [userId, toBase64Url(key)]),
        ),
      },
    });
  },
};
