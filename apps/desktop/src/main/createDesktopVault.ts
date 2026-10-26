import { DeviceTrust } from "@keymember/client";

import { BiometricUnlock } from "./BiometricUnlock.js";
import { ClipboardGuard } from "./ClipboardGuard.js";
import { DesktopVault } from "./DesktopVault.js";
import { DeviceConfigStore } from "./DeviceConfigStore.js";
import { configDeviceRoots } from "./deviceRoots.js";
import type { PlatformServices } from "./platform.js";
import { VaultKeyring } from "./ssh/VaultKeyring.js";

/**
 * ### createDesktopVault
 *
 * Builds a vault and its parts from the operating system's services. The one place that
 * decides which concrete part does each job.
 *
 * @param platform Operating-system services
 * @returns The vault
 */
export function createDesktopVault(platform: PlatformServices): DesktopVault {
  const config = new DeviceConfigStore(platform.dataDir, platform.secretBox);

  return new DesktopVault({
    config,
    trust: new DeviceTrust(configDeviceRoots(config)),
    biometric: new BiometricUnlock(
      platform.dataDir,
      platform.secretBox,
      platform.biometric,
    ),
    clipboard: new ClipboardGuard(platform.clipboard),
    keyring: new VaultKeyring(platform.confirmSigning),
    openExternal: (url) => {
      platform.openExternal(url);
    },
  });
}
