import { decodeRoots, mergeRoots } from "@keymember/client";
import { z } from "zod";

const STORAGE_KEY = "keymember.device.v1";

const deviceSchema = z.object({
  deviceId: z.string(),
  email: z.string().optional(),
  secretKey: z.string().optional(),
  roots: z.record(z.string(), z.string()),
});

/**
 * ### DeviceState
 *
 * What this browser remembers between visits: its device id, the account it signs in to,
 * that account's Secret Key, and the pinned owner key. Never the password, tokens or vault data.
 * Stored in localStorage, so anyone with access to this browser profile (or an XSS bug)
 * can read the Secret Key; the password still protects the account.
 */
export type DeviceState = z.infer<typeof deviceSchema>;

/**
 * ### loadDevice
 *
 * Reads the device state, creating a fresh device id when nothing valid is stored.
 *
 * @returns The device state
 */
export function loadDevice(): DeviceState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const parsed = deviceSchema.safeParse(
      raw === null ? undefined : JSON.parse(raw),
    );

    if (parsed.success) {
      return parsed.data;
    }
  } catch {
    // Storage can be disabled or corrupted; starting as a new device is the safe fallback
  }

  return { deviceId: crypto.randomUUID(), roots: {} };
}

/**
 * ### saveDevice
 *
 * Persists the device state. Failures (private mode, full storage) are ignored: the app
 * keeps working and only asks for the Secret Key again next time.
 *
 * @param state State to store
 */
export function saveDevice(state: DeviceState): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
    // Remembering the device is a convenience; losing it must not break the session
  }
}

/**
 * ### forgetDevice
 *
 * Removes the stored Secret Key and pinned keys from this browser.
 */
export function forgetDevice(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Nothing stored, nothing to forget
  }
}

/**
 * ### rootsOf
 *
 * Decodes the pinned owner keys for the SDK.
 *
 * @param state Device state
 * @returns Pinned signing keys keyed by user id
 */
export function rootsOf(state: DeviceState): Map<string, Uint8Array> {
  return decodeRoots(state.roots);
}

/**
 * ### withRoots
 *
 * Pins issuer keys, as an invite link, the account's saved roots or a compared fingerprint
 * provide them.
 *
 * @param state Current device state
 * @param roots Issuer keys by user id
 * @returns The state with every key pinned
 */
export function withRoots(
  state: DeviceState,
  roots: ReadonlyMap<string, Uint8Array>,
): DeviceState {
  return { ...state, roots: mergeRoots(state.roots, roots) };
}
