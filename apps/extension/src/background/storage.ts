import { z } from "zod";

const deviceSchema = z.object({
  serverUrl: z.string().optional(),
  deviceId: z.string(),
  email: z.string().optional(),
  secretKey: z.string().optional(),
  roots: z.record(z.string(), z.string()),
});

/**
 * ### Device
 *
 * Settings this browser keeps across restarts in `chrome.storage.local`: server, account
 * email, Secret Key and pinned owner key. Never the password, tokens or vault data.
 */
export type Device = z.infer<typeof deviceSchema>;

const menuTokenSchema = z.object({
  tabId: z.number(),
  frameId: z.number(),
  url: z.string(),
  kind: z.enum(["username", "password", "otp"]),
  expiresAt: z.number(),
});

/**
 * ### MenuToken
 *
 * What a one-time inline-menu token authorises: filling one frame of one tab, at the URL it
 * had when the menu opened, with one kind of value.
 */
export type MenuToken = z.infer<typeof menuTokenSchema>;

const pendingSchema = z.object({
  id: z.string(),
  tabId: z.number(),
  url: z.string(),
  username: z.string().optional(),
  password: z.string(),
  createdAt: z.number(),
});

/**
 * ### PendingSave
 *
 * Credentials a page just submitted, held in memory-only storage for a short time so the user
 * can save them from the popup.
 */
export type PendingSave = z.infer<typeof pendingSchema>;

/**
 * ### loadDevice
 *
 * Reads the device settings, creating a device id on first use.
 *
 * @returns The device settings
 */
export async function loadDevice(): Promise<Device> {
  const { device } = await chrome.storage.local.get("device");
  const parsed = deviceSchema.safeParse(device);

  if (parsed.success) {
    return parsed.data;
  }

  const fresh: Device = { deviceId: crypto.randomUUID(), roots: {} };

  await chrome.storage.local.set({ device: fresh });

  return fresh;
}

/**
 * ### saveDevice
 *
 * Persists the device settings.
 *
 * @param device Settings to store
 */
export async function saveDevice(device: Device): Promise<void> {
  await chrome.storage.local.set({ device });
}

/**
 * ### sessionValue
 *
 * Reads one value from `chrome.storage.session`, which lives in memory only, survives the
 * service worker being stopped, and is wiped when the browser closes.
 *
 * @param key Storage key
 * @returns The stored value, unvalidated
 */
export async function sessionValue(key: string): Promise<unknown> {
  return (await chrome.storage.session.get<Record<string, unknown>>(key))[key];
}

/**
 * ### setSessionValue
 *
 * Writes or removes one value in `chrome.storage.session`.
 *
 * @param key Storage key
 * @param value Value to store, or `undefined` to remove it
 */
export async function setSessionValue(
  key: string,
  value: unknown,
): Promise<void> {
  if (value === undefined) {
    await chrome.storage.session.remove(key);
  } else {
    await chrome.storage.session.set({ [key]: value });
  }
}

/**
 * ### loadMenuTokens
 *
 * Reads unexpired menu tokens.
 *
 * @param now Current time in milliseconds
 * @returns Tokens keyed by token string
 */
export async function loadMenuTokens(
  now: number,
): Promise<Record<string, MenuToken>> {
  const parsed = z
    .record(z.string(), menuTokenSchema)
    .safeParse(await sessionValue("menuTokens"));

  return Object.fromEntries(
    Object.entries(parsed.success ? parsed.data : {}).filter(
      ([, token]) => token.expiresAt > now,
    ),
  );
}

/**
 * ### loadPending
 *
 * Reads unexpired pending saves, and removes expired ones from storage.
 *
 * @param now Current time in milliseconds
 * @param ttlMs How long a pending save stays offered
 * @returns Pending saves, newest first
 */
export async function loadPending(
  now: number,
  ttlMs: number,
): Promise<Array<PendingSave>> {
  const parsed = z
    .array(pendingSchema)
    .safeParse(await sessionValue("pending"));
  const stored = parsed.success ? parsed.data : [];
  const live = stored
    .filter((entry) => now - entry.createdAt < ttlMs)
    .sort((a, b) => b.createdAt - a.createdAt);

  // Expired entries hold plaintext passwords; drop them from storage, not just from the answer
  if (live.length !== stored.length) {
    await setSessionValue("pending", live.length === 0 ? undefined : live);
  }

  return live;
}

/**
 * ### KEPT_ACROSS_LOCK
 *
 * Session values that outlive a lock: the clipboard fingerprint, so a copied secret is still
 * cleared after locking, and the unlock counter, which must only ever grow so a passkey ceremony
 * can tell whether the user unlocked during it.
 */
const KEPT_ACROSS_LOCK: ReadonlySet<string> = new Set([
  "clipboard",
  "unlockCount",
]);

/**
 * ### clearUnlockedState
 *
 * Removes everything an unlocked session left in memory-only storage: the session snapshot,
 * pending saves, menu tokens and waiting passkey requests.
 */
export async function clearUnlockedState(): Promise<void> {
  const stored =
    await chrome.storage.session.get<Record<string, unknown>>(null);
  const keys = Object.keys(stored).filter((key) => !KEPT_ACROSS_LOCK.has(key));

  if (keys.length > 0) {
    await chrome.storage.session.remove(keys);
  }
}
