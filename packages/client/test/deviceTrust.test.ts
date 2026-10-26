import { describe, expect, it } from "vitest";

import { DeviceTrust } from "@keymember/client";
import type { DeviceRoots, TrustedSession } from "@keymember/client";

const OWNER = "owner";
const OWNER_KEY = new Uint8Array(32).fill(1);
const SAVED_KEY = new Uint8Array(32).fill(2);

/**
 * ### memoryRoots
 *
 * Device roots kept in a map.
 *
 * @param initial Roots the device starts with
 * @returns The store and the map behind it
 */
function memoryRoots(initial: ReadonlyMap<string, Uint8Array> = new Map()): {
  store: DeviceRoots;
  pinned: Map<string, Uint8Array>;
} {
  const pinned = new Map(initial);

  return {
    pinned,
    store: {
      current: () => Promise.resolve(new Map(pinned)),
      pin: (roots) => {
        for (const [userId, key] of roots) {
          pinned.set(userId, key);
        }

        return Promise.resolve();
      },
    },
  };
}

/**
 * ### fakeSession
 *
 * A session whose server reports one owner and, optionally, saved roots.
 *
 * @param saved Roots the account saved on another device
 * @returns The session and what it was asked to do
 */
function fakeSession(saved?: ReadonlyMap<string, Uint8Array>): {
  session: TrustedSession;
  trusted: Array<ReadonlyMap<string, Uint8Array>>;
  saves: Array<true>;
} {
  const trusted: Array<ReadonlyMap<string, Uint8Array>> = [];
  const saves: Array<true> = [];

  return {
    trusted,
    saves,
    session: {
      ownerCandidates: () =>
        Promise.resolve([
          {
            userId: OWNER,
            email: "owner@example.com",
            signingPublicKey: OWNER_KEY,
            fingerprint: "aaaa-bbbb",
          },
        ]),
      storedTrustedRoots: () => Promise.resolve(saved),
      setRoots: (roots) => {
        trusted.push(roots);
      },
      saveTrustedRoots: () => {
        saves.push(true);

        return Promise.resolve();
      },
    },
  };
}

describe("DeviceTrust", () => {
  it("adopts the account's saved roots on a device that trusts nothing", async () => {
    const device = memoryRoots();
    const { session, trusted } = fakeSession(new Map([[OWNER, SAVED_KEY]]));

    expect(await new DeviceTrust(device.store).afterUnlock(session)).toBe(true);
    expect(device.pinned.get(OWNER)).toEqual(SAVED_KEY);
    expect(trusted.at(-1)?.get(OWNER)).toEqual(SAVED_KEY);
  });

  it("keeps the device's own roots over saved ones", async () => {
    const device = memoryRoots(new Map([[OWNER, OWNER_KEY]]));
    const { session, trusted } = fakeSession(new Map([[OWNER, SAVED_KEY]]));

    await new DeviceTrust(device.store).afterUnlock(session);

    expect(trusted.at(-1)?.get(OWNER)).toEqual(OWNER_KEY);
  });

  it("asks for a fingerprint when nothing is pinned or saved", async () => {
    const { session } = fakeSession();

    expect(
      await new DeviceTrust(memoryRoots().store).afterUnlock(session),
    ).toBe(false);
  });

  it("pins the owner only with the compared fingerprint, then saves the roots", async () => {
    const device = memoryRoots();
    const { session, saves } = fakeSession();
    const trust = new DeviceTrust(device.store);

    await expect(trust.pinOwner(session, OWNER, "zzzz-zzzz")).rejects.toThrow(
      /Compare the fingerprint again/,
    );
    expect(device.pinned.size).toBe(0);
    expect(saves).toHaveLength(0);

    await trust.pinOwner(session, OWNER, "aaaa-bbbb");

    expect(device.pinned.get(OWNER)).toEqual(OWNER_KEY);
    expect(saves).toHaveLength(1);
  });

  it("pins and saves the roots an invite link carried", async () => {
    const device = memoryRoots();
    const { session, trusted, saves } = fakeSession();

    await new DeviceTrust(device.store).adoptRoots(
      session,
      new Map([[OWNER, OWNER_KEY]]),
    );

    expect(device.pinned.get(OWNER)).toEqual(OWNER_KEY);
    expect(trusted.at(-1)?.get(OWNER)).toEqual(OWNER_KEY);
    expect(saves).toHaveLength(1);
  });
});
