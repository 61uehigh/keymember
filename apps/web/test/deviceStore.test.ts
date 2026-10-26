// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  forgetDevice,
  loadDevice,
  rootsOf,
  saveDevice,
  withRoots,
} from "../src/lib/deviceStore.js";

const STORAGE_KEY = "keymember.device.v1";
const KEY_A = new Uint8Array(32).fill(1);
const KEY_B = new Uint8Array(32).fill(2);

describe("device store", () => {
  afterEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("starts a new device when nothing is stored", () => {
    const device = loadDevice();

    expect(device.deviceId).toMatch(/^[0-9a-f-]{36}$/);
    expect(device.roots).toEqual({});
  });

  it("keeps what was saved", () => {
    const saved = withRoots(
      { deviceId: "d1", email: "a@example.com", roots: {} },
      new Map([["owner", KEY_A]]),
    );

    saveDevice(saved);

    expect(loadDevice()).toEqual(saved);
  });

  it("starts over when the stored record is not JSON or has the wrong shape", () => {
    localStorage.setItem(STORAGE_KEY, "{not json");
    expect(loadDevice().roots).toEqual({});

    localStorage.setItem(STORAGE_KEY, JSON.stringify({ deviceId: 7 }));
    expect(loadDevice().deviceId).not.toBe(7);
  });

  it("does not throw when storage is unavailable", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("storage disabled");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("storage disabled");
    });

    expect(() => {
      saveDevice({ deviceId: "d", roots: {} });
    }).not.toThrow();
    expect(loadDevice().roots).toEqual({});
  });

  it("forgets the device", () => {
    saveDevice({ deviceId: "d1", roots: {} });
    forgetDevice();

    expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it("adds roots without dropping the ones already pinned, and decodes them", () => {
    const one = withRoots(
      { deviceId: "d", roots: {} },
      new Map([["owner", KEY_A]]),
    );
    const both = withRoots(one, new Map([["admin", KEY_B]]));
    const roots = rootsOf(both);

    expect(roots.get("owner")).toEqual(KEY_A);
    expect(roots.get("admin")).toEqual(KEY_B);
  });

  it("ignores stored roots that do not decode", () => {
    const roots = rootsOf({
      deviceId: "d",
      roots: { owner: "not base64url!!", other: "" },
    });

    expect(roots.has("owner")).toBe(false);
  });
});
