import { certifyInvitedInBackground, DeviceTrust } from "@keymember/client";
import type { Session } from "@keymember/client";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";

import { clearCopiedSecret } from "./clipboard.js";
import { loadDevice, rootsOf, saveDevice, withRoots } from "./deviceStore.js";
import type { DeviceState } from "./deviceStore.js";

const IDLE_LOCK_MS = 15 * 60 * 1000;

/**
 * ### AppState
 *
 * State shared by every screen: the device record, the unlocked session if any, and a
 * revision counter screens bump to re-read the session cache after a change.
 */
export interface AppState {
  /**
   * ### device
   *
   * This browser's stored device state.
   */
  readonly device: DeviceState;

  /**
   * ### roots
   *
   * Pinned owner keys decoded for the SDK.
   */
  readonly roots: Map<string, Uint8Array>;

  /**
   * ### session
   *
   * Unlocked session, or `undefined` while locked.
   */
  readonly session: Session | undefined;

  /**
   * ### revision
   *
   * Increments whenever the session cache changed, so screens can re-derive their views.
   */
  readonly revision: number;

  /**
   * ### trust
   *
   * How this browser comes to trust the organisation's keys: from an invite link, the account's
   * saved roots, or a compared fingerprint.
   */
  readonly trust: DeviceTrust;

  /**
   * ### updateDevice
   *
   * Replaces and persists the device state.
   */
  readonly updateDevice: (next: DeviceState) => void;

  /**
   * ### unlock
   *
   * Stores a freshly logged-in session.
   */
  readonly unlock: (session: Session) => void;

  /**
   * ### lock
   *
   * Logs out on the server (best effort) and drops every key from memory.
   */
  readonly lock: () => void;

  /**
   * ### touch
   *
   * Marks the session cache as changed.
   */
  readonly touch: () => void;
}

/**
 * ### CERTIFY_INTERVAL_MS
 *
 * How often an admin's open app certifies members who joined through the admin's invite links.
 */
const CERTIFY_INTERVAL_MS = 2 * 60 * 1000;

const AppStateContext = createContext<AppState | undefined>(undefined);

/**
 * ### AppStateProvider
 *
 * Provides {@link AppState} and locks the vault after 15 minutes without user input.
 *
 * @param props Children to render inside the provider
 * @returns The provider element
 */
export function AppStateProvider({ children }: { children: ReactNode }) {
  const [device, setDevice] = useState(loadDevice);
  // The latest device, for unlock calls made right after a pin in the same event
  const deviceRef = useRef(device);
  const [session, setSession] = useState<Session | undefined>(undefined);
  const [revision, setRevision] = useState(0);
  const idleTimer = useRef<number | undefined>(undefined);
  const trust = useMemo(
    () =>
      new DeviceTrust({
        current: () => Promise.resolve(rootsOf(deviceRef.current)),
        pin: (roots) => {
          const next = withRoots(deviceRef.current, roots);

          saveDevice(next);
          deviceRef.current = next;
          setDevice(next);

          return Promise.resolve();
        },
      }),
    [],
  );

  // The session as of the last render, so lock can end it without a side effect in an updater
  const sessionRef = useRef(session);

  sessionRef.current = session;

  const lock = useCallback(() => {
    const current = sessionRef.current;

    sessionRef.current = undefined;
    setSession(undefined);
    clearCopiedSecret();
    // Revoking server-side is best effort: the keys leave memory either way, and a server that
    // cannot be reached ends the login itself when its tokens expire
    void current?.logOut().catch(() => undefined);
  }, []);

  // The server can end the login (suspension, revoked tokens); keys must not stay on screen then
  useEffect(() => session?.onEnded(lock), [session, lock]);

  useEffect(() => {
    if (session === undefined) {
      return undefined;
    }

    const reset = (): void => {
      window.clearTimeout(idleTimer.current);
      idleTimer.current = window.setTimeout(lock, IDLE_LOCK_MS);
    };
    const events = ["pointerdown", "keydown"] as const;

    reset();

    for (const event of events) {
      window.addEventListener(event, reset, { passive: true });
    }

    return () => {
      window.clearTimeout(idleTimer.current);

      for (const event of events) {
        window.removeEventListener(event, reset);
      }
    };
  }, [session, lock]);

  useEffect(() => {
    if (session === undefined || session.user.role === "member") {
      return undefined;
    }

    // Members who joined by this admin's links wait for certification; check now and then
    const certify = (): void => {
      certifyInvitedInBackground(session, {
        trustsOrganisation: rootsOf(deviceRef.current).size > 0,
        onResult: (result) => {
          if (result.certified.length > 0) {
            setRevision((current) => current + 1);
          }
        },
        // The admin console runs the same certification in the foreground and shows its errors
        onError: () => undefined,
      });
    };
    const timer = window.setInterval(certify, CERTIFY_INTERVAL_MS);

    certify();

    return () => {
      window.clearInterval(timer);
    };
  }, [session]);

  const value = useMemo<AppState>(
    () => ({
      device,
      roots: rootsOf(device),
      session,
      revision,
      trust,
      updateDevice: (next) => {
        saveDevice(next);
        deviceRef.current = next;
        setDevice(next);
        session?.setRoots(rootsOf(next));
      },
      unlock: (next) => {
        // Sync accepts others' vault grants only when they chain to the pinned roots
        next.setRoots(rootsOf(deviceRef.current));
        setSession(next);
        setRevision((current) => current + 1);
      },
      lock,
      touch: () => {
        setRevision((current) => current + 1);
      },
    }),
    [device, session, revision, lock, trust],
  );

  return <AppStateContext value={value}>{children}</AppStateContext>;
}

/**
 * ### useAppState
 *
 * Reads {@link AppState}. Must be called under {@link AppStateProvider}.
 *
 * @returns The shared state
 */
export function useAppState(): AppState {
  const state = useContext(AppStateContext);

  if (state === undefined) {
    throw new Error("useAppState must be used inside AppStateProvider");
  }

  return state;
}

/**
 * ### useSession
 *
 * Reads the unlocked session; screens behind the lock can rely on it being present.
 *
 * @returns The unlocked session
 */
export function useSession(): Session {
  const { session } = useAppState();

  if (session === undefined) {
    throw new Error("No unlocked session");
  }

  return session;
}
