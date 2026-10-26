import { useCallback, useEffect, useState } from "react";

import type { ExtensionState } from "../shared/messages.js";
import { call } from "./background.js";
import { Main } from "./screens/Main.js";
import { PinOwner } from "./screens/PinOwner.js";
import { Setup } from "./screens/Setup.js";
import { Unlock } from "./screens/Unlock.js";

/**
 * ### Popup
 *
 * Root of the toolbar popup: setup, unlock, owner pinning, or the main view.
 *
 * @returns The popup
 */
export function Popup() {
  const [state, setState] = useState<ExtensionState | undefined>(undefined);
  const [pinning, setPinning] = useState(false);
  const refresh = useCallback(async () => {
    setState(await call<ExtensionState>({ type: "state" }));
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  if (state === undefined) {
    return <p className="body muted">Loading…</p>;
  }

  if (state.serverUrl === undefined) {
    return <Setup onDone={setState} />;
  }

  if (state.user === undefined) {
    return (
      <Unlock
        state={state}
        onUnlocked={(next) => {
          setState(next);
          setPinning(!next.pinned);
        }}
        onChanged={setState}
      />
    );
  }

  if (pinning) {
    return (
      <PinOwner
        onDone={(next) => {
          setPinning(false);

          if (next !== undefined) {
            setState(next);
          }
        }}
      />
    );
  }

  return (
    <Main
      state={state}
      onLocked={setState}
      onPin={() => {
        setPinning(true);
      }}
    />
  );
}
