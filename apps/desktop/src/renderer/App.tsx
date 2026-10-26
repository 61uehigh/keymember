import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";

import type { DesktopState, SignRequestView } from "../shared/ipc.js";
import { call } from "./ipc.js";
import { Main } from "./screens/Main.js";
import { PinOwner } from "./screens/PinOwner.js";
import { Setup } from "./screens/Setup.js";
import { SignPrompt } from "./screens/SignPrompt.js";
import { Unlock } from "./screens/Unlock.js";

/**
 * ### App
 *
 * Root: setup, unlock, owner pinning, or the main view, plus SSH signing prompts. While no
 * owner key is pinned, pinning is offered after every unlock, and the main view keeps a way back
 * to it if the user postponed it.
 *
 * @returns The app
 */
export function App() {
  const [state, setState] = useState<DesktopState | undefined>(undefined);
  // The user chose to compare the owner's fingerprint later during this unlock
  const [postponed, setPostponed] = useState(false);
  const [signRequest, setSignRequest] = useState<SignRequestView | undefined>(
    undefined,
  );
  const refresh = useCallback(async () => {
    setState(await call<DesktopState>({ type: "state" }));
  }, []);

  useEffect(() => {
    void refresh();
    window.keymember.onSignRequest(setSignRequest);
    // The vault locks on its own (screen lock, idle, the server ending the login)
    window.keymember.onStateChanged(() => {
      void refresh();
    });
  }, [refresh]);

  let screen: ReactNode;

  if (state === undefined) {
    screen = <p className="muted">Loading…</p>;
  } else if (state.serverUrl === undefined) {
    screen = <Setup onDone={setState} />;
  } else if (state.user === undefined) {
    screen = (
      <Unlock
        state={state}
        onUnlocked={(next) => {
          setPostponed(false);
          setState(next);

          return Promise.resolve();
        }}
      />
    );
  } else if (!state.pinned && !postponed) {
    screen = (
      <PinOwner
        onDone={refresh}
        onLater={() => {
          setPostponed(true);
        }}
      />
    );
  } else {
    screen = (
      <Main
        state={state}
        onChange={setState}
        onPinOwner={() => {
          setPostponed(false);
        }}
      />
    );
  }

  return (
    <main>
      <header className="bar">
        <span className="brand">keymember</span>
        {state?.user === undefined ? null : (
          <button
            type="button"
            className="btn btn-small"
            onClick={() => {
              void call<DesktopState>({ type: "lock" }).then(setState);
            }}
          >
            Lock
          </button>
        )}
      </header>
      {screen}
      {signRequest === undefined ? null : (
        <SignPrompt
          request={signRequest}
          onAnswer={(answer) => {
            window.keymember.answerSignRequest(signRequest.id, answer);
            setSignRequest(undefined);
          }}
        />
      )}
    </main>
  );
}
