import type { DesktopState } from "../../shared/ipc.js";
import { call } from "../ipc.js";
import { useAction } from "../useAction.js";

/**
 * ### Settings
 *
 * Touch ID unlock.
 *
 * @param props State and change handler
 * @returns The tab
 */
export function Settings({
  state,
  onChange,
}: {
  state: DesktopState;
  onChange: (state: DesktopState) => void;
}) {
  const action = useAction();

  return (
    <div className="stack">
      <p className="small muted">
        {state.user?.name} ({state.user?.email})
      </p>
      {state.biometricAvailable ? (
        <label className="row">
          <input
            type="checkbox"
            checked={state.biometricEnabled}
            disabled={action.busy}
            onChange={(event) => {
              const enabled = event.target.checked;

              action.run(async () => {
                onChange(
                  await call<DesktopState>({ type: "set-biometric", enabled }),
                );
              });
            }}
          />
          Unlock with Touch ID
        </label>
      ) : (
        <p className="muted small">
          Touch ID isn't available on this computer.
        </p>
      )}
      <p className="hint small">
        When on, your sign-in details are stored encrypted in this computer's
        keychain and opened with Touch ID. You'll still need to enter your
        password once every two weeks.
      </p>
      <p className="error">{action.error}</p>
    </div>
  );
}
