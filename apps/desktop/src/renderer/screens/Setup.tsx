import { useState } from "react";
import type { SyntheticEvent } from "react";

import type { DesktopState } from "../../shared/ipc.js";
import { Field } from "../Field.js";
import { call } from "../ipc.js";
import { useAction } from "../useAction.js";

/**
 * ### Setup
 *
 * Asks for the server address.
 *
 * @param props Completion handler
 * @returns The form
 */
export function Setup({ onDone }: { onDone: (state: DesktopState) => void }) {
  const [serverUrl, setServerUrl] = useState("https://");
  const action = useAction();

  return (
    <form
      className="stack"
      onSubmit={(event: SyntheticEvent) => {
        event.preventDefault();
        action.run(async () => {
          onDone(await call<DesktopState>({ type: "configure", serverUrl }));
        });
      }}
    >
      <h1>Connect to server</h1>
      <Field
        label="keymember server URL"
        id="server"
        type="url"
        required
        value={serverUrl}
        onChange={(event) => {
          setServerUrl(event.target.value);
        }}
      />
      <p className="error">{action.error}</p>
      <button type="submit" className="btn btn-primary" disabled={action.busy}>
        Connect
      </button>
    </form>
  );
}
