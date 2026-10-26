import { useState } from "react";
import type { SyntheticEvent } from "react";

import type { ExtensionState } from "../../shared/messages.js";
import { call } from "../background.js";
import { Shell } from "./Shell.js";
import { useAsync } from "../useAsync.js";

/**
 * ### Setup
 *
 * First run: asks for the server address.
 *
 * @param props Completion handler
 * @returns The setup screen
 */
export function Setup({ onDone }: { onDone: (state: ExtensionState) => void }) {
  const [serverUrl, setServerUrl] = useState("https://");
  const { busy, error, run } = useAsync();

  return (
    <Shell>
      <form
        className="body"
        style={{ padding: 0 }}
        onSubmit={(event: SyntheticEvent) => {
          event.preventDefault();
          run(async () => {
            onDone(
              await call<ExtensionState>({
                type: "configure",
                serverUrl: serverUrl.trim(),
              }),
            );
          });
        }}
      >
        <div className="field">
          <label htmlFor="server">Server URL</label>
          <input
            id="server"
            type="url"
            required
            autoFocus
            value={serverUrl}
            onChange={(event) => {
              setServerUrl(event.target.value);
            }}
          />
        </div>
        <p className="error" role="alert">
          {error}
        </p>
        <button type="submit" className="btn btn-primary" disabled={busy}>
          Save
        </button>
      </form>
    </Shell>
  );
}
