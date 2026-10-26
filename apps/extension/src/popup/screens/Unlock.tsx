import { useState } from "react";
import type { SyntheticEvent } from "react";

import type { ExtensionState } from "../../shared/messages.js";
import { call } from "../background.js";
import { Shell } from "./Shell.js";
import { useAsync } from "../useAsync.js";

/**
 * ### Unlock
 *
 * Unlock form; asks for the Secret Key only on a new device and for a code only when required.
 *
 * @param props Current state and handlers
 * @returns The unlock screen
 */
export function Unlock({
  state,
  onUnlocked,
  onChanged,
}: {
  state: ExtensionState;
  onUnlocked: (state: ExtensionState) => void;
  onChanged: (state: ExtensionState) => void;
}) {
  const [email, setEmail] = useState(state.email ?? "");
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [totp, setTotp] = useState<string | undefined>(undefined);
  const { busy, error, run } = useAsync();

  return (
    <Shell
      action={
        <span className="small muted" title={state.serverUrl}>
          {state.serverUrl === undefined ? "" : new URL(state.serverUrl).host}
        </span>
      }
    >
      <form
        className="body"
        style={{ padding: 0 }}
        onSubmit={(event: SyntheticEvent) => {
          event.preventDefault();
          run(async () => {
            const result = await call<{
              ok: boolean;
              code?: string;
              message?: string;
              recoveryCancelled?: boolean;
            }>({
              type: "unlock",
              email,
              password,
              ...(state.knownDevice ? {} : { secretKey }),
              ...(totp === undefined ? {} : { totp }),
            });

            if (result.ok) {
              if (result.recoveryCancelled === true) {
                window.alert(
                  "Someone had started recovering this account, and signing in just cancelled it. Check with your admin.",
                );
              }

              onUnlocked(await call<ExtensionState>({ type: "state" }));
            } else if (result.code === "totp_required") {
              setTotp("");
            } else {
              throw new Error(result.message ?? "Couldn't unlock.");
            }
          });
        }}
      >
        <div className="field">
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            required
            value={email}
            onChange={(event) => {
              setEmail(event.target.value);
            }}
            autoComplete="username"
          />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            required
            autoFocus
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
            }}
            autoComplete="current-password"
          />
        </div>
        {state.knownDevice ? null : (
          <div className="field">
            <label htmlFor="secret-key">Secret Key</label>
            <input
              id="secret-key"
              required
              spellCheck={false}
              placeholder="K1-…"
              value={secretKey}
              onChange={(event) => {
                setSecretKey(event.target.value);
              }}
            />
          </div>
        )}
        {totp === undefined ? null : (
          <div className="field">
            <label htmlFor="totp">Two-factor code</label>
            <input
              id="totp"
              inputMode="numeric"
              required
              autoFocus
              value={totp}
              onChange={(event) => {
                setTotp(event.target.value);
              }}
              autoComplete="one-time-code"
            />
          </div>
        )}
        <p className="error" role="alert">
          {error}
        </p>
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? "Checking…" : "Unlock"}
        </button>
        <button
          type="button"
          className="btn btn-ghost btn-small"
          onClick={() => {
            run(async () => {
              onChanged(await call<ExtensionState>({ type: "forget-device" }));
            });
          }}
        >
          Remove account from this browser
        </button>
      </form>
    </Shell>
  );
}
